# cve_search.py —— 搜索模块：固件型号 → 相关 CVE 列表
# 核心不用大模型：keyword 粗筛 + 本地归一化 token 精确过滤 + 启发式打分
# 数据源：cve.org restapiv1（主，免鉴权）→ NVD（兜底），配置顺序可调
import hashlib
import json
import os
import re
import time
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlencode

import requests

from config import (
    SEARCH_PROVIDERS, CVEORG_API_URL, RATE_SLEEP_CVEORG,
    NVD_API_BASE, CVE_RECORD_URL, NVD_URL, NVD_API_KEY,
    RESULTS_PER_PAGE, MAX_PAGES, RATE_SLEEP, HTTP_TIMEOUT, USER_AGENT,
    DESCRIPTION_EXCERPT_LEN, DEFAULT_TOP_N, OUTPUT_DIR, DOWNLOAD_CONCURRENCY,
    RESULT_CACHE_TTL, EPSS_API_URL, EPSS_WEIGHT, EPSS_ENABLED,
    COMPONENT_CANDIDATE_LIMIT,
    OSV_API_URL, OSV_ECOSYSTEMS, OSV_ENABLED,
)
from cache import CachedRequest
from poc_downloader import (
    download_poc_for_cve, github_quota_remaining, GITHUB_RATE_MIN,
    community_poc_supplement,
)

_sess = requests.Session()
_sess.headers.update({"User-Agent": USER_AGENT})
if NVD_API_KEY:
    _sess.headers["apiKey"] = NVD_API_KEY
_cache = CachedRequest()

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{3,}$", re.IGNORECASE)


# ---------- 型号归一化 ----------

def normalize_token(text):
    """去掉所有非字母数字、统一小写。'DIR-850L'/'DIR850L'/'dir 850 l' → 'dir850l'"""
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


# 型号噪声 token。两种粒度：
# 严格：只剥 REV/version/firmware/v+数字/fw+*/纯数字/单字母（保 C7、A1 这类型号）
# 宽松：额外剥 字母+数字（A1/B1 硬件版本，但也可能误杀 C7 这类真型号 → 只作召回兜底）
STRICT_NOISE_RE = re.compile(
    r"^(rev|revision|version|ver|firmware|v[\d.]+|fw[\w.]*|[a-z]|\d+([.]\d+)*)$", re.I)
LOOSE_NOISE_RE = re.compile(
    r"^(rev|revision|version|ver|firmware|v[\d.]+|fw[\w.]*|[a-z]\d?|\d+([.]\d+)*)$", re.I)


def _clean_model_tokens(tokens, noise_re):
    """剥离噪声 token 和包裹标点，返回干净型号词。"""
    out = []
    for t in tokens:
        t = t.strip("()[]{}<>\"'.,;:!?")
        if not t or noise_re.match(t):
            continue
        out.append(t)
    return out


def parse_firmware(name):
    """把固件名拆成 vendor + 型号。输入形如 'D-Link DIR-850L REV B'。
    model_core=严格基型（保留 C7/A1）；model_core_loose=宽松基型（剥 A1/B1，召回兜底）。"""
    words = [w for w in name.split() if re.search(r"[A-Za-z0-9]", w)]
    if len(words) >= 2:
        vendor = normalize_token(words[0])
        model_tokens = words[1:]
    else:
        vendor = ""
        model_tokens = words if words else []

    strict = _clean_model_tokens(model_tokens, STRICT_NOISE_RE)
    loose = _clean_model_tokens(model_tokens, LOOSE_NOISE_RE)
    return {
        "input": name,
        "vendor": vendor,
        "model_raw": " ".join(model_tokens),
        "model_clean": " ".join(strict),
        "model_core": normalize_token(" ".join(strict)),
        "model_core_loose": normalize_token(" ".join(loose)),
    }


def keyword_queries(fw):
    """构造 keyword 候选 query。原样 / 严格基型 / 宽松基型 / 连写 都搜，再合并去重。"""
    qs = set()
    for q in (fw["model_raw"], fw["model_clean"], fw["model_core"], fw["model_core_loose"]):
        if q:
            qs.add(q)
    return sorted(qs)


# ---------- provider: cve.org 网站搜索（主源）----------

def _cveorg_search(query, from_=0, size=RESULTS_PER_PAGE):
    body = {
        "query": query,
        "from": from_,
        "size": size,
        "sort": {"property": "cveId", "order": "desc"},
    }
    data = _cache.get(CVEORG_API_URL, body=body)
    if data is None:
        resp = _sess.post(
            CVEORG_API_URL, json=body, timeout=HTTP_TIMEOUT,
            headers={"Accept": "application/json, text/plain, */*",
                     "Referer": "https://www.cve.org/"},
        )
        resp.raise_for_status()
        data = resp.json()
        _cache.put(CVEORG_API_URL, data, body=body)
        time.sleep(RATE_SLEEP_CVEORG)
    return data


def _cveorg_to_common(src):
    """把 cve.org 记录（_source）归一成内部通用结构（与 NVD 字段对齐）。"""
    meta = src.get("cveMetadata", {})
    cna = src.get("containers", {}).get("cna", {}) or {}
    return {
        "id": meta.get("cveId", ""),
        "published": meta.get("datePublished", ""),
        "descriptions": cna.get("descriptions", []) or [],
        "references": cna.get("references", []) or [],
        "affected": cna.get("affected", []) or [],
        "configurations": [],  # cve.org 不携带 NVD 式 CPE configurations
        "weaknesses": [
            {"description": [{"lang": d.get("lang", "en"), "value": d.get("description", "")}]}
            for pt in cna.get("problemTypes", []) or []
            for d in pt.get("descriptions", []) or []
        ],
    }


def _cveorg_fetch(query, limit=None):
    """抓候选，limit 限制总量（组件搜索用小块，避免 openssl 这种大组件拖慢）。"""
    out = []
    start = 0
    size = limit if limit else RESULTS_PER_PAGE
    for _ in range(MAX_PAGES):
        data = _cveorg_search(query, from_=start, size=size)
        batch = data.get("data", [])
        out.extend(batch)
        start += len(batch)
        if limit and len(out) >= limit:
            break
        if start >= data.get("resultsTotal", 0):
            break
    return out


def collect_cveorg(fw, cve_id=None, candidate_limit=None):
    seen = {}
    if cve_id:
        for rec in _cveorg_fetch(cve_id, candidate_limit):
            c = _cveorg_to_common(rec.get("_source", {}))
            if c["id"]:
                seen[c["id"]] = c
        return list(seen.values())
    for q in keyword_queries(fw):
        for rec in _cveorg_fetch(q, candidate_limit):
            c = _cveorg_to_common(rec.get("_source", {}))
            if c["id"]:
                seen[c["id"]] = c
    return list(seen.values())


# ---------- provider: NVD（兜底）----------

def _nvd_search(query=None, cve_id=None, start_index=0, limit=None):
    params = {"resultsPerPage": limit if limit else RESULTS_PER_PAGE, "startIndex": start_index}
    if cve_id:
        params["cveId"] = cve_id
    else:
        params["keywordSearch"] = query
    url = NVD_API_BASE + "?" + urlencode(params)

    data = _cache.get(url)
    if data is None:
        resp = _sess.get(url, timeout=HTTP_TIMEOUT)
        if resp.status_code == 403:   # 大概率限速，退避重试一次
            time.sleep(RATE_SLEEP)
            resp = _sess.get(url, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        data = json.loads(resp.content.decode("utf-8-sig"))  # NVD 响应带 BOM
        _cache.put(url, data)
        time.sleep(RATE_SLEEP)
    return data


def collect_nvd(fw, cve_id=None, candidate_limit=None):
    seen = {}
    if cve_id:
        for v in _nvd_search(cve_id=cve_id, limit=candidate_limit).get("vulnerabilities", []):
            seen[v["cve"]["id"]] = v["cve"]
        return list(seen.values())

    for q in keyword_queries(fw):
        start = 0
        for _ in range(MAX_PAGES):
            data = _nvd_search(query=q, start_index=start, limit=candidate_limit)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                seen[v["cve"]["id"]] = v["cve"]
            start += len(vulns)
            if candidate_limit and len(seen) >= candidate_limit:
                break
            if start >= data.get("totalResults", 0):
                break
    return list(seen.values())


# ---------- provider: OSV（组件漏洞，精确版本范围）----------

def _osv_to_common(vuln):
    """OSV 漏洞记录归一化成内部通用结构。id 优先取 CVE alias。"""
    aliases = vuln.get("aliases") or []
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    vid = vuln.get("id", "")
    if not cve_id and vid.startswith("CVE-"):
        cve_id = vid
    affected = []
    osv_ranges = []
    for a in vuln.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        affected.append({"product": pkg.get("name", ""), "vendor": ""})
        for rr in (a.get("ranges") or []):
            for ev in (rr.get("events") or []):
                if ev.get("introduced") and ev["introduced"] not in ("0", "0.0.0"):
                    osv_ranges.append(("ge", str(ev["introduced"])))
                if ev.get("fixed"):
                    osv_ranges.append(("lt", str(ev["fixed"])))
    desc = vuln.get("summary") or vuln.get("details") or ""
    return {
        "id": cve_id or vid,
        "published": vuln.get("published", ""),
        "descriptions": [{"lang": "en", "value": desc}],
        "references": [
            {"url": ref.get("url", ""), "name": "", "tags": [ref.get("type", "")]}
            for ref in (vuln.get("references") or []) if isinstance(ref, dict)
        ],
        "affected": affected,
        "configurations": [],
        "weaknesses": [],
        "_osv_ranges": osv_ranges,
    }


def _osv_search(name, limit=None):
    """跨发行版生态查 OSV 组件漏洞，返回归一化记录。"""
    out = []
    for eco in OSV_ECOSYSTEMS:
        payload = {"package": {"ecosystem": eco, "name": name}}
        try:
            resp = _sess.post(OSV_API_URL, json=payload, timeout=HTTP_TIMEOUT)
            resp.raise_for_status()
            for v in resp.json().get("vulns", []):
                out.append(_osv_to_common(v))
        except Exception:
            continue
    seen = {}
    for c in out:
        if c["id"]:
            seen[c["id"]] = c
    return list(seen.values())[:limit] if limit else list(seen.values())


# ---------- 候选获取（按配置顺序，失败降级）----------

PROVIDERS = {"cveorg": collect_cveorg, "nvd": collect_nvd}


def _get_candidates(fw, cve_id=None, candidate_limit=None):
    """按 SEARCH_PROVIDERS 顺序尝试。返回 (source, candidates, errors)。
    candidate_limit 限制候选总量（组件搜索用小量，避免大组件拖慢）。
    errors 记录各 provider 的异常（网络/HTTP 错误），用于区分"没结果"和"源挂了"。"""
    errors = []
    for name in SEARCH_PROVIDERS:
        fn = PROVIDERS.get(name)
        if not fn:
            continue
        try:
            cands = fn(fw, cve_id, candidate_limit) if candidate_limit else fn(fw, cve_id)
            if cands:
                return name, cands, errors
        except Exception as e:
            errors.append(f"{name}: {type(e).__name__}: {e}")
    return None, [], errors


# ---------- 本地过滤 + 打分 ----------

def _cpe_strings(cve):
    """NVD configurations 里所有 CPE criteria 串（cve.org 记录没有 → 空）。防御畸形数据。"""
    out = []

    def walk(node):
        if not isinstance(node, dict):
            return
        for m in (node.get("cpeMatch") or []):
            if isinstance(m, dict):
                out.append(str(m.get("criteria", "")))
        for sub in (node.get("children") or []):
            walk(sub)

    for cfg in (cve.get("configurations") or []):
        if not isinstance(cfg, dict):
            continue
        for node in (cfg.get("nodes") or []):
            walk(node)
    return out


def _cve_text(cve):
    """描述 + affected 产品 + CPE 串，拼成可搜索文本。防御畸形数据（None/非字符串）。"""
    parts = []
    for d in (cve.get("descriptions") or []):
        if isinstance(d, dict) and d.get("lang") in ("en", None, ""):
            parts.append(str(d.get("value", "")))
    for a in (cve.get("affected") or []):
        if isinstance(a, dict):
            parts.append(str(a.get("product", "")))
    parts.extend(_cpe_strings(cve))
    return " ".join(parts)


def _normalized(cve):
    return normalize_token(_cve_text(cve))


def _weaknesses(cve):
    out = []
    for w in (cve.get("weaknesses") or []):
        if not isinstance(w, dict):
            continue
        for d in (w.get("description") or []):
            if isinstance(d, dict):
                m = re.search(r"CWE-\d+", str(d.get("value", "")))
                if m:
                    out.append(m.group(0))
    return out


def score_cve(cve, fw):
    """启发式打分。返回 (score, reasons, include)。
    精确过滤门槛：型号 core 必须命中 CVE 文本（描述/affected/CPE），否则不收录。"""
    text_n = _normalized(cve)
    reasons = []
    score = 0.0

    # 双基型匹配：严格基型（含 C7/A1）优先；宽松基型（剥 A1/B1）召回兜底
    strict = fw["model_core"]
    loose = fw["model_core_loose"]
    if strict and strict in text_n:
        score += 0.5
        reasons.append(f"model:{strict}")
        cnt = text_n.count(strict)
        if cnt >= 3:
            score += 0.05
            reasons.append(f"model_x{cnt}")
    elif loose and loose in text_n:
        score += 0.4
        reasons.append(f"model_loose:{loose}")
        cnt = text_n.count(loose)
        if cnt >= 3:
            score += 0.05
            reasons.append(f"model_x{cnt}")
    else:
        return 0.0, reasons, False

    if fw["vendor"] and fw["vendor"] in text_n:
        score += 0.15
        reasons.append(f"vendor:{fw['vendor']}")

    cwes = _weaknesses(cve)
    if cwes:
        score += 0.05
        reasons.append(f"cwe:{cwes[0]}")

    pub = str(cve.get("published") or "")
    if pub:
        try:
            pub_ts = time.mktime(time.strptime(pub[:10], "%Y-%m-%d"))
            days = (time.time() - pub_ts) / 86400
            if days >= 0:
                score += 0.10 * max(0.0, 1.0 - days / (2 * 365))
        except (ValueError, OverflowError, OSError):
            pass

    return min(score, 1.0), reasons, True


# ---------- POC 判定（只分类，不下载）----------

def classify_reference(ref):
    """判定 reference 是否 POC。返回 (is_poc, source)。
    source = tag（官方 Exploit 标注） / heuristic（URL 启发式） / none。防御畸形数据。"""
    if not isinstance(ref, dict):
        return False, ""
    url = str(ref.get("url") or "").lower()
    name = str(ref.get("source") or ref.get("name") or "").lower()
    tags_val = ref.get("tags") or []
    if not isinstance(tags_val, list):
        tags_val = []
    tags = [str(t).lower() for t in tags_val if t is not None]

    if "exploit" in tags:
        return True, "tag"

    hay = f"{url} {name}"
    for hint in ("github.com", "raw.githubusercontent.com", "exploit-db.com",
                 "seebug.org", "packetstormsecurity.com", "rapid7.com",
                 "metasploit", "huntr.com", "0day.today", "github.io"):
        if hint in hay:
            return True, "heuristic"

    if re.search(r"\b(poc|exploit|proof[- ]of[- ]concept|cve-\d{4}-\d{3,})\b", hay):
        return True, "heuristic"

    return False, ""


def build_result(cve):
    cve_id = cve["id"]
    desc = " ".join(
        str(d.get("value", ""))
        for d in (cve.get("descriptions") or [])
        if isinstance(d, dict) and d.get("lang") == "en"
    )

    refs = []
    for ref in (cve.get("references") or []):
        if not isinstance(ref, dict):
            continue
        is_poc, src = classify_reference(ref)
        refs.append({
            "url": str(ref.get("url") or ""),
            "name": str(ref.get("name") or ref.get("source") or ""),
            "tags": ref.get("tags", []),
            "is_poc": is_poc,
            "poc_source": src if is_poc else "none",
        })

    return {
        "cve_id": cve_id,
        "cve_url": CVE_RECORD_URL.format(cve_id=cve_id),
        "nvd_url": NVD_URL.format(cve_id=cve_id),
        "published": str(cve.get("published") or ""),
        "description": desc[:DESCRIPTION_EXCERPT_LEN],
        "cwe": _weaknesses(cve),
        "references": refs,
    }


# ---------- 对外主入口 ----------

def _reject_reason(name):
    """输入预校验。返回拒绝原因（非真实固件输入），None 表示可继续。"""
    name = (name or "").strip()
    if not name:
        return "empty"
    if len(name) > 80:
        return "too_long"
    if not re.search(r"[A-Za-z0-9]", name):
        return "no_alnum"
    return None


def _empty_result(name, reason):
    return {
        "firmware": name,
        "found": False,
        "reason": reason,
        "candidate_count": 0,
        "result_count": 0,
        "source": None,
        "results": [],
    }


def _download_precheck(results):
    """下载前预检。有 GitHub POC 引用才需要查 GitHub 配额，不足返回警告（None 表示可下载）。
    以后换快代理海外后，这里追加查快代理额度的逻辑即可。"""
    has_github = any(
        "github.com" in (ref.get("url") or "").lower()
        for r in results
        for ref in r["references"]
        if ref.get("is_poc")
    )
    if not has_github:
        return None
    rem = github_quota_remaining()
    if rem == -1:
        return "GitHub 配额查询失败（网络/鉴权），跳过 POC 下载"
    if rem < GITHUB_RATE_MIN:
        return f"GitHub 配额不足（剩 {rem}/60），跳过 POC 下载：配 GITHUB_TOKEN 或稍后再试"
    return None


def _fetch_epss(cve_ids):
    """批量查 EPSS 危险评分（每批最多 100 个）。返回 {cve_id: (epss, percentile)}，失败返回已拿到的。"""
    ids = [i for i in (cve_ids or []) if i]
    out = {}
    for i in range(0, len(ids), 100):
        batch = ids[i:i + 100]
        url = f"{EPSS_API_URL}?cve={','.join(batch)}"
        data = _cache.get(url)
        if data is None:
            try:
                resp = _sess.get(url, timeout=HTTP_TIMEOUT)
                resp.raise_for_status()
                data = resp.json()
                _cache.put(url, data)
            except Exception:
                return out   # 部分失败：返回已拿到的，不崩
        for item in data.get("data", []):
            cve = item.get("cve")
            if cve:
                try:
                    out[cve] = (float(item.get("epss", 0)), float(item.get("percentile", 0)))
                except (TypeError, ValueError):
                    out[cve] = (0.0, 0.0)
    return out


def _apply_epss(results):
    """给结果加 EPSS 危险评分并加权打分。失败时静默跳过（不崩任务）。"""
    if not results:
        return
    scores = _fetch_epss([r["cve_id"] for r in results])
    for r in results:
        hit = scores.get(r["cve_id"])
        if hit is None:
            r["epss"] = None
            r["epss_percentile"] = None
            continue
        r["epss"] = round(hit[0], 4)
        r["epss_percentile"] = round(hit[1], 4)
        r["score"] = round(min(r["score"] + EPSS_WEIGHT * hit[0], 1.0), 3)


def _search_product(query, source_tag, max_results=20, version=None):
    """搜一个产品名（固件或组件），返回带 from 标记的 scored 结果（截断 max_results）。
    version 提供时做受影响版本匹配：明确不受影响的剔除，命中的加分。"""
    fw = parse_firmware(query)
    if not re.search(r"[a-z]", fw["model_core"]) or len(fw["model_core"]) < 3:
        return []   # 泛化守卫
    source, candidates, errors = _get_candidates(fw, None, candidate_limit=COMPONENT_CANDIDATE_LIMIT)
    if OSV_ENABLED:
        osv_records = _osv_search(query, limit=COMPONENT_CANDIDATE_LIMIT)
        candidates = (candidates or []) + osv_records
    if not candidates:
        return []
    out = []
    for cve in candidates:
        score, reasons, ok = score_cve(cve, fw)
        if ok:
            r = build_result(cve)
            r["score"] = round(score, 3)
            r["match_reasons"] = reasons
            r["from"] = source_tag
            r["version_match"] = _version_in_ranges(version, _cve_version_ranges(cve)) if version else None
            out.append(r)
    if version:
        # 明确不受影响的剔除（有版本信息但不在受影响范围内）
        out = [r for r in out if r.get("version_match") is not False]
        for r in out:
            if r.get("version_match") is True:
                r["score"] = round(min(r["score"] + 0.1, 1.0), 3)
                r["match_reasons"] = r.get("match_reasons", []) + [f"ver_match:{version}"]
    out.sort(key=lambda x: x["score"], reverse=True)
    return out[:max_results]


def _write_manifest(manifest_dir, firmware_name, source, scored):
    """把固件涉及的全部 CVE 编号清单写入 output/<固件>/_cves.json（不受 top_n 截断）。"""
    if not scored:
        return
    path = os.path.join(OUTPUT_DIR, manifest_dir, "_cves.json")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        manifest = {
            "firmware": firmware_name,
            "source": source,
            "total_cves": len(scored),
            "cves": [
                {
                    "cve_id": x["cve_id"],
                    "score": x["score"],
                    "match_reasons": x.get("match_reasons", []),
                    "poc_downloaded": any(
                        ref.get("poc_local") for ref in x["references"] if ref.get("is_poc")
                    ),
                    "downloaded_at": next(
                        (ref.get("downloaded_at") for ref in x["references"] if ref.get("poc_local")), None
                    ),
                    "poc_links": [ref["url"] for ref in x["references"] if ref.get("is_poc")],
                    "epss": x.get("epss"),
                    "community_pocs": [
                        {"repo": c.get("repo"), "url": c.get("url"), "stars": c.get("stars")}
                        for c in x.get("community_pocs", [])
                    ],
                }
                for x in scored
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def _query_hash(firmware_name, download_poc, community_poc, component=None):
    """结果缓存的身份标识：防目录名碰撞（不同输入可能 sanitize 成同名目录）。"""
    key = f"{firmware_name}|{download_poc}|{community_poc}|{_components_key(component)}"
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def _components_key(component):
    """组件参数归一成字符串（列表排序，保证 hash 稳定）。"""
    if not component:
        return ""
    if isinstance(component, (str, dict)):
        return _component_str(component)
    return ",".join(sorted(_component_str(c) for c in component if c))


def _component_str(comp):
    """组件归一成可读字符串（含版本）。"""
    if isinstance(comp, dict):
        name = (comp.get("name") or "").strip()
        ver = (comp.get("version") or "").strip()
        return f"{name} {ver}" if ver else name
    return (comp or "").strip()


def _components_list(component):
    """组件参数归一成字符串列表（含版本，用于输出展示）。"""
    if not component:
        return []
    comps = [component] if isinstance(component, (str, dict)) else component
    return [_component_str(c) for c in comps if c]


def _parse_component(comp):
    """解析组件为 (name, version)。支持：
    'openssl' → ('openssl', None)
    'openssl 1.0.1f' → ('openssl', '1.0.1f')
    {'name':'openssl','version':'1.0.1f'} → ('openssl', '1.0.1f')"""
    if isinstance(comp, dict):
        name = (comp.get("name") or "").strip()
        ver = (comp.get("version") or "").strip()
        return name, (ver or None)
    s = (comp or "").strip()
    if not s:
        return "", None
    m = re.search(r"\s(v?\d[\d.\-]*(?:[a-z]+\d*)?)\s*$", s)
    if m:
        return s[:m.start()].strip(), m.group(1)
    return s, None


def _ver_key(v):
    """版本号转可比较数值元组。'1.0.1f'/'v2.5' → (1,0,1)/(2,5)。
    处理 Debian 格式：'1:1.20.0-3'（epoch:版本-revision）→ (1,20,0)。无法解析返回 None。"""
    if v is None:
        return None
    s = str(v).strip().lower()
    if ":" in s:            # Debian epoch
        s = s.split(":", 1)[1]
    s = s.split("-")[0]     # Debian revision
    m = re.match(r"v?(\d+(?:[.\-]\d+)*)", s)
    if not m:
        return None
    return tuple(int(x) for x in re.split(r"[.\-]", m.group(1)))


def _ver_cmp(a, b):
    """版本比较：1/-1/0；无法比较返回 None。"""
    ka, kb = _ver_key(a), _ver_key(b)
    if ka is None or kb is None:
        return None
    return (ka > kb) - (ka < kb)


def _parse_range_string(s, default_op="eq"):
    """解析版本范围字符串 '>= 0.10.50, < 0.10.80' → [('ge','0.10.50'),('lt','0.10.80')]。
    default_op：纯版本（无操作符）时的默认操作符。"""
    out = []
    if not s or s in ("n/a", "*", "-"):
        return out
    for part in str(s).split(","):
        part = part.strip()
        m = re.match(r"(<=|>=|<|>|==|=)\s*(v?\d[\d.\-]*)", part)
        if m:
            op = {"<=": "le", ">=": "ge", "<": "lt", ">": "gt", "==": "eq", "=": "eq"}[m.group(1)]
            out.append((op, m.group(2)))
        else:
            m2 = re.match(r"v?\d[\d.\-]*", part)
            if m2:
                out.append((default_op, m2.group(0)))
    return out


def _cve_version_ranges(cve):
    """提取 CVE 受影响版本范围，返回 [(op, ver)]。
    op: le(<=) / lt(<) / eq(==) / ge(>=) / gt(>)。
    cve.org: affected[].versions[]（lessThanOrEqual/lessThan/version 可能是范围字符串）
    NVD: configurations[].nodes[].cpeMatch[]（versionStart/End Including/Excluding）"""
    ranges = []
    for a in (cve.get("affected") or []):
        if not isinstance(a, dict):
            continue
        for v in (a.get("versions") or []):
            if not isinstance(v, dict):
                continue
            if v.get("status") not in (None, "affected"):
                continue
            if v.get("lessThanOrEqual"):
                ranges.append(("le", str(v["lessThanOrEqual"])))
            if v.get("lessThan"):
                ranges.append(("lt", str(v["lessThan"])))
            if v.get("version") and v.get("version") != "*":
                # 有上下界时 version 是受影响起始版本(ge)；无界时才是精确版本(eq)
                has_bound = bool(v.get("lessThanOrEqual") or v.get("lessThan"))
                ranges.extend(_parse_range_string(v["version"], default_op="ge" if has_bound else "eq"))
    for cfg in (cve.get("configurations") or []):
        if not isinstance(cfg, dict):
            continue
        for node in (cfg.get("nodes") or []):
            if not isinstance(node, dict):
                continue
            for m in (node.get("cpeMatch") or []):
                if not isinstance(m, dict):
                    continue
                if m.get("versionEndIncluding"):
                    ranges.append(("le", str(m["versionEndIncluding"])))
                if m.get("versionEndExcluding"):
                    ranges.append(("lt", str(m["versionEndExcluding"])))
                if m.get("versionStartIncluding"):
                    ranges.append(("ge", str(m["versionStartIncluding"])))
                if m.get("versionStartExcluding"):
                    ranges.append(("gt", str(m["versionStartExcluding"])))
    ranges.extend(cve.get("_osv_ranges") or [])   # OSV 的 introduced/fixed
    return ranges


def _version_in_ranges(version, ranges):
    """输入版本是否落在 CVE 受影响范围。
    True=命中；False=明确不受影响；None=无法判断（无版本信息/不可比较）。"""
    if not version or not ranges:
        return None
    any_compared = False
    for op, rv in ranges:
        c = _ver_cmp(version, rv)
        if c is None:
            continue
        any_compared = True
        if op == "le" and c > 0:
            return False
        if op == "lt" and c >= 0:
            return False
        if op == "eq" and c != 0:
            return False
        if op == "ge" and c < 0:
            return False
        if op == "gt" and c <= 0:
            return False
    return True if any_compared else None


def _load_result_cache(manifest_dir, query_hash, top_n, download_poc, community_poc):
    """读结果缓存。命中且新鲜、且 hash 匹配、且覆盖本次请求范围才返回，否则 None。
    缓存存全量；返回时按 top_n 截断、清内部元数据。"""
    path = os.path.join(OUTPUT_DIR, manifest_dir, "_result.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not data.get("found"):
        return None
    if data.get("query_hash") != query_hash:   # 目录名碰撞 → 缓存不属于这次查询
        return None
    if data.get("_ts", 0) + RESULT_CACHE_TTL < time.time():
        return None
    # 覆盖判断：要下载但缓存没下过 → 重跑；要社区但缓存没搜 → 重跑
    if community_poc and not data.get("community_poc"):
        return None
    if download_poc:
        if not data.get("download_poc"):
            return None
        # 下载范围：缓存只下了 top_n 条，这次请求要更多 → 重跑（top_n=0 表示要全部）
        cached_scope = data.get("download_top_n", 0)            # 0 = 全量已下载
        requested_scope = float("inf") if top_n == 0 else top_n
        if cached_scope != 0 and requested_scope > cached_scope:
            return None
    data.pop("_ts", None)
    data.pop("query_hash", None)
    data.pop("download_poc", None)
    data.pop("download_top_n", None)
    data.pop("community_poc", None)
    if top_n and top_n > 0:
        data["results"] = data["results"][:top_n]
        data["result_count"] = len(data["results"])
    return data


def _save_result_cache(manifest_dir, query_hash, result, download_poc, community_poc, download_top_n=0):
    """存结果缓存（存全量，返回时再截断 top_n）。"""
    if not result.get("found"):
        return
    path = os.path.join(OUTPUT_DIR, manifest_dir, "_result.json")
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = dict(result)
        data["_ts"] = time.time()
        data["query_hash"] = query_hash
        data["download_poc"] = download_poc
        data["download_top_n"] = download_top_n if download_poc else 0
        data["community_poc"] = community_poc
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except OSError:
        pass


def search_firmware(firmware_name, top_n=DEFAULT_TOP_N, download_poc=False, community_poc=False,
                    force_refresh=False, component=None):
    """固件名（或 CVE 编号）→ 相关 CVE 列表 JSON dict。搜不到返回 found=false，不瞎猜。
    download_poc=True 时顺带下载 POC 到 output/<固件>/<CVE>/。
    community_poc=True 时，对无官方 POC 的 CVE 额外搜 GitHub 社区 POC 补充。
    force_refresh=True 时绕过结果缓存重跑。
    component：固件内组件名（字符串或列表，如 "busybox" / ["busybox","openssl"]），
    信息增强——顺带搜组件 CVE 一起返回，每条标 from。"""
    raw = (firmware_name or "").strip()
    reason = _reject_reason(raw)
    if reason:
        return _empty_result(raw, reason)

    m = CVE_ID_RE.match(raw)
    cve_id = m.group(0).upper() if m else None
    fw = None if cve_id else parse_firmware(raw)

    # 型号泛化守卫：纯数字或太短 → 不是真实固件型号（防 "12345" 误报）
    if fw and (not re.search(r"[a-z]", fw["model_core"]) or len(fw["model_core"]) < 3):
        return _empty_result(raw, "model_too_generic")

    # 输出目录（缓存/清单/下载都用）：精确查 → output/<CVE>/；固件 → output/<固件>/
    if cve_id:
        fw_dir = ""
        manifest_dir = cve_id
    else:
        fw_dir = re.sub(r"[^A-Za-z0-9._-]", "_", raw) or "firmware"
        manifest_dir = fw_dir

    # 结果缓存：TTL 内直接返回（带 cached 标记），不重跑不重下；hash 防目录名碰撞
    query_hash = _query_hash(raw, download_poc, community_poc, component)
    if not force_refresh:
        cached = _load_result_cache(manifest_dir, query_hash, top_n, download_poc, community_poc)
        if cached is not None:
            cached["cached"] = True
            return cached

    source, candidates, errors = _get_candidates(fw, cve_id)
    if source is None:
        if errors:
            out = _empty_result(raw, "provider_error")
            out["errors"] = errors
            return out
        return _empty_result(raw, "no_source_match")

    scored = []
    for cve in candidates:
        if cve_id:
            r = build_result(cve)
            r["score"] = 1.0
            r["match_reasons"] = ["cve_id_exact"]
            r["from"] = "cve_id_exact"
            scored.append(r)
        else:
            score, reasons, ok = score_cve(cve, fw)
            if ok:
                r = build_result(cve)
                r["score"] = round(score, 3)
                r["match_reasons"] = reasons
                r["from"] = "firmware"
                scored.append(r)

    # 组件信息增强：顺带搜组件 CVE，合并去重（固件结果优先保留）
    if component and not cve_id:
        comps = [component] if isinstance(component, (str, dict)) else component
        for comp in comps:
            comp_name, comp_ver = _parse_component(comp)
            if not comp_name:
                continue
            scored.extend(_search_product(comp_name, f"component:{comp_name}", version=comp_ver))
        seen = {}
        for r in scored:
            if r["cve_id"] not in seen:
                seen[r["cve_id"]] = r
        scored = list(seen.values())
        scored.sort(key=lambda x: x["score"], reverse=True)

    # EPSS 危险评分：加权 + 重排（失败静默跳过，不阻塞）
    if EPSS_ENABLED and scored:
        _apply_epss(scored)
        scored.sort(key=lambda x: x["score"], reverse=True)

    scored_all = scored

    if top_n and top_n > 0:
        scored = scored[:top_n]

    notice = None
    if download_poc and scored:
        notice = _download_precheck(scored)
        if notice:
            # 预检警告：只预标记 GitHub 引用跳过；exploit-db 等不消耗 GitHub 配额的照常下
            for r in scored:
                for ref in r["references"]:
                    if ref.get("is_poc") and "github.com" in (ref.get("url") or "").lower():
                        ref["poc_local"] = []
                        ref["download_skipped"] = notice
        # 并发下载：GitHub 引用若被预标记则快速跳过，其他源正常下（有界，尊重限速）
        with ThreadPoolExecutor(max_workers=DOWNLOAD_CONCURRENCY) as ex:
            futures = [ex.submit(download_poc_for_cve, r, fw_dir) for r in scored]
            for fut in futures:
                fut.result()
        # 社区 POC 补充：配额正常时，对无官方 POC 的 CVE 搜 GitHub（串行节流）
        if community_poc and not notice:
            for r in scored:
                community_poc_supplement(r, fw_dir)

    # 固件涉及的全部 CVE 编号清单落盘（全量；下载完成后写，poc_downloaded 反映真实状态）
    if scored_all:
        _write_manifest(manifest_dir, raw, source, scored_all)

    # 完整结果（存缓存用，全量不截断）
    out_full = {
        "firmware": firmware_name,
        "components": _components_list(component),
        "found": bool(scored_all),
        "candidate_count": len(candidates),
        "result_count": len(scored_all),
        "source": source,
        "results": scored_all,
    }
    if notice:
        out_full["notice"] = notice
    if cve_id:
        out_full["normalized"] = {"cve_id": cve_id}
    else:
        out_full["normalized"] = {"vendor": fw["vendor"], "model_core": fw["model_core"]}
    _save_result_cache(manifest_dir, query_hash, out_full, download_poc, community_poc, download_top_n=top_n)

    # 返回结果（按 top_n 截断）
    out = dict(out_full)
    out["results"] = scored
    out["result_count"] = len(scored)
    return out


def _main():
    download = "--download" in sys.argv[1:]
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(json.dumps({"error": "用法: python cve_search.py <固件型号名 或 CVE-xxxx-xxxx> [--download]"}, ensure_ascii=False))
        return
    print(json.dumps(search_firmware(args[0], download_poc=download), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _main()
