# poc_downloader.py —— GitHub POC 下载
# 流程：解析 GitHub 仓库 → API 列文件树 → 本地过滤 POC 代码文件 → 下 raw → 落盘 output/
# 轮换思路：撞 403/429/502 先 rotate_ip() 换出口 IP 重试，不行再报错。
import os
import re
import time

import requests

from config import (
    OUTPUT_DIR, HTTP_TIMEOUT, GITHUB_TOKEN,
    MAX_POC_FILES_PER_REPO, MAX_POC_FILE_BYTES,
    COMMUNITY_POC_PER_CVE, GITHUB_SEARCH_SLEEP,
)
from proxy import proxies_for_github, github_headers, rotate_ip

GITHUB_REPO_RE = re.compile(r"github\.com/([^/]+)/([^/#?]+)", re.I)
# blob 型引用：github.com/owner/repo/blob/<branch>/<path>
GITHUB_BLOB_RE = re.compile(r"github\.com/([^/]+)/([^/#?]+)/blob/[^/]+/(.+)", re.I)
GITHUB_RATE_MIN = 10   # 下载前预检阈值：剩余配额低于此值就跳过下载
EXPLOITDB_RE = re.compile(r"exploit-db\.com/(?:exploits|download)/(\d+)", re.I)
POC_NAME_RE = re.compile(r"(poc|exploit|proof[\s_-]*of[\s_-]*concept|cve-\d{4}-\d{3,})", re.I)
CODE_EXT = {".py", ".sh", ".pl", ".rb", ".c", ".h", ".go", ".java", ".php", ".js", ".ts",
            ".ps1", ".bat", ".lua", ".asm", ".rs"}
SKIP_EXT = {".png", ".jpg", ".jpeg", ".gif", ".svg", ".md", ".txt", ".pdf",
            ".zip", ".gz", ".7z", ".rar", ".bin", ".exe", ".elf", ".img", ".wav", ".mp4"}

# Content-Type → 扩展名（exploit-db 下载无文件名）
CT_EXT = {
    "text/x-python": ".py", "text/x-python-script": ".py",
    "text/x-ruby": ".rb", "text/x-ruby-script": ".rb",
    "text/x-php": ".php", "text/x-shellscript": ".sh",
    "text/x-c": ".c", "text/x-perl": ".pl",
    "text/plain": ".txt",
}


def _session():
    s = requests.Session()
    s.proxies.update(proxies_for_github())
    return s


def _now():
    """下载时间戳（本地时间，可读格式）。"""
    return time.strftime("%Y-%m-%d %H:%M:%S")


def github_quota_remaining():
    """查 GitHub 剩余配额。返回 remaining；-1 表示查询失败。"""
    resp = _safe_get("https://api.github.com/rate_limit")
    if resp is None or resp.status_code != 200:
        return -1
    try:
        return resp.json()["resources"]["core"]["remaining"]
    except (KeyError, ValueError):
        return -1


def _safe_get(url, **kw):
    """GET 捕获网络异常，异常返回 None（调用方按失败处理，不抛崩整个任务）。"""
    try:
        return _session().get(url, headers=github_headers(), timeout=HTTP_TIMEOUT, **kw)
    except requests.RequestException:
        return None


def _github_get(url, retries=2):
    """GET 带轮换重试：撞 403/429/502 先换 IP 再试，重试 N 次仍失败返回最后一次响应。"""
    resp = None
    for _ in range(retries + 1):
        resp = _safe_get(url)
        if resp is None:
            time.sleep(1)
            continue
        if resp.status_code in (403, 429, 502) and rotate_ip():
            time.sleep(1)
            continue
        return resp
    return resp


def _parse_github(url):
    m = GITHUB_REPO_RE.search(url)
    return (m.group(1), m.group(2)) if m else None


def _parse_github_blob(url):
    """解析 blob 型引用，返回 (owner, repo, path)；非 blob 引用返回 None。"""
    m = GITHUB_BLOB_RE.search(url)
    return (m.group(1), m.group(2), m.group(3)) if m else None


def _is_poc_file(path):
    low = path.lower()
    ext = os.path.splitext(low)[1]
    if ext in SKIP_EXT:
        return False
    return ext in CODE_EXT and POC_NAME_RE.search(low)


def list_repo_files(owner, repo):
    """列仓库 blob 文件树。返回 (paths, status)；status=0 表示网络失败。"""
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
    resp = _github_get(url)
    if resp is None:
        return None, 0
    if resp.status_code != 200:
        return None, resp.status_code
    tree = resp.json().get("tree", [])
    return [t["path"] for t in tree if t.get("type") == "blob"], 200


def download_raw(owner, repo, path):
    """下单个 raw 文件。返回 (content_bytes, status)；status=0 表示网络失败。"""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}"
    resp = _safe_get(url)
    if resp is None:
        return None, 0
    if resp.status_code != 200:
        return None, resp.status_code
    return resp.content, 200


def _ext_from_content_type(resp):
    ct = (resp.headers.get("Content-Type") or "").lower().split(";")[0].strip()
    return CT_EXT.get(ct, ".txt")


def _sniff_ext(content):
    """按内容特征猜 POC 语言扩展名，猜不出返回 None。"""
    head = content[:800].decode("utf-8", "replace")
    if "require 'msf" in head or 'require "msf' in head:
        return ".rb"                      # Metasploit Ruby 模块
    if head.startswith("#!") and "python" in head[:160].lower():
        return ".py"
    if head.startswith("#!") and re.search(r"/bin/(ba)?sh", head[:160]):
        return ".sh"
    if "<?php" in head:
        return ".php"
    if head.startswith("#!") and "perl" in head[:160].lower():
        return ".pl"
    # 无 shebang 的 Python：头部出现典型 import 语句
    if re.search(r"^import (requests|socket|urllib|sys|subprocess|ctypes|struct|scapy|http|re|time|json|argparse)\b", head, re.M):
        return ".py"
    return None


def _download_repo(owner, repo, cve_dir, cve_id):
    """列树→过滤 POC 文件→下 raw（官方引用和社区补充共用）。返回 (local_paths, skip_reason)。"""
    files, status = list_repo_files(owner, repo)
    if status in (403, 429):
        return [], f"GitHub 限速({status})：配 GITHUB_TOKEN 或切换 FlClash 节点后重试"
    if files is None:
        return [], f"列文件树失败 status={status}"
    poc_files = [p for p in files if _is_poc_file(p)][:MAX_POC_FILES_PER_REPO]
    if not poc_files:
        return [], "仓库内无 POC 代码文件（可能只有截图/文档）"

    os.makedirs(cve_dir, exist_ok=True)   # 有 POC 文件要下才建目录
    local = []
    for i, p in enumerate(poc_files, 1):
        content, st = download_raw(owner, repo, p)
        if st != 200 or not content or len(content) > MAX_POC_FILE_BYTES:
            continue
        base = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(p)) or "poc"
        out = os.path.join(cve_dir, f"{cve_id}_poc_{i}_{base}")
        with open(out, "wb") as f:
            f.write(content)
        local.append(out)
    return local, (None if local else "文件下载失败")


def _download_github_ref(ref, cve_dir, cve_id):
    blob = _parse_github_blob(ref["url"])
    if blob:
        _download_github_blob(ref, cve_dir, blob, cve_id)
        return
    gh = _parse_github(ref["url"])
    if not gh:
        ref["poc_local"] = []
        ref["download_skipped"] = "无法解析 GitHub 仓库"
        return
    local, skip = _download_repo(gh[0], gh[1], cve_dir, cve_id)
    ref["poc_local"] = local
    if local:
        ref["download_status"] = "ok"
        ref["downloaded_at"] = _now()
    else:
        ref["download_status"] = "failed"
        ref["download_skipped"] = skip


def _download_github_blob(ref, cve_dir, blob, cve_id):
    """blob 型引用：指向具体文件，直接检查该文件是否存活。
    文件被删（404）→ 诚实标注"引用已失效"，而不是笼统说"无 POC 代码文件"。"""
    owner, repo, path = blob
    files, status = list_repo_files(owner, repo)
    if status in (403, 429):
        ref["poc_local"] = []
        ref["download_status"] = "failed"
        ref["download_skipped"] = f"GitHub 限速({status})：配 GITHUB_TOKEN 或切换 FlClash 节点后重试"
        return
    if files is None:
        ref["poc_local"] = []
        ref["download_status"] = "failed"
        ref["download_skipped"] = f"列文件树失败 status={status}"
        return
    if path not in files:
        ref["poc_local"] = []
        ref["download_status"] = "failed"
        ref["download_skipped"] = "引用文件已失效（可能被作者删除）"
        return
    os.makedirs(cve_dir, exist_ok=True)
    content, st = download_raw(owner, repo, path)
    if st != 200 or not content or len(content) > MAX_POC_FILE_BYTES:
        ref["poc_local"] = []
        ref["download_status"] = "failed"
        ref["download_skipped"] = f"引用文件下载失败 status={st}"
        return
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(path)) or "poc"
    out = os.path.join(cve_dir, f"{cve_id}_poc_1_{safe}")
    with open(out, "wb") as f:
        f.write(content)
    ref["poc_local"] = [out]
    ref["download_status"] = "ok"
    ref["downloaded_at"] = _now()


def _download_exploitdb_ref(ref, cve_dir, cve_id):
    m = EXPLOITDB_RE.search(ref["url"])
    if not m:
        ref["poc_local"] = []
        ref["download_skipped"] = "无法解析 exploit-db 编号"
        return
    eid = m.group(1)
    resp = _safe_get(f"https://www.exploit-db.com/download/{eid}/", allow_redirects=True)
    if resp is None:
        ref["poc_local"] = []
        ref["download_skipped"] = "exploit-db 网络请求失败"
        return
    if resp.status_code != 200:
        ref["poc_local"] = []
        ref["download_skipped"] = f"exploit-db 下载失败 status={resp.status_code}"
        return
    if not resp.content or len(resp.content) > MAX_POC_FILE_BYTES:
        ref["poc_local"] = []
        ref["download_skipped"] = "exploit-db 返回空或文件过大"
        return

    os.makedirs(cve_dir, exist_ok=True)   # 有文件要写才建目录
    ext = _sniff_ext(resp.content) or _ext_from_content_type(resp)
    out = os.path.join(cve_dir, f"{cve_id}_poc_1_exploitdb_{eid}{ext}")
    with open(out, "wb") as f:
        f.write(resp.content)
    ref["poc_local"] = [out]
    ref["download_status"] = "ok"
    ref["downloaded_at"] = _now()


def download_poc_for_cve(result, firmware_dir):
    """对单个 CVE 结果里的 POC 引用下载，就地更新 result['references']。
    按源分发：GitHub（列树→挑代码→下 raw）/ exploit-db（下载原始 exploit）/ 其他只记链接。
    每个引用补字段：poc_local / download_skipped / download_status。
    poc 文件扁平落在结果目录（firmware_dir）下，文件名带 CVE 前缀。"""
    cve_id = result["cve_id"]
    cve_dir = os.path.join(OUTPUT_DIR, firmware_dir)

    for ref in result["references"]:
        if not ref.get("is_poc"):
            continue
        if ref.get("download_skipped"):   # 已被预检/先前跳过，不再尝试
            continue
        try:
            url = (ref.get("url") or "").lower()
            if "github.com" in url:
                _download_github_ref(ref, cve_dir, cve_id)
            elif "exploit-db.com" in url:
                _download_exploitdb_ref(ref, cve_dir, cve_id)
            else:
                ref["poc_local"] = []
                ref["download_skipped"] = "非代码型源（文章/公告/邮件列表），只记链接"
        except Exception as e:
            # 单个引用异常不崩整个任务
            ref["poc_local"] = []
            ref["download_skipped"] = f"下载异常: {type(e).__name__}: {e}"

    return result


# ---------- 社区 POC 补充（GitHub 仓库搜索）----------

def search_github_poc_repos(cve_id, per_page=None):
    """搜 GitHub 上该 CVE 的社区 POC 仓库（按 stars 排序）。返回 [(owner, repo, stars), ...]。
    仓库搜索 API 未认证 10/min，节流重试一次。"""
    per_page = per_page or COMMUNITY_POC_PER_CVE
    url = "https://api.github.com/search/repositories"
    params = {"q": f"{cve_id} poc", "sort": "stars", "order": "desc", "per_page": per_page}
    resp = None
    for attempt in range(2):
        resp = _safe_get(url, params=params)
        if resp is None:
            return []
        if resp.status_code == 200:
            break
        if resp.status_code in (403, 429) and attempt == 0:
            time.sleep(GITHUB_SEARCH_SLEEP)   # 搜索限速，退避重试
            continue
        return []
    if resp is None:
        return []
    try:
        items = resp.json().get("items", [])
    except ValueError:
        return []
    out = []
    cid = cve_id.lower()
    for it in items:
        full = it.get("full_name") or ""
        name = (it.get("name") or "").lower()
        if "poc" in name or "exploit" in name or cid in name:
            if "/" in full:
                o, r = full.split("/", 1)
                out.append((o, r, it.get("stargazers_count", 0)))
    return out[:per_page]


def community_poc_supplement(result, fw_dir):
    """对没从官方 reference 下到 POC 的 CVE，搜 GitHub 社区 POC 补充。就地更新 result。"""
    cve_id = result["cve_id"]
    # 已有官方 POC 下载 → 不补
    if any(ref.get("poc_local") for ref in result["references"] if ref.get("is_poc")):
        return result
    repos = search_github_poc_repos(cve_id)
    if not repos:
        return result
    cve_dir = os.path.join(OUTPUT_DIR, fw_dir)
    result.setdefault("community_pocs", [])
    for owner, repo, stars in repos:
        local, skip = _download_repo(owner, repo, cve_dir, cve_id)
        if local:
            result["community_pocs"].append({
                "repo": f"{owner}/{repo}",
                "stars": stars,
                "url": f"https://github.com/{owner}/{repo}",
                "poc_local": local,
                "downloaded_at": _now(),
            })
        time.sleep(GITHUB_SEARCH_SLEEP)   # 每 CVE 搜索后节流
    return result
