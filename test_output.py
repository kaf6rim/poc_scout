"""输出结构测试：main.json（CVE 信息栏）+ <CVE编号>.json（全量 poc 含内容）+ severity 提取。"""
import base64
import json
import os

from cve_search import (
    _main_cve_entry, _write_main_json, _write_cve_poc_json, _extract_severity,
)


# ---------- severity 提取（三数据源权威性 + 崩溃回归）----------

def test_severity_cveorg_list_metrics():
    """cve.org 归一化记录 metrics 是 list——曾因对 list 调 .get() 崩溃（回归测试）。"""
    rec = {"metrics": [{"cvssV3_1": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]}
    assert _extract_severity(rec) == ("HIGH", 7.5)


def test_severity_nvd_dict_metrics():
    rec = {"metrics": {"cvssMetricV31": [{"baseSeverity": "MEDIUM", "baseScore": 5.5}]}}
    assert _extract_severity(rec) == ("MEDIUM", 5.5)


def test_severity_osv_fallback():
    rec = {"_osv_severity": [{"type": "HIGH", "score": "CVSS:3.1"}]}
    assert _extract_severity(rec) == ("HIGH", "CVSS:3.1")


def test_severity_nvd_precedence():
    """NVD dict 结构优先于 cve.org list 结构。"""
    rec = {
        "metrics": {"cvssMetricV31": [{"baseSeverity": "CRITICAL", "baseScore": 9.8}]},
        "_osv_severity": [{"type": "LOW", "score": "3.0"}],
    }
    assert _extract_severity(rec) == ("CRITICAL", 9.8)


def test_severity_missing_returns_none():
    assert _extract_severity({}) == (None, None)
    assert _extract_severity({"metrics": []}) == (None, None)


# ---------- main.json 信息栏 ----------

def _poc_abs_path(tmp_output):
    return str(os.path.join(tmp_output, "Test_Device", "CVE-2024-0001_poc_1_exploit.py"))


def _scored(tmp_output, with_local=True):
    return {
        "cve_id": "CVE-2024-0001",
        "cve_url": "https://www.cve.org/CVERecord?id=CVE-2024-0001",
        "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
        "published": "2024-01-01T00:00:00",
        "description": "test vulnerability",
        "cwe": ["CWE-787"],
        "severity": "HIGH",
        "severity_score": 7.5,
        "extra": {"provider": "vendor", "datePublic": "2024-01-01"},
        "score": 0.9,
        "match_reasons": ["token_match"],
        "epss": 0.5,
        "epss_percentile": 0.8,
        "from": "firmware",
        "references": [
            {
                "url": "https://github.com/foo/bar/blob/main/exploit.py",
                "name": "exploit.py",
                "tags": ["Exploit"],
                "is_poc": True,
                "poc_source": "tag",
                "poc_local": [_poc_abs_path(tmp_output)] if with_local else [],
                "download_status": "ok" if with_local else "failed",
                "downloaded_at": "2024-01-02 10:00:00" if with_local else None,
                "download_skipped": None if with_local else "非代码型源，只记链接",
            },
            {"url": "https://example.com/advisory", "name": "adv", "tags": [],
             "is_poc": False, "poc_source": "none"},
        ],
    }


def test_main_cve_entry_fields():
    """信息栏：poc 无则 null、有则文件名列表；poc reference 摘要；severity/extra 扁平。"""
    rec = _scored("/tmp")
    entry = _main_cve_entry(rec)
    assert entry["severity"] == "HIGH"
    assert entry["severity_score"] == 7.5
    assert entry["extra"]["provider"] == "vendor"
    assert entry["from"] == "firmware"
    assert entry["poc_count"] == 1
    assert entry["poc"] == ["CVE-2024-0001_poc_1_exploit.py"]   # 有则文件名（basename）
    assert entry["poc_references"][0]["url"] == rec["references"][0]["url"]
    assert entry["poc_references"][0]["poc_local"] == ["CVE-2024-0001_poc_1_exploit.py"]
    assert entry["poc_references"][0]["download_status"] == "ok"
    # 非 poc 的 reference 不进 poc_references
    assert len(entry["poc_references"]) == 1


def test_main_cve_entry_community_poc(tmp_output):
    """社区补充的 poc：文件名进 poc，引用也进 poc_references（source=community）。"""
    rec = _scored(tmp_output, with_local=False)
    rec["community_pocs"] = [{
        "repo": "foo/poc", "stars": 100,
        "url": "https://github.com/foo/poc",
        "poc_local": [str(os.path.join(tmp_output, "Test_Device", "CVE-2024-0001_poc_1_community.py"))],
        "downloaded_at": "2024-01-03 09:00:00",
    }]
    entry = _main_cve_entry(rec)
    assert entry["poc"] == ["CVE-2024-0001_poc_1_community.py"]
    assert entry["poc_count"] == 1
    assert any(r["source"] == "community" for r in entry["poc_references"])


def test_main_cve_entry_no_poc_is_null(tmp_output):
    rec = _scored(tmp_output, with_local=False)
    entry = _main_cve_entry(rec)
    assert entry["poc_count"] == 0
    assert entry["poc"] is None   # 无则 null


def test_write_main_json(tmp_output):
    _write_main_json("Test_Device", "Test Device", "cveorg", [_scored(tmp_output)],
                     components=["busybox"])
    path = os.path.join(tmp_output, "Test_Device", "main.json")
    assert os.path.isfile(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["firmware"] == "Test Device"
    assert data["source"] == "cveorg"
    assert data["total_cves"] == 1
    assert data["components"] == ["busybox"]
    assert data["cves"][0]["cve_id"] == "CVE-2024-0001"
    assert data["cves"][0]["poc"] == ["CVE-2024-0001_poc_1_exploit.py"]
    assert "severity" in data["cves"][0]


def test_write_cve_poc_json(tmp_output):
    """<CVE编号>.json：下载成功的带 base64 内容；仅记链接的只有元数据。"""
    # 先让 poc 文件真实存在（base64 读取依赖它）
    poc_path = _poc_abs_path(tmp_output)
    os.makedirs(os.path.dirname(poc_path), exist_ok=True)
    with open(poc_path, "wb") as f:
        f.write(b"#!/usr/bin/env python\nprint('poc')")
    _write_cve_poc_json("Test_Device", [_scored(tmp_output)])
    path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001.json")
    assert os.path.isfile(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["cve_id"] == "CVE-2024-0001"
    assert data["poc_count"] == 1
    poc = data["pocs"][0]
    assert poc["local_file"] == "CVE-2024-0001_poc_1_exploit.py"
    assert poc["content_encoding"] == "base64"
    assert base64.b64decode(poc["content"]) == b"#!/usr/bin/env python\nprint('poc')"
    assert poc["source"] == "tag"


def test_write_cve_poc_json_link_only(tmp_output):
    """未下载成功的 poc：json 里只有元数据，内容为 null。"""
    _write_cve_poc_json("Test_Device", [_scored(tmp_output, with_local=False)])
    path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001.json")
    assert os.path.isfile(path)
    data = json.loads(open(path, encoding="utf-8").read())
    assert data["poc_count"] == 1
    poc = data["pocs"][0]
    assert poc["content"] is None
    assert poc["download_skipped"]  # 只记链接


def test_write_cve_poc_json_skips_no_poc(tmp_output):
    """无任何 poc 记录的 CVE 不写 json。"""
    rec = _scored(tmp_output, with_local=False)
    rec["references"][0]["is_poc"] = False
    _write_cve_poc_json("Test_Device", [rec])
    path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001.json")
    assert not os.path.exists(path)


def test_community_poc_content_not_embedded(tmp_output):
    """未验证的社区 POC：json 不嵌 base64 内容，只记元数据 + unverified/commit_sha 标记。"""
    poc_path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001_poc_1_community.py")
    os.makedirs(os.path.dirname(poc_path), exist_ok=True)
    with open(poc_path, "wb") as f:
        f.write(b"#!/usr/bin/env python\nprint('community')")
    rec = _scored(tmp_output, with_local=False)
    rec["community_pocs"] = [{
        "repo": "foo/poc", "stars": 100,
        "url": "https://github.com/foo/poc",
        "poc_local": [poc_path],
        "downloaded_at": "2024-01-03 09:00:00",
        "commit_sha": "abc123",
        "unverified_source": True,
    }]
    _write_cve_poc_json("Test_Device", [rec])
    path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001.json")
    data = json.loads(open(path, encoding="utf-8").read())
    # 官方引用条目前置、社区条目在后 → 按 source 定位社区条目
    poc = next(p for p in data["pocs"] if p.get("source") == "community")
    assert poc["content"] is None
    assert poc["content_encoding"] is None
    assert poc["unverified_source"] is True
    assert poc["commit_sha"] == "abc123"


def test_community_poc_verified_embeds_content(tmp_output):
    """验证通过的社区 POC：嵌 base64 内容（与官方引用一致），并记 verification 说明。"""
    poc_path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001_poc_1_community.py")
    os.makedirs(os.path.dirname(poc_path), exist_ok=True)
    with open(poc_path, "wb") as f:
        f.write(b"#!/usr/bin/env python\nprint('ok')")
    rec = _scored(tmp_output, with_local=False)
    rec["community_pocs"] = [{
        "repo": "foo/poc", "stars": 100,
        "url": "https://github.com/foo/poc",
        "poc_local": [poc_path],
        "downloaded_at": "2024-01-03 09:00:00",
        "commit_sha": "abc123",
        "verified": True,
        "verification": "static_ok",
    }]
    _write_cve_poc_json("Test_Device", [rec])
    path = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001.json")
    data = json.loads(open(path, encoding="utf-8").read())
    poc = next(p for p in data["pocs"] if p.get("source") == "community")
    assert poc["content_encoding"] == "base64"
    assert base64.b64decode(poc["content"]) == b"#!/usr/bin/env python\nprint('ok')"
    assert poc.get("verification") == "static_ok"
