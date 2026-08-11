"""搜索模块集成测试：固件/组件/版本/EPSS，全部 mock 数据源，离线可跑。"""
import cve_search
import poc_downloader
from cve_search import search_firmware, _parse_component, _components_list


# ---------- 输入解析 ----------

def test_parse_component_forms():
    assert _parse_component("openssl") == ("openssl", None)
    assert _parse_component("openssl 1.0.1f") == ("openssl", "1.0.1f")
    assert _parse_component({"name": "busybox", "version": "1.22.0"}) == ("busybox", "1.22.0")


def test_components_list_normalized():
    assert _components_list("busybox") == ["busybox"]
    assert _components_list("openssl 1.0.1f") == ["openssl 1.0.1f"]
    assert _components_list([{"name": "busybox", "version": "1.22.0"}]) == ["busybox 1.22.0"]


# ---------- 固件搜索 ----------

def test_firmware_search_returns_results(make_cve, fake_sources, tmp_output):
    rec = make_cve("CVE-2024-0001", product="Test Device")
    fake_sources(records=[rec])
    r = search_firmware("Test Device", force_refresh=True)
    assert r["found"] is True
    assert r["results"][0]["cve_id"] == "CVE-2024-0001"
    assert r["results"][0]["from"] == "firmware"
    assert r["results"][0]["score"] > 0


def test_garbage_input_rejected(fake_sources, tmp_output):
    for bad in ["", "!!!", "12345"]:
        r = search_firmware(bad)
        assert r["found"] is False
        assert r.get("reason"), f"{bad!r} 应带 reason"


def test_not_found_honest(make_cve, fake_sources, tmp_output):
    fake_sources(records=[])   # 无候选
    r = search_firmware("Nonexistent Device", force_refresh=True)
    assert r["found"] is False


# ---------- 组件合并 ----------

def test_component_merge(make_cve, fake_sources, tmp_output):
    fw = make_cve("CVE-2024-0001", product="Test Device")
    comp = make_cve("CVE-2024-0002", product="busybox")
    fake_sources(records=[fw], osv_records=[comp])
    r = search_firmware("Test Device", component="busybox", force_refresh=True)
    froms = {x["cve_id"]: x.get("from") for x in r["results"]}
    assert froms["CVE-2024-0001"] == "firmware"
    assert froms["CVE-2024-0002"] == "component:busybox"


# ---------- 组件版本精化 ----------

def test_component_version_match(make_cve, fake_sources, tmp_output):
    fw = make_cve("CVE-2024-0001", product="Test Device")
    rec = make_cve(
        "CVE-2024-0002", product="busybox",
        affected_versions=[{"version": "1.0", "status": "affected", "lessThanOrEqual": "1.5"}],
    )
    fake_sources(records=[fw], osv_records=[rec])
    r = search_firmware("Test Device", component={"name": "busybox", "version": "1.4"}, force_refresh=True)
    comp = [x for x in r["results"] if x.get("from", "").startswith("component")]
    assert comp and comp[0]["version_match"] is True


def test_component_version_not_affected_filtered(make_cve, fake_sources, tmp_output):
    fw = make_cve("CVE-2024-0001", product="Test Device")
    rec = make_cve(
        "CVE-2024-0002", product="busybox",
        affected_versions=[{"version": "1.0", "status": "affected", "lessThanOrEqual": "1.5"}],
    )
    fake_sources(records=[fw], osv_records=[rec])
    # 版本 2.0 > 1.5 → 明确不受影响 → 剔除
    r = search_firmware("Test Device", component={"name": "busybox", "version": "2.0"}, force_refresh=True)
    comp = [x for x in r["results"] if x.get("from", "").startswith("component")]
    assert not comp


# ---------- EPSS ----------

def test_epss_affects_score(make_cve, fake_sources, tmp_output):
    rec = make_cve("CVE-2024-0001", product="Test Device")
    fake_sources(records=[rec], epss={"CVE-2024-0001": (0.9, 0.99)})
    r = search_firmware("Test Device", force_refresh=True)
    top = r["results"][0]
    assert top["epss"] == 0.9
    assert top["epss_percentile"] == 0.99
    # 0.9 概率应显著加分
    assert top["score"] > 0.7


# ---------- 精确 CVE 查 ----------

def test_exact_cve_lookup(make_cve, fake_sources, tmp_output):
    rec = make_cve("CVE-2024-0001", product="Test Device")
    fake_sources(records=[rec])
    r = search_firmware("CVE-2024-0001", force_refresh=True)
    assert r["found"] is True
    assert r["results"][0]["cve_id"] == "CVE-2024-0001"
    assert r["results"][0]["from"] == "cve_id_exact"


# ---------- NVD 兜底 ----------

def test_nvd_fallback(monkeypatch, tmp_output, make_cve):
    rec = make_cve("CVE-2024-0002", product="NVD Device")
    monkeypatch.setitem(cve_search.PROVIDERS, "cveorg",
                        lambda fw, cve_id, candidate_limit=None: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setitem(cve_search.PROVIDERS, "nvd",
                        lambda fw, cve_id, candidate_limit=None: [rec])
    monkeypatch.setattr(cve_search, "SEARCH_PROVIDERS", ["cveorg", "nvd"])
    monkeypatch.setattr(cve_search, "_fetch_epss", lambda ids: {})
    r = search_firmware("NVD Device", force_refresh=True)
    assert r["source"] == "nvd"
    assert r["results"][0]["cve_id"] == "CVE-2024-0002"


def test_all_providers_down_honest(monkeypatch, tmp_output):
    monkeypatch.setitem(cve_search.PROVIDERS, "cveorg",
                        lambda fw, cve_id, candidate_limit=None: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setitem(cve_search.PROVIDERS, "nvd",
                        lambda fw, cve_id, candidate_limit=None: (_ for _ in ()).throw(RuntimeError("down")))
    monkeypatch.setattr(cve_search, "SEARCH_PROVIDERS", ["cveorg", "nvd"])
    r = search_firmware("Test Device", force_refresh=True)
    assert r["found"] is False
    assert r.get("reason") == "provider_error"


# ---------- 社区 POC 补充 ----------

def test_community_poc(monkeypatch, tmp_output, make_cve, fake_sources):
    fw = make_cve("CVE-2024-0001", product="Test Device")
    fake_sources(records=[fw])
    monkeypatch.setattr(cve_search, "github_quota_remaining", lambda: 50)   # 配额充足
    monkeypatch.setattr(poc_downloader, "search_github_poc_repos",
                        lambda cve_id, per_page=None: [("foo", "bar", 5)])
    monkeypatch.setattr(poc_downloader, "list_repo_files", lambda owner, repo: (["poc.py"], 200))
    monkeypatch.setattr(poc_downloader, "download_raw",
                        lambda owner, repo, path: (b"#!/usr/bin/env python\nprint()", 200))
    monkeypatch.setattr(poc_downloader.time, "sleep", lambda s: None)       # 跳过节流 sleep
    r = search_firmware("Test Device", download_poc=True, community_poc=True, force_refresh=True)
    assert r["results"][0].get("community_pocs"), "应有社区 POC 补充"
