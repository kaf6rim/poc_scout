"""搜索模块集成测试：固件/组件/版本/EPSS，全部 mock 数据源，离线可跑。"""
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
