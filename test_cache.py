"""结果缓存 / hash 测试。"""
from cve_search import (
    _query_hash, _components_key,
    _save_result_cache, _load_result_cache,
)


def test_query_hash_deterministic():
    assert _query_hash("A", False, False) == _query_hash("A", False, False)
    assert _query_hash("A", False, False) != _query_hash("B", False, False)


def test_query_hash_includes_component():
    assert _query_hash("A", False, False, "busybox") != _query_hash("A", False, False)


def test_components_key_order_stable():
    assert _components_key(["b", "a"]) == _components_key(["a", "b"])


def test_result_cache_roundtrip(tmp_output, make_cve):
    rec = make_cve("CVE-2024-0001", product="Test Device")
    result = {"found": True, "firmware": "Test Device", "results": [rec]}
    qh = _query_hash("Test Device", False, False)
    _save_result_cache("Test_Device", qh, result, False, False)
    loaded = _load_result_cache("Test_Device", qh, 0, False, False)
    assert loaded is not None
    assert loaded["results"][0]["id"] == "CVE-2024-0001"


def test_result_cache_hash_mismatch_miss(tmp_output, make_cve):
    rec = make_cve("CVE-2024-0001", product="Test Device")
    result = {"found": True, "firmware": "Test Device", "results": [rec]}
    _save_result_cache("Test_Device", _query_hash("A", False, False), result, False, False)
    # 不同 hash → 当作目录名碰撞，未命中
    assert _load_result_cache("Test_Device", _query_hash("B", False, False), 0, False, False) is None


def test_result_cache_topn_truncate(tmp_output, make_cve):
    recs = [make_cve("CVE-2024-0001", product="Test Device"), make_cve("CVE-2024-0002", product="Test Device")]
    result = {"found": True, "firmware": "Test Device", "results": recs}
    qh = _query_hash("Test Device", False, False)
    _save_result_cache("Test_Device", qh, result, False, False)
    loaded = _load_result_cache("Test_Device", qh, 1, False, False)
    assert loaded is not None
    assert len(loaded["results"]) == 1
