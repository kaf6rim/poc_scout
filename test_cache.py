"""结果缓存 / hash 测试。缓存文件名即 hash，存在临时 cache/ 目录（tmp_output fixture 已指向）。"""
import hashlib
import json
import os

from cve_search import (
    _query_hash, _components_key,
    _save_result_cache, _load_result_cache,
)


def _cache_path(tmp_output, qh):
    """结果缓存文件路径（tmp_output 的 cache 目录 + 文件名即 hash）。"""
    return os.path.join(str(tmp_output.parent / "cache"), f"result_{qh}.json")


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
    _save_result_cache(qh, result, False, False)
    loaded = _load_result_cache(qh, 0, False, False)
    assert loaded is not None
    assert loaded["results"][0]["id"] == "CVE-2024-0001"
    # 缓存文件在 cache/ 里，不在 output/ 里
    assert os.path.isfile(_cache_path(tmp_output, qh))
    assert not os.path.exists(os.path.join(str(tmp_output), "Test_Device", "_result.json"))


def test_result_cache_hash_mismatch_miss(tmp_output, make_cve):
    rec = make_cve("CVE-2024-0001", product="Test Device")
    result = {"found": True, "firmware": "Test Device", "results": [rec]}
    _save_result_cache(_query_hash("A", False, False), result, False, False)
    # 不同 hash → 不同缓存文件 → 未命中
    assert _load_result_cache(_query_hash("B", False, False), 0, False, False) is None


def test_result_cache_topn_truncate(tmp_output, make_cve):
    recs = [make_cve("CVE-2024-0001", product="Test Device"), make_cve("CVE-2024-0002", product="Test Device")]
    result = {"found": True, "firmware": "Test Device", "results": recs}
    qh = _query_hash("Test Device", False, False)
    _save_result_cache(qh, result, False, False)
    loaded = _load_result_cache(qh, 1, False, False)
    assert loaded is not None
    assert len(loaded["results"]) == 1


# ---------- 缓存完整性（防投毒）----------

def test_result_cache_rejects_foreign_source(tmp_output, make_cve):
    """结果缓存必须带 _src 标记；外来无标记文件视为不可信 → miss。"""
    rec = make_cve("CVE-2024-0001", product="Test Device")
    result = {"found": True, "firmware": "Test Device", "results": [rec]}
    qh = _query_hash("Test Device", False, False)
    _save_result_cache(qh, result, False, False)
    path = _cache_path(tmp_output, qh)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data.pop("_src", None)     # 模拟外来/旧格式文件
    data.pop("_mac", None)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    assert _load_result_cache(qh, 0, False, False) is None


def test_result_cache_mac_detects_content_tamper(tmp_output, make_cve, monkeypatch):
    """设置 CACHE_MAC_KEY 后，改动缓存内容 → HMAC 校验失败 → miss。"""
    import cache as cache_mod
    monkeypatch.setattr(cache_mod, "_MAC_KEY", "testkey")
    rec = make_cve("CVE-2024-0001", product="Test Device")
    result = {"found": True, "firmware": "Test Device", "results": [rec]}
    qh = _query_hash("Test Device", False, False)
    _save_result_cache(qh, result, False, False)
    path = _cache_path(tmp_output, qh)
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    data["results"][0]["id"] = "CVE-9999-9999"   # 篡改内容
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)
    assert _load_result_cache(qh, 0, False, False) is None


def test_cached_request_rejects_foreign(monkeypatch, tmp_path):
    """API 缓存（CachedRequest）：外来无 _src 标记的文件 → miss。"""
    import cache as cache_mod
    monkeypatch.setattr(cache_mod, "CACHE_DIR", str(tmp_path))
    c = cache_mod.CachedRequest(ttl_days=7)
    key = hashlib.sha1(b"http://evil").hexdigest()
    with open(tmp_path / f"{key}.json", "w", encoding="utf-8") as f:
        json.dump({"_ts": 99999999999, "data": {"x": 1}}, f)
    assert c.get("http://evil") is None


def test_cached_request_mac_detects_tamper(monkeypatch, tmp_path):
    """API 缓存：设置 CACHE_MAC_KEY 后，篡改缓存内容 → miss。"""
    import glob
    import cache as cache_mod
    monkeypatch.setattr(cache_mod, "CACHE_DIR", str(tmp_path))
    monkeypatch.setattr(cache_mod, "_MAC_KEY", "k")
    c = cache_mod.CachedRequest(ttl_days=7)
    c.put("http://x", {"a": 1})
    assert c.get("http://x") == {"a": 1}
    fp = glob.glob(str(tmp_path / "*.json"))[0]
    with open(fp, encoding="utf-8") as f:
        data = json.load(f)
    data["data"] = {"evil": True}
    with open(fp, "w", encoding="utf-8") as f:
        json.dump(data, f)
    assert c.get("http://x") is None
