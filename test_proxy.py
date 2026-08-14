"""代理池测试：ProxyPool 轮换逻辑 + 快代理 fetch + rotate_ip 分发。mock 网络，离线可跑。"""
import hashlib

import pytest
import requests

import proxy as p
import proxy

# 每个测试前重置全局池，避免用例间共享状态
@pytest.fixture(autouse=True)
def _reset_pool(monkeypatch):
    monkeypatch.setattr(p, "_kdl_pool", None)


# ---------- ProxyPool ----------

def test_pool_refill_below_threshold(monkeypatch):
    """低于 min_pool 自动刷新；取用按 FIFO。"""
    calls = []

    def fetch():
        calls.append(1)
        return [f"1.2.3.{i}:8080" for i in range(1, 6)]

    pool = p.ProxyPool(fetch, min_pool=3)
    assert pool.get() == "1.2.3.1:8080"
    assert pool.get() == "1.2.3.2:8080"
    assert pool.get() == "1.2.3.1:8080"   # 剩 3 个 ≤ min_pool → 刷新，从头再来
    assert len(calls) >= 2


def test_pool_mark_dead_excluded():
    """死亡代理被剔除，不会再次取到。"""
    def fetch():
        return ["1.2.3.1:8080", "1.2.3.2:8080"]

    pool = p.ProxyPool(fetch, min_pool=0)
    assert pool.get() == "1.2.3.1:8080"
    pool.mark_current_dead()
    pool.refresh()
    assert pool.get() == "1.2.3.2:8080"
    pool.mark_current_dead()
    pool.refresh()
    assert not pool.available()   # 全死 → 无可用
    assert pool.get() is None


def test_pool_fetch_failure_keeps_old():
    """API 提取失败时保留旧池，不崩。"""
    def fetch():
        raise requests.ConnectionError()

    pool = p.ProxyPool(fetch, min_pool=0)
    assert pool.get() is None
    assert not pool.available()


# ---------- 快代理 fetch ----------

def test_kdl_fetch_no_orderid_empty(monkeypatch):
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "")
    assert p._kdl_fetch() == []


def test_kdl_fetch_parses_proxy_list(monkeypatch):
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "123")
    monkeypatch.setattr(p, "KUAIDAILI_SECRET", "")

    class FakeResp:
        def json(self):
            return {"code": 0, "data": {"proxy_list": ["1.2.3.4:8080", "5.6.7.8:8080"]}}

    monkeypatch.setattr(proxy.requests, "get", lambda *a, **k: FakeResp())
    assert p._kdl_fetch() == ["1.2.3.4:8080", "5.6.7.8:8080"]


def test_kdl_fetch_signature_when_secret(monkeypatch):
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "123")
    monkeypatch.setattr(p, "KUAIDAILI_SECRET", "abc")
    captured = {}

    class FakeResp:
        def json(self):
            return {"code": 0, "data": {"proxy_list": []}}

    def fake_get(url, params=None, timeout=None):
        captured["params"] = params
        return FakeResp()

    monkeypatch.setattr(proxy.requests, "get", fake_get)
    p._kdl_fetch()
    assert captured["params"]["signature"] == hashlib.md5(b"123abc").hexdigest()


def test_kdl_fetch_api_error_empty(monkeypatch):
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "123")
    monkeypatch.setattr(p, "KUAIDAILI_SECRET", "")

    class FakeResp:
        def json(self):
            return {"code": 1, "msg": "invalid orderid"}

    monkeypatch.setattr(proxy.requests, "get", lambda *a, **k: FakeResp())
    assert p._kdl_fetch() == []


# ---------- proxies_for_github / rotate_ip 分发 ----------

def test_proxies_kuaidaili_no_account_direct(monkeypatch):
    """无账号 → 池空 → 降级直连 {}（不崩）。"""
    monkeypatch.setattr(p, "PROXY_MODE", "kuaidaili")
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "")
    assert p.proxies_for_github() == {}


def test_proxies_kuaidaili_uses_pool_ip(monkeypatch):
    monkeypatch.setattr(p, "PROXY_MODE", "kuaidaili")
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "123")

    class FakeResp:
        def json(self):
            return {"code": 0, "data": {"proxy_list": ["1.2.3.4:8080"]}}

    monkeypatch.setattr(proxy.requests, "get", lambda *a, **k: FakeResp())
    proxies = p.proxies_for_github()
    assert proxies == {"http": "http://1.2.3.4:8080", "https": "http://1.2.3.4:8080"}


def test_proxies_fixed_uses_proxy_url(monkeypatch):
    monkeypatch.setattr(p, "PROXY_MODE", "fixed")
    monkeypatch.setattr(p, "PROXY_URL", "http://127.0.0.1:7890")
    assert p.proxies_for_github()["https"] == "http://127.0.0.1:7890"


def test_proxies_direct_empty(monkeypatch):
    monkeypatch.setattr(p, "PROXY_MODE", "direct")
    assert p.proxies_for_github() == {}


def test_rotate_direct_false(monkeypatch):
    monkeypatch.setattr(p, "PROXY_MODE", "direct")
    assert p.rotate_ip() is False


def test_rotate_fixed_controller_down(monkeypatch):
    monkeypatch.setattr(p, "PROXY_MODE", "fixed")
    monkeypatch.setattr(p, "PROXY_URL", "http://127.0.0.1:1")

    def boom(*a, **k):
        raise requests.ConnectionError()

    monkeypatch.setattr(proxy.requests, "get", boom)
    assert p.rotate_ip() is False   # controller 不可达 → 诚实 False


def test_rotate_kuaidaili_swaps_and_skips_dead(monkeypatch):
    monkeypatch.setattr(p, "PROXY_MODE", "kuaidaili")
    monkeypatch.setattr(p, "KUAIDAILI_ORDERID", "123")

    class FakeResp:
        def json(self):
            return {"code": 0, "data": {"proxy_list": ["1.2.3.4:8080", "5.6.7.8:8080"]}}

    monkeypatch.setattr(proxy.requests, "get", lambda *a, **k: FakeResp())
    assert p.proxies_for_github()["https"] == "http://1.2.3.4:8080"
    assert p.rotate_ip() is True     # 当前死亡 + 刷新，还有货
    assert p.proxies_for_github()["https"] == "http://5.6.7.8:8080"  # 死亡的 1.2.3.4 不再取
