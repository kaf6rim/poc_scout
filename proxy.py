# proxy.py —— GitHub 代理策略 + 轮换 IP
# PROXY_MODE: direct=直连 / fixed=FlClash 固定代理（controller 切节点轮换）/ kuaidaili=快代理 API 代理池
# 轮换思路：撞 403/429/502 时调 rotate_ip() 换出口 IP 再重试，而不是干等。
import hashlib
import threading
import time
import urllib.parse

import requests

from config import (
    PROXY_MODE, PROXY_URL, GITHUB_TOKEN, FLCLASH_CONTROLLER,
    KUAIDAILI_ORDERID, KUAIDAILI_SECRET, KUAIDAILI_API_URL,
    KUAIDAILI_NUM, KUAIDAILI_POOL_MIN,
)

# 并发下载时多个线程可能同时触发 rotate_ip，用锁串行化，避免切节点打架
_rotate_lock = threading.Lock()


class ProxyPool:
    """通用代理池：fetch 提取 ip:port 列表，池子缓存取用，当前代理可标记死亡并刷新。
    兼容任意返回 ip:port 列表的代理 API（快代理 / 自建 / 其他），线程安全。"""

    def __init__(self, fetch, min_pool=3):
        self._fetch = fetch
        self._min_pool = min_pool
        self._pool = []
        self._dead = set()
        self._current = None
        self._lock = threading.Lock()

    def get(self):
        """取下一个代理（ip:port 字符串）；池空返回 None。低于阈值先自动刷新。"""
        with self._lock:
            if len(self._pool) <= self._min_pool:
                self._refresh()
            self._current = self._pool.pop(0) if self._pool else None
            return self._current

    def available(self):
        """池里是否还有可用代理（不消费）。"""
        with self._lock:
            if len(self._pool) <= self._min_pool:
                self._refresh()
            return bool(self._pool)

    def mark_current_dead(self):
        """把当前代理标记为死亡，避免再取到它。"""
        with self._lock:
            if self._current:
                self._dead.add(self._current)

    def refresh(self):
        """强制从 API 重新提取一批。"""
        with self._lock:
            self._refresh()

    def _refresh(self):
        try:
            fresh = self._fetch() or []
            self._pool = [p for p in fresh if p not in self._dead] or []
        except Exception:
            pass   # 提取失败保留旧池，下次再试


# ---------- 快代理（kuaidaili）代理池 ----------

_kdl_pool = None


def _kdl_pool_instance():
    global _kdl_pool
    if _kdl_pool is None:
        _kdl_pool = ProxyPool(_kdl_fetch, min_pool=KUAIDAILI_POOL_MIN)
    return _kdl_pool


def _kdl_fetch():
    """从快代理动态代理 API 提取 ip:port 列表。无 orderid → []（kuaidaili 模式降级直连）。
    快代理 dps API：GET /api/getdps?orderid=..&num=..&format=json&sep=1&signature=..
    返回 {"code":0,"data":{"proxy_list":["ip:port",...]}}。"""
    if not KUAIDAILI_ORDERID:
        return []
    params = {"orderid": KUAIDAILI_ORDERID, "num": KUAIDAILI_NUM, "format": "json", "sep": 1}
    if KUAIDAILI_SECRET:
        params["signature"] = hashlib.md5((KUAIDAILI_ORDERID + KUAIDAILI_SECRET).encode()).hexdigest()
    try:
        r = requests.get(KUAIDAILI_API_URL, params=params, timeout=10)
        data = r.json()
        if data.get("code") == 0:
            return data.get("data", {}).get("proxy_list", []) or []
    except Exception:
        pass
    return []


# ---------- 对外接口 ----------

def proxies_for_github():
    """返回 requests 用的 proxies dict（只对 GitHub 请求生效）。"""
    if PROXY_MODE == "fixed" and PROXY_URL:
        return {"http": PROXY_URL, "https": PROXY_URL}
    if PROXY_MODE == "kuaidaili":
        proxy = _kdl_pool_instance().get()
        if proxy:
            return {"http": f"http://{proxy}", "https": f"http://{proxy}"}
        return {}   # 池空/无账号：降级直连，不崩
    return {}  # direct


def github_headers():
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "poc_scout/0.1 (IoT firmware CVE crawler; educational)",
    }
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


# ---------- 轮换 IP ----------

def rotate_ip(max_attempts=10):
    """撞 403/429/502 时换出口 IP（并发安全：加锁串行化，防止并发切节点打架）。
    fixed=FlClash controller 切节点；kuaidaili=换池子下一个 IP（API 提取的 IP 天然不同）。"""
    if PROXY_MODE == "fixed":
        with _rotate_lock:
            return _rotate_ip_unlocked(max_attempts)
    if PROXY_MODE == "kuaidaili":
        with _rotate_lock:
            pool = _kdl_pool_instance()
            pool.mark_current_dead()   # 当前代理撞墙 → 死亡
            pool.refresh()             # 强制重提，跳过死亡 IP
            return pool.available()
    return False


def _egress_ip():
    """通过当前代理查出口 IP。"""
    try:
        r = requests.get("https://api.ipify.org", proxies=proxies_for_github(), timeout=10)
        return r.text.strip()
    except Exception:
        return ""


def _wait_egress_change(old_ip, tries=3):
    """切换节点后等待出口 IP 变化（代理切换有延迟），变了返回 True。"""
    for _ in range(tries):
        time.sleep(1.0)
        ip = _egress_ip()
        if ip and ip != old_ip:
            return True
    return False


def _traffic_group():
    """自动发现承载流量的组。
    规则模式 → MATCH 兜底规则指向的组；全局模式 → GLOBAL；direct → 无法轮换。"""
    try:
        cfg = requests.get(f"{FLCLASH_CONTROLLER}/configs", timeout=5).json()
        mode = cfg.get("mode", "rule")
        if mode == "global":
            return "GLOBAL"
        if mode == "direct":
            return None
        rules = requests.get(f"{FLCLASH_CONTROLLER}/rules", timeout=5).json().get("rules", [])
        for r in rules:
            if str(r.get("type", "")).lower() == "match":
                return r.get("proxy") or None
        return None
    except Exception:
        return None


def _rotate_ip_unlocked(max_attempts=10):
    """rotate_ip 的实际实现（fixed 模式，FlClash）。撞 403/429/502 时换出口 IP。
    1. 自动发现承载流量的组（规则模式=MATCH 兜底 / 全局模式=GLOBAL / 找不到就遍历所有组）
    2. 在该组内逐个切换节点
    3. 唯一硬标准：切换后验证出口 IP 真变了才返回 True（同 IP 节点会被诚实跳过）
    订阅里同 IP 节点多时可能换不成功，属数据问题，如实返回 False。"""
    if PROXY_MODE != "fixed":
        return False
    try:
        d = requests.get(f"{FLCLASH_CONTROLLER}/proxies", timeout=5).json()
        all_proxies = d.get("proxies", {})

        group = _traffic_group()
        if group:
            candidates = [group]
        else:
            # 兜底：找不到流量组就遍历所有可切组
            candidates = [n for n, p in all_proxies.items()
                          if p.get("type") in ("Selector", "URLTest", "Fallback")]

        cur_ip = _egress_ip()
        attempts = 0
        for gname in candidates:
            p = all_proxies.get(gname)
            if not p or p.get("type") not in ("Selector", "URLTest", "Fallback"):
                continue
            now = p.get("now", "")
            for target in p.get("all", []):
                if target in ("DIRECT", "REJECT") or target == now:
                    continue
                requests.put(
                    f"{FLCLASH_CONTROLLER}/proxies/{urllib.parse.quote(gname)}",
                    json={"name": target}, timeout=5,
                )
                attempts += 1
                if _wait_egress_change(cur_ip, tries=3):
                    return True
                if attempts >= max_attempts:
                    return False
        return False
    except Exception:
        return False
