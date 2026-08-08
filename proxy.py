# proxy.py —— GitHub 代理策略 + 轮换 IP
# PROXY_MODE: direct=直连 / fixed=FlClash 固定代理 / kuaidaili=快代理池(留 stub)
# 轮换思路：撞 403/429/502 时调 rotate_ip() 换出口 IP 再重试，而不是干等。
import threading
import time
import urllib.parse

import requests

from config import PROXY_MODE, PROXY_URL, GITHUB_TOKEN, FLCLASH_CONTROLLER

# 并发下载时多个线程可能同时触发 rotate_ip，用锁串行化，避免切节点打架
_rotate_lock = threading.Lock()


def proxies_for_github():
    """返回 requests 用的 proxies dict（只对 GitHub 请求生效）。"""
    if PROXY_MODE == "fixed" and PROXY_URL:
        return {"http": PROXY_URL, "https": PROXY_URL}
    if PROXY_MODE == "kuaidaili":
        # TODO: 快代理 API 提取池（等学长给账号实现）。
        # 思路：每次请求前从池子拿一个活 IP(ip:port)，失败 mark_dead 换下一个；
        # IP 活几分钟，池子低于阈值提前 refresh；吞吐上限 ≈ 池大小 × 60/h。
        raise NotImplementedError("kuaidaili 代理池待实现（需要快代理账号）")
    return {}  # direct


def github_headers():
    h = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "poc_scout/0.1 (IoT firmware CVE crawler; educational)",
    }
    if GITHUB_TOKEN:
        h["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return h


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


def rotate_ip(max_attempts=10):
    """撞 403/429/502 时换出口 IP（并发安全：加锁串行化，防止并发切节点打架）。"""
    with _rotate_lock:
        return _rotate_ip_unlocked(max_attempts)


def _rotate_ip_unlocked(max_attempts=10):
    """rotate_ip 的实际实现。撞 403/429/502 时换出口 IP（通用版，不依赖订阅特性）。
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
