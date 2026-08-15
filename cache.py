# cache.py —— 本地 hash 缓存（搜索响应，GET 按 URL、POST 按 URL+body）
# 安全：写缓存带 _src 来源标记 + CACHE_MAC_KEY 可选 HMAC 签名（防本地投毒/篡改）；
#      原子写（临时文件 + os.replace）防并发写损坏。
import hashlib
import hmac
import json
import os
import time

from config import CACHE_DIR

# 可选缓存完整性密钥：设置后对缓存内容做 HMAC-SHA256，防本地投毒。
# 不设置时仍做 _src 来源标记 + 损坏检测（防"放一个长得像的缓存 JSON"）。
_MAC_KEY = os.environ.get("CACHE_MAC_KEY", "")


def _mac(payload):
    if not _MAC_KEY:
        return None
    return hmac.new(_MAC_KEY.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def cache_sign(data):
    """给缓存 dict 加完整性标记：_src 恒有；设置 CACHE_MAC_KEY 时加 _mac。就地修改并返回。"""
    data["_src"] = "poc_scout"
    payload = json.dumps({k: v for k, v in data.items() if k != "_mac"},
                         sort_keys=True, ensure_ascii=False).encode("utf-8")
    mac = _mac(payload)
    if mac:
        data["_mac"] = mac
    return data


def cache_verify(data):
    """校验缓存 dict 可信：_src 必须存在；有 _mac 时校验签名。返回 bool。"""
    if not isinstance(data, dict) or data.get("_src") != "poc_scout":
        return False
    if data.get("_mac"):
        payload = json.dumps({k: v for k, v in data.items() if k != "_mac"},
                             sort_keys=True, ensure_ascii=False).encode("utf-8")
        expected = _mac(payload)
        if not expected or not hmac.compare_digest(expected, data["_mac"]):
            return False
    return True


def _atomic_write_json(path, item):
    """写 JSON 到临时文件再 os.replace 原子替换，避免并发写损坏。"""
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(item, f, ensure_ascii=False)
    os.replace(tmp, path)


class CachedRequest:
    """按 url（POST 再加 body）的 sha1 做 key，把响应 JSON 缓存到本地文件。"""

    def __init__(self, ttl_days=7):
        os.makedirs(CACHE_DIR, exist_ok=True)
        self.ttl = ttl_days * 86400

    def _key(self, url, body=None):
        raw = url if body is None else url + json.dumps(body, sort_keys=True)
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()

    def _path(self, url, body=None):
        return os.path.join(CACHE_DIR, self._key(url, body) + ".json")

    def get(self, url, body=None):
        p = self._path(url, body)
        if not os.path.exists(p):
            return None
        try:
            with open(p, "r", encoding="utf-8") as f:
                item = json.load(f)
        except (json.JSONDecodeError, OSError):
            return None
        if not cache_verify(item):
            return None
        if item.get("ts", 0) + self.ttl < time.time():
            return None
        return item.get("data")

    def put(self, url, data, body=None):
        p = self._path(url, body)
        try:
            item = cache_sign({"ts": time.time(), "data": data})
            _atomic_write_json(p, item)
        except OSError:
            pass
