# cache.py —— 本地 hash 缓存（搜索响应，GET 按 URL、POST 按 URL+body）
import hashlib
import json
import os
import time

from config import CACHE_DIR


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
        if item.get("ts", 0) + self.ttl < time.time():
            return None
        return item.get("data")

    def put(self, url, data, body=None):
        p = self._path(url, body)
        try:
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"ts": time.time(), "data": data}, f, ensure_ascii=False)
        except OSError:
            pass
