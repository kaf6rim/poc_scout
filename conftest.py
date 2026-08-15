# conftest.py —— 测试配置 + fixtures（mock 数据源，全程不碰网络）
import os

import pytest
from hypothesis import settings

import cve_search
import poc_downloader

# ---------- Hypothesis profile ----------
settings.register_profile("default", max_examples=100)
settings.register_profile("large", max_examples=500)
settings.register_profile("xlarge", max_examples=2000)

_profile = os.environ.get("HYPOTHESIS_PROFILE", "default")
if _profile in ("default", "large", "xlarge"):
    settings.load_profile(_profile)


# ---------- fixtures ----------

@pytest.fixture
def make_cve():
    """构造内部通用形状的 CVE 记录（score_cve/build_result 可处理）。"""
    def _make(cve_id, product="Test Device", desc=None, references=None,
              affected_versions=None, weaknesses=None, published="2024-01-01T00:00:00"):
        desc = desc or f"Vulnerability in {product} devices allows remote code execution."
        affected = [{"product": product, "vendor": ""}]
        if affected_versions:
            affected[0]["versions"] = affected_versions
        return {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": desc}],
            "references": references or [],
            "affected": affected,
            "configurations": [],
            "weaknesses": weaknesses or [],
        }
    return _make


@pytest.fixture
def fake_sources(monkeypatch):
    """mock cveorg/EPSS/OSV，返回可控记录。全部离线，不调真实 API。"""
    def _set(records=None, osv_records=None, epss=None):
        monkeypatch.setitem(
            cve_search.PROVIDERS, "cveorg",
            lambda fw, cve_id, candidate_limit=None: records or [],
        )
        monkeypatch.setattr(cve_search, "SEARCH_PROVIDERS", ["cveorg"])
        monkeypatch.setattr(cve_search, "_fetch_epss", lambda ids: epss or {})
        monkeypatch.setattr(cve_search, "_osv_search", lambda name, limit=None: osv_records or [])
    return _set


@pytest.fixture
def tmp_output(tmp_path, monkeypatch):
    """把输出目录与缓存目录指到临时目录，测试不污染真实 output/ 和 cache/。"""
    out = tmp_path / "output"
    out.mkdir()
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr(cve_search, "OUTPUT_DIR", str(out))
    monkeypatch.setattr(poc_downloader, "OUTPUT_DIR", str(out))
    monkeypatch.setattr(cve_search, "CACHE_DIR", str(cache_dir))
    return out


@pytest.fixture
def fake_github(monkeypatch):
    """mock GitHub 下载逻辑：commit SHA 解析 + 列树 + raw 内容。"""
    def _set(files, raw_map):
        monkeypatch.setattr(poc_downloader, "_repo_head_sha",
                            lambda owner, repo: "testsha123")
        monkeypatch.setattr(poc_downloader, "list_repo_files",
                            lambda owner, repo, ref=None: (files, 200))
        monkeypatch.setattr(poc_downloader, "download_raw",
                            lambda owner, repo, path, ref=None: (raw_map.get(path, b""), 200))
    return _set
