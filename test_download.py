"""POC 下载逻辑测试：GitHub 下载/死链/扩展名/exploit-db，mock 网络，离线可跑。"""
import os

import poc_downloader
from poc_downloader import download_poc_for_cve, _is_poc_file, _parse_github_blob


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
    # 文件确实落盘
    base = os.path.join(tmp_output, "Test_Device", "CVE-2024-0001")
    assert os.path.isdir(base)
    assert os.listdir(base), "目录应有文件"


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
