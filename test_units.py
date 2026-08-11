"""纯函数单元测试：版本比较 / 范围解析 / 扩展名嗅探。"""
from cve_search import (
    _ver_key, _ver_cmp, _version_in_ranges, _parse_range_string,
)
from poc_downloader import _sniff_ext


# ---------- 版本 ----------

def test_ver_key_formats():
    assert _ver_key("1.0.1f") == (1, 0, 1)
    assert _ver_key("1:1.20.0-3") == (1, 20, 0)   # Debian epoch + revision
    assert _ver_key("v2.5") == (2, 5)
    assert _ver_key("abc") is None


def test_ver_cmp_order():
    assert _ver_cmp("1.0.1", "1.0.2") == -1
    assert _ver_cmp("1.0.2", "1.0.1") == 1
    assert _ver_cmp("1.0.1", "1.0.1") == 0
    assert _ver_cmp("1:1.20.0-3", "1.20.0") == 0   # Debian 版本可比


def test_version_in_ranges():
    assert _version_in_ranges("1.4", [("le", "1.5")]) is True
    assert _version_in_ranges("1.6", [("le", "1.5")]) is False
    assert _version_in_ranges("1.4", []) is None
    assert _version_in_ranges("1.0", [("ge", "1.0"), ("lt", "1.5")]) is True
    assert _version_in_ranges("1.4", [("ge", "1.0"), ("lt", "1.5")]) is True
    assert _version_in_ranges("1.6", [("ge", "1.0"), ("lt", "1.5")]) is False


def test_parse_range_string():
    assert _parse_range_string(">= 0.10.50, < 0.10.80") == [("ge", "0.10.50"), ("lt", "0.10.80")]
    assert _parse_range_string("<= 1.0.1f") == [("le", "1.0.1")]
    assert _parse_range_string("n/a") == []
    assert _parse_range_string("1.0", default_op="ge") == [("ge", "1.0")]
    assert _parse_range_string("1.0") == [("eq", "1.0")]


# ---------- 扩展名嗅探 ----------

def test_sniff_ext():
    assert _sniff_ext(b"require 'msf/core'") == ".rb"
    assert _sniff_ext(b"#!/usr/bin/env python\nprint('poc')") == ".py"
    assert _sniff_ext(b"import requests\nprint('x')") == ".py"
    assert _sniff_ext(b"<?php echo 'x';") == ".php"
    assert _sniff_ext(b"#!/bin/sh\necho hi") == ".sh"
    assert _sniff_ext(b"just some text") is None
