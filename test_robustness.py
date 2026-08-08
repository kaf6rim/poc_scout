"""鲁棒性 fuzz 测试：用 Hypothesis 喂随机/畸形输入，验证不崩溃。
运行：.venv\Scripts\python.exe -m pytest test_robustness.py -v
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from hypothesis import given, strategies as st

from cve_search import (
    parse_firmware, _reject_reason, normalize_token,
    classify_reference, score_cve, build_result,
)

# ---------- 1. 输入字符串 fuzz（固件名）----------

@given(st.text())
def test_parse_firmware_never_crashes(s):
    fw = parse_firmware(s)
    assert {"input", "vendor", "model_raw", "model_clean", "model_core", "model_core_loose"} <= set(fw)


@given(st.text())
def test_reject_reason_never_crashes(s):
    r = _reject_reason(s)
    assert r is None or isinstance(r, str)


@given(st.text(max_size=100))
def test_normalize_token_never_crashes(s):
    assert isinstance(normalize_token(s), str)


# ---------- 2. reference 判定 fuzz ----------

REF_STRATEGY = st.one_of(
    st.none(),
    st.dictionaries(
        st.text(),
        st.one_of(st.text(), st.integers(), st.booleans(), st.none(), st.lists(st.text())),
    ),
)

@given(REF_STRATEGY)
def test_classify_reference_never_crashes(ref):
    r = classify_reference(ref)
    assert isinstance(r, tuple) and len(r) == 2


# ---------- 3. CVE 记录 fuzz（畸形数据）----------

def _desc_strategy():
    return st.one_of(
        st.none(),
        st.lists(st.one_of(
            st.none(),
            st.dictionaries(st.text(), st.one_of(st.text(), st.integers(), st.none())),
        )),
    )


CVE_STRATEGY = st.fixed_dictionaries({
    "id": st.text(min_size=4),
    "published": st.one_of(st.text(), st.none(), st.integers()),
    "descriptions": _desc_strategy(),
    "references": st.one_of(st.none(), st.lists(st.one_of(
        st.none(),
        st.dictionaries(st.text(), st.one_of(st.text(), st.integers(), st.booleans(), st.none(), st.lists(st.text()))),
    ))),
    "affected": st.one_of(st.none(), st.lists(
        st.dictionaries(st.text(), st.one_of(st.text(), st.integers(), st.none())),
    )),
    "weaknesses": st.one_of(st.none(), st.lists(
        st.dictionaries(st.text(), st.one_of(st.text(), st.none(), st.integers())),
    )),
})


@given(CVE_STRATEGY)
def test_score_cve_never_crashes(cve):
    fw = parse_firmware("D-Link DIR-850L")
    score_cve(cve, fw)   # 应永不抛异常


@given(CVE_STRATEGY)
def test_build_result_never_crashes(cve):
    build_result(cve)    # 应永不抛异常


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-v", "--tb=short"]))
