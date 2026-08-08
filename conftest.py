# 测试配置：Hypothesis profile
# 默认 max_examples=100；跑大样本：HYPOTHESIS_PROFILE=large pytest test_robustness.py
import os

from hypothesis import settings

settings.register_profile("default", max_examples=100)
settings.register_profile("large", max_examples=500)
settings.register_profile("xlarge", max_examples=2000)

# 显式从环境变量加载 profile（否则 hypothesis pytest 插件可能不认）
_profile = os.environ.get("HYPOTHESIS_PROFILE", "default")
if _profile in ("default", "large", "xlarge"):
    settings.load_profile(_profile)
