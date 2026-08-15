"""server.py 冒烟测试：MCP server 可导入、工具注册正常。
防依赖区间（mcp>=2.0,<3）或 SDK API 变更导致 server 静默崩溃——此前 server 零测试覆盖。"""
import server


def test_server_imports():
    """MCPServer 实例存在（2.x 独有 API，能 import 说明依赖区间正确）。"""
    assert server.server is not None


def test_tool_registered():
    """MCP 工具函数可调用（对外唯一入口）。"""
    assert callable(server.search_cve_by_firmware)


def test_tool_rejects_empty_firmware(tmp_output):
    """直接调工具逻辑：空输入应返回 found=false 而非抛异常。"""
    import json
    out = json.loads(server.search_cve_by_firmware("   "))
    assert out["found"] is False
