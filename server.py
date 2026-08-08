# server.py —— MCP server 入口（stdio transport，官方 mcp SDK 2.x）
import json

from mcp.server import MCPServer

from cve_search import search_firmware

server = MCPServer("poc_scout", version="0.1")


@server.tool(
    description="按固件型号名检索相关漏洞并下载 POC。返回 CVE 编号、网址、POC 链接及本地下载路径。",
)
def search_cve_by_firmware(firmware_name: str, top_n: int = 0, download_poc: bool = False, community_poc: bool = False, force_refresh: bool = False, component: list[str] | str | None = None) -> str:
    """按固件型号名在 CVE 数据源上检索相关漏洞，可选下载 POC。支持固件+组件输入。

    Args:
        firmware_name: 固件型号名，如 "D-Link DIR-850L"；也支持直接传 CVE 编号
        top_n: 返回前 N 条，0 表示全部
        download_poc: 是否下载 POC 到本地 output 目录
        community_poc: 是否额外搜 GitHub 社区 POC（补官方未收录的）
        force_refresh: 是否强制绕过结果缓存重跑
        component: 固件内组件名（字符串或列表，如 "busybox"），信息增强，顺带搜组件 CVE
    """
    return json.dumps(
        search_firmware(firmware_name, top_n, download_poc, community_poc, force_refresh, component),
        ensure_ascii=False,
    )


if __name__ == "__main__":
    server.run()  # 默认 stdio transport
