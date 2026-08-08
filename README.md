# poc_scout

**IoT 固件漏洞情报 + PoC 自动下载的 MCP 工具，供 AI agent 直接调用。**

*Query IoT firmware CVEs by device/component and auto-download PoCs — an MCP server for AI agents.*

## 是什么

`poc_scout` 是物联网固件漏洞情报工具，以 **MCP server** 形式提供服务。AI agent 把固件型号名（可附带组件名）喂给它，它返回相关 CVE 列表，按危险评分排序，并自动下载 PoC 到本地。

纯 API + 规则实现，核心不依赖大模型。

## 快速开始

```bash
pip install -r requirements.txt
python server.py          # 作为 MCP server（stdio transport）
```

注册到 Claude Code：

```bash
claude mcp add poc_scout -- python server.py
```

命令行直接测：

```bash
python cve_search.py "D-Link DIR-850L"              # 只搜 CVE
python cve_search.py "D-Link DIR-850L" --download   # 顺带下载 PoC
```

## MCP 工具

`search_cve_by_firmware(firmware_name, top_n=0, download_poc=False, community_poc=False, force_refresh=False, component=None)`

| 参数 | 说明 |
|---|---|
| `firmware_name` | 固件型号名，如 `"D-Link DIR-850L"`；也支持 CVE 编号 |
| `component` | 固件内组件名（字符串或列表，如 `"busybox"`），信息增强 |
| `download_poc` | 下载 PoC 到本地 `output/` |
| `community_poc` | 额外搜 GitHub 社区 PoC（补官方未收录的） |
| `top_n` | 返回条数，`0` = 全部 |
| `force_refresh` | 强制绕过结果缓存重跑 |

## 功能

- 固件 + 组件 → 相关 CVE（cve.org 主源 + NVD 兜底）
- PoC 自动下载：GitHub、exploit-db、社区 PoC 补充、死链检测
- EPSS 危险评分（野外被利用概率，高危排前）
- 并发下载 + 限速预检
- 结果缓存 + 下载时间戳
- CVE 编号清单 `output/<固件>/_cves.json`
- 鲁棒性测试（Hypothesis fuzz）

## 测试

```bash
python -m pytest test_robustness.py -v
```
