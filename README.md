# poc_scout

![CI](https://github.com/kaf6rim/poc_scout/actions/workflows/test.yml/badge.svg)

**IoT 固件漏洞情报 + PoC 自动下载的 MCP 工具，供 AI agent 直接调用。**

**IoT firmware vulnerability intelligence + PoC auto-download, exposed as an MCP server for AI agents.**

---

## 是什么 / What it is

**中文**：`poc_scout` 是物联网固件漏洞情报工具，以 MCP server 形式提供服务。AI agent 把固件型号名（可附带组件名）喂给它，它返回相关 CVE 列表，按危险评分排序，并自动下载 PoC 到本地。纯 API + 规则实现，核心不依赖大模型。

**English**: `poc_scout` is an IoT firmware vulnerability intelligence tool exposed as an MCP server. Feed it a firmware model (optionally with component names), and it returns the relevant CVEs ranked by risk score, then auto-downloads PoCs to local disk. Built with pure APIs and rules — no LLM in the core.

## 快速开始 / Quick start

```bash
pip install -r requirements.txt
python server.py          # MCP server（stdio transport）
```

注册到 Claude Code / Register with Claude Code：

```bash
claude mcp add poc_scout -- python server.py
```

命令行直接测 / CLI:

```bash
python cve_search.py "D-Link DIR-850L"              # 只搜 CVE / search only
python cve_search.py "D-Link DIR-850L" --download   # 顺带下载 PoC / with PoC download
```

## MCP 工具 / MCP tool

`search_cve_by_firmware(firmware_name, top_n=0, download_poc=False, community_poc=False, force_refresh=False, component=None)`

| 参数 / Param | 说明 / Description |
|---|---|
| `firmware_name` | 固件型号名，如 `"D-Link DIR-850L"`；也支持 CVE 编号 / firmware model, e.g. `"D-Link DIR-850L"`; CVE IDs also supported |
| `component` | 固件内组件名（字符串/列表，如 `"busybox"`，可带版本 `"openssl 1.0.1f"`），信息增强；带版本时按受影响版本精化 / component names (str or list, e.g. `"busybox"`, or with version like `"openssl 1.0.1f"`); version-aware refinement when provided |
| `download_poc` | 下载 PoC 到本地 / download PoCs to `output/` |
| `community_poc` | 额外搜 GitHub 社区 PoC / also search GitHub community PoCs |
| `top_n` | 返回条数，`0` = 全部 / max results, `0` = all |
| `force_refresh` | 强制绕过结果缓存 / bypass result cache |

> **限速说明 / Rate limits**：GitHub API 未认证限速 60 次/小时。批量下载 PoC 时，可配合**轮换 IP** 或配置 **`GITHUB_TOKEN`**（配额升至 5000/h）缓解。
> *Unauthenticated GitHub API is limited to 60 req/h. For bulk PoC downloads, use **rotating IPs** or set **`GITHUB_TOKEN`** (raises the quota to 5000/h).*

## 功能 / Features

- 固件 + 组件 → 相关 CVE（cve.org 主源 + NVD 兜底 + OSV 组件漏洞）；组件带版本时按受影响版本精化 / firmware + component → CVEs (cve.org primary + NVD fallback + OSV component vulns); version-aware refinement when component includes a version
- PoC 自动下载：GitHub、exploit-db、社区 PoC 补充、死链检测 / auto PoC download: GitHub, exploit-db, community supplement, dead-link detection
- EPSS 危险评分（野外被利用概率，高危排前）/ EPSS exploit-probability scoring, high-risk first
- 并发下载 + 限速预检 / concurrent downloads + rate-limit precheck
- 结果缓存 + 下载时间戳 / result cache + download timestamps
- CVE 编号清单 `output/<固件>/_cves.json` / per-firmware CVE manifest `output/<firmware>/_cves.json`
- 鲁棒性测试（Hypothesis fuzz）/ robustness tests (Hypothesis fuzz)

## 测试 / Testing

```bash
python -m pytest            # 全部测试：fuzz + 搜索集成 + 下载 + 缓存 + 单元
python -m pytest --cov      # 带覆盖率
```

37 个用例，CI 每次 push 自动运行（见顶部徽章）。
