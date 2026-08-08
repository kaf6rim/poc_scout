# poc_scout

**IoT 固件漏洞情报 + PoC 自动下载的 MCP 工具，供 AI agent 直接调用。**

*Query IoT firmware CVEs by device/component and auto-download PoCs — an MCP server for AI agents.*

---

## 这是什么

`poc_scout` 是物联网固件漏洞情报工具，以 **MCP server** 形式提供服务。AI agent 解析固件后，把固件型号名（和组件名）喂给它，它负责：

- 在 CVE 数据源检索相关漏洞 → 返回编号、网址、描述
- 按 **EPSS 野外利用概率** 打分排序，高危漏洞排前
- **自动下载 PoC**（GitHub / exploit-db / 社区源）到本地
- 输出固件级 CVE 清单（`_cves.json`）

纯 API + 规则实现，核心不依赖大模型。

## 快速开始

### 依赖

- Python 3.10+
- `pip install -r requirements.txt`

### 作为 MCP server（推荐）

```bash
python server.py        # stdio transport
```

注册到 Claude Code：

```bash
claude mcp add poc_scout -- python server.py
```

### 命令行直接测

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
| `download_poc` | 是否下载 PoC 到本地 `output/` |
| `community_poc` | 是否额外搜 GitHub 社区 PoC（补官方未收录的） |
| `top_n` | 返回条数，`0` = 全部 |
| `force_refresh` | 是否强制绕过结果缓存重跑 |

## 功能

- [x] 固件 + 组件 → 相关 CVE（cve.org 主源 + NVD 兜底，双 provider 降级）
- [x] 型号归一化 + 双基型匹配（处理 `DIR-850L REV B` 等不规范写法）
- [x] PoC 自动下载：GitHub（列树→挑代码→下 raw）、exploit-db、社区 PoC 补充、**死链检测**
- [x] EPSS 危险评分（野外被利用概率，高危排前）
- [x] 并发下载 + 限速预检 + 代理轮换（FlClash，撞 403/429/502 自动换节点）
- [x] 结果缓存（hash 防目录名碰撞）+ 下载时间戳
- [x] CVE 编号清单 `output/<固件>/_cves.json`
- [x] 鲁棒性测试（Hypothesis fuzz）
- [ ] Kafka 推送 / MCP HTTP 部署（规划中）

## 数据源

| 源 | 用途 | 说明 |
|---|---|---|
| cve.org restapiv1 | 主搜索源 | 免鉴权端点（公开 `/api/cve` 需 CNA 级凭证，故用网站搜索端点） |
| NVD API | 兜底 | 免费，配 `NVD_API_KEY` 提速 |
| GitHub + exploit-db | PoC 下载 | 社区 PoC 搜索补充官方未收录的 |
| FIRST.org EPSS | 危险评分 | CVE 野外被利用概率 |

## 配置（环境变量）

| 变量 | 默认 | 说明 |
|---|---|---|
| `PROXY_MODE` | `fixed` | 代理模式：`fixed`(FlClash) / `direct` / `kuaidaili` |
| `PROXY_URL` | `http://127.0.0.1:7890` | FlClash 混合端口 |
| `FLCLASH_CONTROLLER` | `http://127.0.0.1:9090` | FlClash 外部控制器（自动换节点用） |
| `GITHUB_TOKEN` | — | 可选，GitHub API 配额 60/h → 5000/h |
| `SEARCH_PROVIDERS` | `cveorg,nvd` | 搜索源顺序 |
| `CVE_OUTPUT_DIR` | `output/` | 输出目录 |

## 测试

```bash
python -m pytest test_robustness.py -v                               # 默认 100 例/测试
HYPOTHESIS_PROFILE=large python -m pytest test_robustness.py         # 500 例/测试
```

## Roadmap

- **本地 CVE 库**：漏洞数据同步本地，离线查询、抗 API 限速
- **多数据源**：接入 OSV / RedHat 等免费源
- **Kafka 推送 + HTTP 部署**：结果分发到服务器，MCP transport 切 HTTP
- 固件二进制扫描交由上游 agent 解析后喂入

## License

MIT
