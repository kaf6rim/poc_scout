# poc_scout —— IoT 固件 CVE 检索 + POC 下载工具

agent 剥离出固件漏洞 → 调用本工具 → 找该固件的相关漏洞 → 返回编号+网址+POC。

核心不用大模型，纯 API + 规则。

> 数据源说明（2026-08 侦查结论）：
> 
> - CVE.org 公开 API `/api/cve` 搜索要 CNA 级鉴权（ORG+USER+KEY），拿不到；
> - 但 cve.org 网站搜索走自己的**免鉴权端点** `POST https://www.cve.org/restapiv1/search`
>   （body: `{"query":..., "from":0, "size":N, "sort":{...}}`，返回完整 CVE 记录，reference 带
>   `exploit`/`x_refsource_EXPLOIT-DB` 等 tag）。主源用它。
> - 它非公开端点有被锁风险 → **NVD API 兜底**（`SEARCH_PROVIDERS` 环境变量可调顺序）。
>   单条记录链接输出 cve.org/nvd 官方页。

## 目录

- `cve_search.py` — 搜索模块：型号归一化 + 双 provider 粗筛（cve.org restapiv1 主 / NVD 兜底）+ 本地 token 精确过滤 + 打分（含 CPE 命中信号）
- `server.py` — MCP server 入口（stdio transport，官方 mcp SDK）
- `cache.py` — 本地 hash 缓存
- `config.py` — 配置

## 用法

```bash
# 命令行直接测
.venv\Scripts\python.exe cve_search.py "D-Link DIR-850L"

# 作为 MCP server 启动
.venv\Scripts\python.exe server.py
```

## 已实现

- [x] 搜索模块（固件名 → 相关 CVE 列表 + JSON 输出）
- [x] POC 链接判定（官方 tag 优先 + URL 启发式兜底）
- [x] POC 内容下载：GitHub（列树→挑代码文件→下 raw）、exploit-db（下载原始 exploit）、内容嗅探扩展名；落盘 `output/<固件>/<CVE>/poc_*`
- [x] CVE 编号清单：每个固件写 `output/<固件>/_cves.json`（全部 CVE 编号 + 分数 + POC 状态）
- [x] 代理策略 proxy.py：`PROXY_MODE = direct / fixed(FlClash) / kuaidaili(留 stub)`，`rotate_ip()` 撞 403/429/502 自动切 FlClash 节点重试
- [x] EPSS 危险评分：每个 CVE 带野外被利用概率（FIRST.org），打分加权高危排前
- [ ] Kafka 推送（后话）

## 用法

```bash
# 命令行直接测（带 POC 下载）
.venv\Scripts\python.exe cve_search.py "D-Link DIR-850L" --download

# 作为 MCP server 启动（工具参数 download_poc=True 时下载）
.venv\Scripts\python.exe server.py
```

## 目录

- 代码：`poc_scout/`（config/cache/cve_search/poc_downloader/proxy/server）
- 输出：`poc_scout/output/`（项目内，下载的 POC + 每个固件的 `_cves.json` 清单）

## 环境变量

- `PROXY_MODE`：fixed（默认，FlClash 代理池）/ direct / kuaidaili
- `PROXY_URL`：FlClash 混合端口（默认 http://127.0.0.1:7890）
- `CVE_OUTPUT_DIR`：输出目录（默认项目内 `output/`）
- `FLCLASH_CONTROLLER`：FlClash 外部控制器（默认 http://127.0.0.1:9090，rotate_ip 用）
- `GITHUB_TOKEN`：可选，配了 GitHub API 配额 60/h → 5000/h
- `NVD_API_KEY`：可选，NVD 兜底源提速
- `SEARCH_PROVIDERS`：搜索源顺序（默认 cveorg,nvd）

## 设计决策记录

见 `~/.claude/projects/C--Users-Lenovo/memory/project_iot_cve_poc_tool.md`
