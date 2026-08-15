# poc_scout

![CI](https://github.com/kaf6rim/poc_scout/actions/workflows/test.yml/badge.svg)

**IoT firmware vulnerability intelligence, exposed as an MCP server for AI agents.**
**物联网固件漏洞情报工具，以 MCP server 形式供 AI agent 使用。**

Input a firmware model (optionally with components) → get related CVEs ranked by exploit risk, with PoCs auto-downloaded to local disk. Pure APIs and rules — no LLM in the core.

## Features

- **Firmware + component → CVEs**: cve.org primary, NVD fallback, OSV component vulns
- **Version-aware refinement**: when a component includes a version (e.g. `"openssl 1.0.1f"`), results are narrowed to the affected range
- **PoC auto-download**: GitHub, exploit-db, community supplement, dead-link detection
- **EPSS exploit-probability scoring**: high-risk CVEs rank first
- **CVSS severity** per CVE (NVD → cve.org → OSV authority order, NVD backfill when cve.org lacks metrics)
- **Concurrent downloads + rate-limit precheck**
- **Result cache + download timestamps**
- **Structured per-firmware output**: `main.json` (per-CVE info rows) + `<CVE-ID>.json` (full PoCs with base64 content) + flattened PoC files
- **Robustness tested** (Hypothesis fuzz + integration tests, CI on every push)

## Data sources

| Source | Role |
|---|---|
| cve.org (restapiv1) | primary search |
| NVD API | fallback |
| OSV (osv.dev) | component vulnerabilities, precise version ranges |
| FIRST.org EPSS | exploit-probability scoring |
| GitHub / Exploit-DB | PoC download |

## Install

```bash
pip install -r requirements.txt
```

## Usage as an MCP server

Run the stdio MCP server:

```bash
python server.py
```

Register it with your MCP client. For example, with Claude Code:

```bash
claude mcp add poc_scout -- python server.py
```

Any MCP client that supports stdio servers can connect to it.

## MCP tool

`search_cve_by_firmware(firmware_name, top_n=0, download_poc=False, community_poc=False, force_refresh=False, component=None)`

| Param | Description |
|---|---|
| `firmware_name` | firmware model, e.g. `"D-Link DIR-850L"`; CVE IDs also supported |
| `component` | component names (str or list, e.g. `"busybox"`, or with version `"openssl 1.0.1f"`); version-aware refinement |
| `download_poc` | download PoCs to `output/` |
| `community_poc` | also search GitHub community PoCs |
| `top_n` | max results, `0` = all |
| `force_refresh` | bypass result cache |

### Example output

```json
{
  "firmware": "D-Link DIR-850L",
  "components": ["busybox 1.19.4"],
  "found": true,
  "result_count": 40,
  "results": [
    {
      "cve_id": "CVE-2026-38752",
      "from": "component:busybox",
      "version_match": true,
      "severity": "HIGH",
      "severity_score": 8.8,
      "score": 0.746,
      "epss": 0.64,
      "description": "A use-after-free in the awk_sub() function..."
    }
  ]
}
```

## Output structure

Results are written under `output/<firmware>/` (one folder per firmware; a CVE-ID query uses `output/<CVE-ID>/`). The result cache lives in `cache/result_<hash>.json` — keyed by query hash, not in the output folder:

```
output/<firmware>/
├── main.json              # per-CVE info rows (all CVEs, not truncated to top_n)
├── <CVE-ID>.json          # one per CVE with PoC references: full PoC info
└── CVE-<id>_poc_<n>_<name>.<ext>   # flattened PoC files, prefixed with CVE ID
```

**`main.json`** — one row per CVE:

| Field | Meaning |
|---|---|
| `cve_id` / `cve_url` / `nvd_url` / `published` / `description` / `cwe` | CVE identity |
| `severity` / `severity_score` | CVSS, authority order NVD → cve.org → OSV (NVD backfilled when cve.org lacks metrics) |
| `extra` | site-specific fields (e.g. `provider`, `datePublic`, `vulnStatus`, `nvd_severity`) |
| `from` / `version_match` | source (`firmware` / `component:<name>`) + affected-version match |
| `score` / `match_reasons` / `epss` / `epss_percentile` | ranking info |
| `poc_count` / `poc` | PoC count; file names (`null` when none) |
| `poc_references` | summary of every PoC reference (URL, source, local file, download status) |

**`<CVE-ID>.json`** — full PoCs for that CVE: each entry has URL / source / local file / download timestamp / **base64 `content`**. Link-only entries have `content: null`; community PoCs embed content only when verified (see Security) — otherwise metadata + `verification` reason.

## CLI

```bash
python cve_search.py "D-Link DIR-850L"              # search only
python cve_search.py "D-Link DIR-850L" --download   # with PoC download
```

> **Rate limits**: Unauthenticated GitHub API is limited to 60 req/h. For bulk PoC downloads, set **`GITHUB_TOKEN`** (5000/h) or enable rotating IPs (below).

## Proxies

GitHub API is rate-limited (60/h unauthenticated, 5000/h with `GITHUB_TOKEN`); on 403/429/502 `rotate_ip()` switches the egress IP automatically. All configuration is via env vars:

| Variable | Default | Meaning |
|---|---|---|
| `PROXY_MODE` | `fixed` | `direct` / `fixed` (FlClash) / `kuaidaili` |
| `PROXY_URL` | `http://127.0.0.1:7890` | FlClash mixed port; accepts `user:pass@host:port` |
| `FLCLASH_CONTROLLER` | `http://127.0.0.1:9090` | FlClash controller (node rotation) |
| `GITHUB_TOKEN` | *(empty)* | GitHub token — 5000/h quota |
| `KUAIDAILI_ORDERID` | *(empty)* | Kuaidaili order ID (extraction API) |
| `KUAIDAILI_SECRET` | *(empty)* | Kuaidaili signature secret (IP-whitelist orders can skip) |
| `KUAIDAILI_API_URL` | `https://dps.kdlapi.com/api/getdps` | Kuaidaili extraction API |
| `KUAIDAILI_NUM` | `10` | IPs per extraction |
| `KUAIDAILI_POOL_MIN` | `3` | pool auto-refill threshold |
| `CACHE_MAC_KEY` | *(empty)* | HMAC key for cache tamper detection |
| `VERIFIED_POC_REPOS` | *(empty)* | `owner/repo` allowlist trusted for community PoC content |

Modes: `direct` (no proxy) · `fixed` (default — FlClash; switches node on rate limit) · `kuaidaili` (IP pool from extraction API; no order ID → degrades to direct). Kuaidaili tunnel-style products use `fixed` with `PROXY_URL=http://user:pass@host:port`. Run `probe_kuaidaili()` to self-check an order before trusting it.

## Security

Downloaded PoCs are code — treat them as untrusted.

- GitHub downloads are pinned to the default-branch **commit SHA** (`commit_sha` / `commit_pinned`), so later repo changes don't silently swap what you saved.
- **Community PoCs are opt-in** (`community_poc=True`) and unverified (found by keyword + stars). Content is embedded into `<CVE-ID>.json` **only when it passes a static risk scan** (`curl|sh`, `powershell -enc`, `certutil`, remote-fetch-then-`eval` …) or the repo is in `VERIFIED_POC_REPOS`; otherwise just metadata + a `verification` reason. Files are always saved to disk either way.
- Local caches are tagged `_src: poc_scout`; set `CACHE_MAC_KEY` to HMAC-sign them so tampered cache files are rejected.
- Requires `mcp>=2.0` (uses the 2.x `MCPServer` API).

## Testing

```bash
python -m pytest            # all tests: fuzz + integration + download + cache + units
python -m pytest --cov      # with coverage
```

79 tests, CI runs on every push (badge above).

## License

[GNU AGPL v3](LICENSE)

## Project layout

```
server.py            # MCP server entry
cve_search.py        # search: providers, matching, scoring, EPSS, cache
poc_downloader.py    # PoC download: GitHub / exploit-db / community
proxy.py             # proxy strategy + IP rotation
config.py            # configuration
cache.py             # local hash cache
test_*.py            # test suite
```
