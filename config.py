# config.py —— 工具配置
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------- 搜索源 ----------
# 侦查发现：cve.org 公开搜索 API /api/cve 要求 CNA 级鉴权（ORG/USER/KEY），
# 但其网站搜索走的是自己的免鉴权端点 restapiv1/search（POST JSON，完整 CVE 记录）。
# 主源用 cve.org（学长要求、第一手数据），非公开端点有被锁风险 → NVD 兜底。
SEARCH_PROVIDERS = ["cveorg", "nvd"]   # 顺序即优先级；可用: cveorg / nvd；可用环境变量 SEARCH_PROVIDERS 覆盖
CVEORG_API_URL = "https://www.cve.org/restapiv1/search"
RATE_SLEEP_CVEORG = 1.0                # cve.org 无官方限速文档，取礼貌间隔

# ---------- 兜底源：NVD ----------
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_RECORD_URL = "https://www.cve.org/CVERecord?id={cve_id}"
NVD_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
# 无 key：5 req/30s → 间隔 6s；有 key：50 req/30s → 间隔 0.6s
RATE_SLEEP = 0.6 if NVD_API_KEY else 6.0

RESULTS_PER_PAGE = 200    # NVD 单页上限 2000；cve.org size 上限同理
MAX_PAGES = 2             # 单次搜索最多翻几页（候选集上限）
HTTP_TIMEOUT = 20
USER_AGENT = "poc_scout/0.1 (IoT firmware CVE crawler; educational)"

# ---------- 目录 ----------
CACHE_DIR = os.path.join(BASE_DIR, "cache")
# 输出目录：项目文件夹内 output/，可用 CVE_OUTPUT_DIR 环境变量覆盖
OUTPUT_DIR = os.environ.get("CVE_OUTPUT_DIR", os.path.join(BASE_DIR, "output"))

# ---------- 输出 ----------
DEFAULT_TOP_N = 0            # 0 = 返回全部
DESCRIPTION_EXCERPT_LEN = 300

# ---------- GitHub 代理与鉴权 ----------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
# PROXY_MODE: direct=直连 / fixed=FlClash 固定代理（默认，用户选择用代理池）/ kuaidaili=快代理 API 代理池
PROXY_MODE = os.environ.get("PROXY_MODE", "fixed")
PROXY_URL = os.environ.get("PROXY_URL", "http://127.0.0.1:7890")  # FlClash 混合端口
FLCLASH_CONTROLLER = os.environ.get("FLCLASH_CONTROLLER", "http://127.0.0.1:9090")  # FlClash 外部控制器（自动换节点用）

# ---------- 快代理（kuaidaili）API 代理池 ----------
# 动态代理提取：dps API 拉 ip:port 列表 → 池子轮换。无 orderid 时 kuaidaili 模式优雅降级直连。
KUAIDAILI_ORDERID = os.environ.get("KUAIDAILI_ORDERID", "")     # 快代理订单号（dps 提取需要）
KUAIDAILI_SECRET = os.environ.get("KUAIDAILI_SECRET", "")       # 签名密钥（白名单 IP 订单可不填）
KUAIDAILI_API_URL = os.environ.get("KUAIDAILI_API_URL", "https://dps.kdlapi.com/api/getdps")
KUAIDAILI_NUM = int(os.environ.get("KUAIDAILI_NUM", "10"))       # 每次提取 IP 数
KUAIDAILI_POOL_MIN = int(os.environ.get("KUAIDAILI_POOL_MIN", "3"))  # 池子低于此阈值自动刷新
MAX_POC_FILES_PER_REPO = 5
MAX_POC_FILE_BYTES = 2 * 1024 * 1024
# 并发下载 worker 数：有界，尊重 GitHub 限速；配额充足时并发把网络等待并行掉
DOWNLOAD_CONCURRENCY = int(os.environ.get("DOWNLOAD_CONCURRENCY", "4"))

# 社区 POC 补充：对无官方 POC 的 CVE 搜 GitHub 仓库（仓库搜索 API 未认证 10/min）
COMMUNITY_POC_PER_CVE = int(os.environ.get("COMMUNITY_POC_PER_CVE", "3"))
GITHUB_SEARCH_SLEEP = float(os.environ.get("GITHUB_SEARCH_SLEEP", "7"))  # 搜索节流，配 token 后可调小

# 结果缓存：同一固件查过 TTL 内直接读 output/<固件>/_result.json，不重跑不重下
RESULT_CACHE_TTL = int(os.environ.get("RESULT_CACHE_TTL", "86400"))  # 默认 24h

# OSV（Google 开源组件漏洞库）：组件搜索增强，带精确版本范围
OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEMS = ["Debian", "Ubuntu", "Alpine"]   # 固件组件常用发行版生态
OSV_ENABLED = True

# 组件搜索候选上限：openssl 这种大组件候选上千，限制抓取量避免拖慢（信息增强够用即可）
COMPONENT_CANDIDATE_LIMIT = int(os.environ.get("COMPONENT_CANDIDATE_LIMIT", "50"))

# EPSS 危险评分（FIRST.org）：CVE 野外被利用概率，打分加权（可选增强，失败静默跳过）
EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_WEIGHT = 0.15          # 加到 score 上的权重
EPSS_ENABLED = True

# 环境变量覆盖 provider 顺序，如 SEARCH_PROVIDERS=nvd 或 cveorg,nvd
_env_prov = os.environ.get("SEARCH_PROVIDERS", "").strip()
if _env_prov:
    SEARCH_PROVIDERS = [p.strip() for p in _env_prov.split(",") if p.strip()]
