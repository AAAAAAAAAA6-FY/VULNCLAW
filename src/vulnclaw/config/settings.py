# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/settings.py
"""
统一配置管理 - 精简版
所有配置项均通过 pydantic-settings 加载，支持类型校验和默认值。
"""
import atexit
import shutil
import tempfile
from typing import Any, Optional, List, Dict
from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import json
import os
import re
from pathlib import Path

# src-layout：settings.py 位于 src/vulnclaw/core/，parents[3] 才是项目根
_PKG_ROOT_DIR = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    # ========== 基础配置 ==========
    target: str = ""
    output_dir: str = "_runtime_cache/reports"
    debug: bool = False
    compliant: bool = Field(False, alias="COMPLIANT")

    # ========== 危险操作权限模型（Danger Guard） ==========
    # deny=默认拒绝 / prompt=交互确认 / allow=放行（CLI --dangerous 或 DANGEROUS_MODE=allow）
    dangerous_mode: str = Field("deny", alias="DANGEROUS_MODE")
    # 在 deny 模式下单独放行的操作，逗号分隔（如 DANGEROUS_ALLOW="exploit_verify"）
    dangerous_allow_list: List[str] = Field(default_factory=list, alias="DANGEROUS_ALLOW")

    # ========== 网络与性能 ==========
    rps: float = Field(2.0, alias="RPS")
    timeout: int = Field(30, alias="TIMEOUT")
    max_concurrent: int = Field(10, alias="MAX_CONCURRENT")
    proxy: Optional[str] = Field(None, alias="PROXY")
    proxy_list: List[str] = Field(default_factory=list, alias="PROXY_LIST")
    max_scan_time: int = Field(3600, alias="MAX_SCAN_TIME")
    # E5.1 scope 硬约束白名单（逗号分隔：example.com 匹配自身及子域；*.*.example.com 通配；10.0.0.0/8 CIDR；精确 IP）
    allowed_scope: str = Field("", alias="ALLOWED_SCOPE")

    # ========== B 堆新增引擎开关（可选，默认启用） ==========
    password_reset: bool = Field(True, alias="PASSWORD_RESET")
    cloud_container_exposure: bool = Field(True, alias="CLOUD_CONTAINER_EXPOSURE")
    backend_component_cve: bool = Field(True, alias="BACKEND_COMPONENT_CVE")

    # ========== 请求头 ==========
    user_agent: str = Field(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        alias="USER_AGENT"
    )
    extra_headers: Dict[str, str] = Field(default_factory=dict, alias="EXTRA_HEADERS")

    # ========== AI 配置 ==========
    # 默认模型池（AI_MODELS 未配置时使用；模型名支持 1/2/4/5 别名或全名，任意数量）
    DEFAULT_AI_MODEL_CODES: List[str] = ["1", "2", "4", "5"]
    # AI 档位（AI_MODE）：0~4 五种模式
    #   0 = 纯引擎模式（不调用任何 AI）
    #   1/2/3/4 = 使用模型池中前 N 个模型
    #   未设置 = 使用 AI_MODELS 全部（默认 4 个，保持原行为）
    ai_mode: Optional[int] = Field(None, alias="AI_MODE")
    ai_provider: str = Field("zhipu", alias="AI_PROVIDER")
    ai_models: List[str] = Field(
        default_factory=lambda: ["1", "2", "4", "5"],
        alias="AI_MODELS"
    )
    ai_model_configs: Dict[str, Dict[str, str]] = Field(default_factory=dict, alias="AI_MODEL_CONFIGS")
    ai_model_aliases: Dict[str, str] = Field(
        default_factory=lambda: {
            "1": "glm-4-flash",
            "2": "qwen-plus-2025-07-28",
            "4": "deepseek-ai/DeepSeek-V3.1-Terminus",
            "5": "glm-4.7"
        },
        alias="AI_MODEL_ALIASES"
    )
    # 远程 AI Agent 接入（0~N 个，统一抽象；与本地 AI_MODELS 互补）
    # JSON 数组：[{"name":"...","type":"mcp|http|cli","url":"http://...","token":"...","tool":"analyze","model":"...","command":"..."}]
    #   type=mcp  → 平台作为 MCP 客户端连接远程 MCP Server（标准协议，推荐）
    #   type=http → 远程 Agent 的 HTTP / OpenAI 兼容 chat/completions 接口
    #   type=cli  → 外部 Agent CLI 子进程（command 含 {prompt} 占位符，或 stdin 传入）
    # 安全默认：非本机地址(非 127.0.0.1/localhost)必须带 token，否则该 Agent 被忽略；
    #            HTTPS 证书校验默认开启；每次委派有超时+熔断，失败自动回退本地逻辑。
    remote_agents: List[Dict[str, Any]] = Field(default_factory=list, alias="REMOTE_AGENTS")
    # 远程 Agent 委派超时（秒，单次调用上限 600）
    remote_agent_timeout: int = Field(60, alias="REMOTE_AGENT_TIMEOUT")
    # 任务委派路由：{"本地工具名": "远程 Agent 名"}，未指定 agent 时走首个可用 Agent
    remote_task_routing: Dict[str, str] = Field(default_factory=dict, alias="REMOTE_TASK_ROUTING")
    # 是否启用远程深度渗透（scan.deep_remote 工具）
    remote_deep_enabled: bool = Field(False, alias="REMOTE_DEEP_ENABLED")
    ai_task_allocation: Dict[str, Any] = Field(
        default_factory=lambda: {
            "verify": {
                "recommended": ["glm-4.7"],
                "fallback": ["glm-4-flash", "qwen-plus-2025-07-28"],
                "description": "漏洞验证（复杂推理，用大模型）",
            },
            "filter": {
                "recommended": ["glm-4-flash"],
                "fallback": ["qwen-plus-2025-07-28", "glm-4.7"],
                "description": "快速过滤（低延迟，用小模型）",
            },
        },
        alias="AI_TASK_ALLOCATION"
    )
    ai_timeout: int = Field(300, alias="AI_TIMEOUT")
    ai_api_base: str = Field("https://open.bigmodel.cn/api/paas/v4/", alias="AI_API_BASE")
    ai_api_key: str = Field("", alias="AI_API_KEY")

    # ========== 硬编码参数改为 env 读取（新增通用字段） ==========
    enable_waf_bypass: bool = Field(True, alias="ENABLE_WAF_BYPASS")
    agent_max_iterations: int = Field(15, alias="AGENT_MAX_ITERATIONS")
    agent_max_failures_per_param: int = Field(3, alias="AGENT_MAX_FAILURES_PER_PARAM")
    agent_consecutive_failures_threshold: int = Field(6, alias="AGENT_CONSECUTIVE_FAILURES_THRESHOLD")
    max_paths: int = Field(150, alias="MAX_PATHS")  # 默认提高到150，避免漏扫
    # ========== S1: ReActAgent 接入 V100 主链路（深挖阶段） ==========
    enable_react_dive: bool = Field(False, alias="ENABLE_REACT_DIVE")  # --deep 或 env 开启
    react_dive_max_params: int = Field(3, alias="REACT_DIVE_MAX_PARAMS")  # 每轮最多深挖参数数
    react_dive_max_iterations: int = Field(5, alias="REACT_DIVE_MAX_ITERATIONS")  # 每参数 ReAct 轮数
    react_dive_budget: float = Field(150.0, alias="REACT_DIVE_BUDGET")  # 每参数总预算（秒）
    # ========== S2: 跨引擎攻击链路由（chain_router） ==========
    enable_chain_router: bool = Field(True, alias="ENABLE_CHAIN_ROUTER")  # SSRF->内网/Redis、上传->RCE
    # ========== S3: 唤醒闲置资产（VectorMemory/ClueEngine/上下文压缩） ==========
    enable_clue_engine: bool = Field(True, alias="ENABLE_CLUE_ENGINE")  # ReAct 深挖前预生成线索
    # ========== A2: 多 Agent 协作（角色化子 Agent + 共享黑板 + 竞争协作） ==========
    enable_agent_roles: bool = Field(False, alias="ENABLE_AGENT_ROLES")  # 深挖改用多 Agent 编排
    multi_agent_max_params: int = Field(1, alias="MULTI_AGENT_MAX_PARAMS")
    multi_agent_max_iterations: int = Field(4, alias="MULTI_AGENT_MAX_ITERATIONS")
    enable_agent_race: bool = Field(False, alias="ENABLE_AGENT_RACE")  # 竞争协作：取先确认者
    # ========== A4: 上下文管理（分层/裁剪） ==========
    context_clip_max_chars: int = Field(1500, alias="CONTEXT_CLIP_MAX_CHARS")  # 工具原始输出裁剪阈值

    # ========== Burp 配置 ==========
    burp_api_url: str = Field("http://127.0.0.1:1337", alias="BURP_API_URL")
    burp_api_key: str = Field("", alias="BURP_API_KEY")

    # ========== 工具路径 ==========
    thirdparty_dir: str = Field(str(_PKG_ROOT_DIR / "thirdparty"), alias="THIRDPARTY_DIR")
    nuclei_template_dir: str = Field(os.path.expanduser("~/nuclei-templates"), alias="NUCLEI_TEMPLATE_DIR")

    # ========== P4: 外围工具集成 ==========
    # P4-1 情报补全（Shodan / Censys）
    intel_enabled: bool = Field(True, alias="INTEL_ENABLED")
    shodan_api_key: str = Field("", alias="SHODAN_API_KEY")
    censys_api_id: str = Field("", alias="CENSYS_API_ID")
    censys_api_secret: str = Field("", alias="CENSYS_API_SECRET")
    intel_timeout: int = Field(15, alias="INTEL_TIMEOUT")
    # P4-2 Metasploit RPC
    msf_rpc_host: str = Field("127.0.0.1", alias="MSF_RPC_HOST")
    msf_rpc_port: int = Field(55552, alias="MSF_RPC_PORT")
    msf_rpc_user: str = Field("msf", alias="MSF_RPC_USER")
    msf_rpc_password: str = Field("", alias="MSF_RPC_PASSWORD")
    msf_rpc_ssl: bool = Field(False, alias="MSF_RPC_SSL")
    msf_rpc_timeout: int = Field(30, alias="MSF_RPC_TIMEOUT")
    msf_auto_confirm: bool = Field(True, alias="MSF_AUTO_CONFIRM")  # 成功后自动执行 whoami/id
    # P4-3 Nuclei
    nuclei_auto_update: bool = Field(True, alias="NUCLEI_AUTO_UPDATE")
    # P4-3 原默认 True（按技术栈只跑≤6个tags，省时但实战极易扫不出漏洞）。
    # 拉满覆盖改为 False：不限制 tags，扫描 ~/nuclei-templates 全量模板库。
    # 需要提速时设 NUCLEI_TAGS_FROM_STACK=true 恢复按指纹裁剪。
    nuclei_tags_from_stack: bool = Field(False, alias="NUCLEI_TAGS_FROM_STACK")
    # P4-4 SQLMap API 守护进程
    sqlmap_api_url: str = Field("http://127.0.0.1:8775", alias="SQLMAP_API_URL")
    sqlmap_api_autostart: bool = Field(True, alias="SQLMAP_API_AUTOSTART")
    # P4-4 补充：SQLi 检出后用 sqlmap 轻量确认（POC 级，不提取数据），把引擎检出升级为实锤
    sqli_sqlmap_confirm: bool = Field(True, alias="SQLI_SQLMAP_CONFIRM")
    # 实锤后是否做最小化数据提取（仅 DBMS banner/当前库名/当前用户，不导出业务数据表）
    sqli_sqlmap_extract: bool = Field(True, alias="SQLI_SQLMAP_EXTRACT")
    # P4-5 告警卡片
    alert_card_enabled: bool = Field(True, alias="ALERT_CARD_ENABLED")
    alert_at_all_on_critical: bool = Field(True, alias="ALERT_AT_ALL_ON_CRITICAL")

    # P4-6 XSS 浏览器执行验证（headless 加载 PoC 确认真正可执行，而非仅反射判定）
    xss_browser_verify: bool = Field(True, alias="XSS_BROWSER_VERIFY")
    xss_browser_timeout: int = Field(15, alias="XSS_BROWSER_TIMEOUT")

    # ========== 性能优化 ==========
    verify_batch_ai: bool = Field(True, alias="VERIFY_BATCH_AI")  # 优化7: 同(url,param)合并 AI 判定
    sqli_fast_fail: bool = Field(True, alias="SQLI_FAST_FAIL")    # 优化3: SQLi 快失败

    # ========== E组 性能优化（增量/分档/早停/复用/分片） ==========
    # E2: Nuclei 模板分档（full=全量 / balanced=中危以上 / fast=仅高危），与 nuclei_tags_from_stack 配合提速
    nuclei_template_tier: str = Field("balanced", alias="NUCLEI_TEMPLATE_TIER")
    # E3: 单参数一旦确认高危/严重，跳过剩余低优先级引擎（早停），减少无效调用
    engine_early_stop_on_confirmed: bool = Field(True, alias="ENGINE_EARLY_STOP_ON_CONFIRMED")
    # E1: 增量扫描——基于上次状态文件跳过已扫端点/参数
    incremental_scan: bool = Field(False, alias="INCREMENTAL_SCAN")
    incremental_state_file: str = Field("", alias="INCREMENTAL_STATE_FILE")
    # E4: 请求复用（core/utils.get_shared_session）开关
    reuse_shared_session: bool = Field(True, alias="REUSE_SHARED_SESSION")
    # E6: 分布式分片（无 Redis 走 fakeredis 模拟）
    distributed_scan: bool = Field(False, alias="DISTRIBUTED_SCAN")

    # ========== C组 AI 架构 ==========
    # C3: 成本预算熔断（美元），超预算后自动降级为纯引擎模式（ai_mode=0）
    ai_cost_budget_usd: float = Field(0.5, alias="AI_COST_BUDGET_USD")
    ai_cost_circuit_breaker: bool = Field(True, alias="AI_COST_CIRCUIT_BREAKER")
    # C9: LLM-as-Judge 去重（对疑似重复 finding 用模型二次判定）
    llm_as_judge_dedup: bool = Field(True, alias="LLM_AS_JUDGE_DEDUP")
    # C10: 幻觉抑制（强制 evidence 非空且可复现，否则降级为低置信）
    hallucination_suppression: bool = Field(True, alias="HALLUCINATION_SUPPRESSION")

    # ========== G5 危险操作三级分级 ==========
    # 级别：read(只读) / write(写) / destructive(破坏性)
    # dangerous_mode=deny 时，write/destructive 默认拦截；下列开关可分别放行（需 --dangerous 配合）
    danger_level_write_allow: bool = Field(False, alias="DANGER_LEVEL_WRITE_ALLOW")
    danger_level_destructive_allow: bool = Field(False, alias="DANGER_LEVEL_DESTRUCTIVE_ALLOW")

    # ========== H组 交付 ==========
    report_sarif: bool = Field(True, alias="REPORT_SARIF")               # 输出 SARIF 文件
    report_include_poc: bool = Field(True, alias="REPORT_INCLUDE_POC")   # 高危必带可运行 PoC
    scan_diff: bool = Field(True, alias="SCAN_DIFF")                     # 两次扫描 diff/趋势
    scan_diff_baseline: str = Field("", alias="SCAN_DIFF_BASELINE")      # 基线报告 JSON 路径

    # ========== F组 覆盖增强 ==========
    graphql_max_depth: int = Field(8, alias="GRAPHQL_MAX_DEPTH")         # GraphQL 查询深度上限
    api_bola_test: bool = Field(True, alias="API_BOLA_TEST")             # BOLA/BOPLA 越权测试
    component_cve_check: bool = Field(True, alias="COMPONENT_CVE_CHECK") # 组件指纹→CVE 匹配

    # ========== D组 爬取增强 ==========
    crawl_render_spa: bool = Field(True, alias="CRAWL_RENDER_SPA")       # SPA/渲染爬取（D1 已落地）
    crawl_js_sourcemap: bool = Field(True, alias="CRAWL_JS_SOURCEMAP")   # JS sourceMap 分析
    crawl_authed: bool = Field(False, alias="CRAWL_AUTHED")              # 认证后爬取
    crawl_hash_routing: bool = Field(True, alias="CRAWL_HASH_ROUTING")   # SPA hash 路由爬取（D2）
    crawl_websocket: bool = Field(True, alias="CRAWL_WEBSOCKET")         # WebSocket 端点爬取（D2）
    tci_adaptive_planning: bool = Field(True, alias="TCI_ADAPTIVE_PLANNING")  # TCI 自适应规划总开关（E3）
    business_flow_modeling: bool = Field(True, alias="BUSINESS_FLOW_MODELING")  # 业务流建模/竞争条件总开关（B）

    # ========== 轨道2: 报告可交付化 ==========
    # 2.1: curl 复现命令是否附带会话 Cookie（默认开启以保证可复现；报告外发时可关闭）
    report_include_cookie: bool = Field(True, alias="REPORT_INCLUDE_COOKIE")

    # ========== 其他 ==========
    alert_webhook: str = Field("", alias="ALERT_WEBHOOK")
    enable_metrics: bool = Field(False, alias="ENABLE_METRICS")
    metrics_port: int = Field(0, alias="METRICS_PORT")
    http2: bool = Field(False, alias="HTTP2")
    max_response_size_mb: int = Field(50, alias="MAX_RESPONSE_SIZE_MB")
    cache_ttl: int = Field(7200, alias="CACHE_TTL")
    cache_backend: str = Field("memory", alias="CACHE_BACKEND")
    port_scan_tool: str = Field("nmap", alias="PORT_SCAN_TOOL")
    port_scan_ports: str = Field(
        "80,443,8080,8443,3000,5000,7000,8000,9000,3306,5432,6379,9200,27017",
        alias="PORT_SCAN_PORTS"
    )
    port_scan_rate: int = Field(1000, alias="PORT_SCAN_RATE")

    # ========== 扫描覆盖 / 深度（默认最强：不截断） ==========
    # scan_profile: strong（默认，最大覆盖，不截断）/ safe（保守）/ aggressive（同 strong，危险操作需另行开启）
    scan_profile: str = Field("strong", alias="SCAN_PROFILE")
    # 以下上限 0 = 不限制（最强模式）；如需保守可设具体数字（safe 档）。
    max_url_params: int = Field(0, alias="MAX_URL_PARAMS")                 # 参数级引擎测试的总参数数
    max_idor_params: int = Field(0, alias="MAX_IDOR_PARAMS")               # IDOR 测试参数数
    max_forms: int = Field(0, alias="MAX_FORMS")                           # 表单数
    max_js_endpoints: int = Field(0, alias="MAX_JS_ENDPOINTS")             # JS/API 端点数（含静态收割、迭代）
    max_api_endpoints: int = Field(0, alias="MAX_API_ENDPOINTS")           # API 端点任务数
    max_found_dirs: int = Field(0, alias="MAX_FOUND_DIRS")                 # 目录爆破结果
    max_nuclei_results: int = Field(0, alias="MAX_NUCLEI_RESULTS")         # 报告/简报保留的 nuclei 条数（0=全部）
    max_crawl_endpoints: int = Field(0, alias="MAX_CRAWL_ENDPOINTS")       # 爬虫端点喂给引擎的数量（替代原 CRAWL_ENDPOINT_CAP）
    max_crawl_seed_urls: int = Field(0, alias="MAX_CRAWL_SEED_URLS")       # 迭代爬虫种子 URL
    max_crawl_batch: int = Field(0, alias="MAX_CRAWL_BATCH")               # 每轮爬虫批处理 URL
    max_crawl_rounds: int = Field(8, alias="MAX_CRAWL_ROUNDS")             # 迭代爬虫轮数（原固定 3）
    max_iterative_urls: int = Field(0, alias="MAX_ITERATIVE_URLS")         # 迭代发现 URL 上限
    max_js_files: int = Field(0, alias="MAX_JS_FILES")                     # 深度分析的 JS 文件数
    max_intranet_addrs: int = Field(0, alias="MAX_INTRANET_ADDRS")         # SSRF 内网探测地址数
    max_upload_urls: int = Field(0, alias="MAX_UPLOAD_URLS")               # 上传产物验证 URL 数
    max_url_pool: int = Field(0, alias="MAX_URL_POOL")                     # 深挖线索 URL 池
    max_engines_per_param: int = Field(0, alias="MAX_ENGINES_PER_PARAM")   # 单参数选用的引擎数
    max_test_params_per_endpoint: int = Field(0, alias="MAX_TEST_PARAMS_PER_ENDPOINT")  # 单端点测试参数数
    max_burp_history: int = Field(0, alias="MAX_BURP_HISTORY")             # Burp 历史解析条数
    max_subdomains: int = Field(0, alias="MAX_SUBDOMAINS")                  # 子域收集上限（0=不限制）
    # Nuclei 扫描参数（原硬编码）改为可调
    nuclei_rate_limit: int = Field(5, alias="NUCLEI_RATE_LIMIT")                       # -rl
    nuclei_retries: int = Field(1, alias="NUCLEI_RETRIES")                             # -retries
    nuclei_per_host_timeout: int = Field(120, alias="NUCLEI_PER_HOST_TIMEOUT")         # -timeout

    @model_validator(mode="after")
    def _apply_profile(self):
        # scan_profile=safe 时套用保守上限；strong/aggressive 保持默认（0=不限制=最强）
        if self.scan_profile == "safe":
            self.max_url_params = 30
            self.max_idor_params = 10
            self.max_forms = 30
            self.max_js_endpoints = 100
            self.max_api_endpoints = 100
            self.max_found_dirs = 50
            self.max_nuclei_results = 50
            self.max_crawl_endpoints = 60
            self.max_crawl_seed_urls = 15
            self.max_crawl_batch = 30
            self.max_crawl_rounds = 3
            self.max_iterative_urls = 100
            self.max_js_files = 5
            self.max_intranet_addrs = 3
            self.max_upload_urls = 3
            self.max_url_pool = 3
            self.max_engines_per_param = 3
            self.max_test_params_per_endpoint = 5
            self.max_burp_history = 50
            self.max_subdomains = 50
        return self

    # 目录爆破字典（200+ 条，按 OWASP 常见路径分类）
    # 也支持通过环境变量 COMMON_DIRS="/path/to/dict.txt" 指定外部文件
    common_dirs: List[str] = Field(
        default_factory=lambda: [
            # ===== 登录/后台 =====
            "admin", "admin.php", "admin.asp", "admin.aspx", "admin/login",
            "administrator", "admin_login", "admincp", "adminpanel", "backoffice",
            "backend", "login", "login.html", "login.php", "login.aspx", "login.asp",
            "signin", "signin.html", "auth", "auth/login", "account/login",
            "user/login", "users/login", "member/login", "mod", "moderator",
            "manager", "webadmin", "wp-admin", "wp-admin/admin-ajax.php",
            "wp-login.php", "admin_console", "controlpanel", "cpanel",
            # ===== API/接口 =====
            "api", "api/v1", "api/v2", "api/v3", "api/rest", "api/graphql",
            "graphql", "graphiql", "swagger", "swagger-ui.html", "swagger.json",
            "swagger-resources", "docs", "docs/swagger", "apidoc", "api-docs",
            "openapi.json", "v1", "v2", "v3", "internal", "debug",
            # ===== 文件/目录遍历 =====
            ".env", ".env.local", ".env.prod", ".env.development", ".htaccess",
            ".htpasswd", ".git", ".git/HEAD", ".git/config", ".svn", ".hg",
            ".DS_Store", "composer.json", "composer.lock", "package.json",
            "package-lock.json", "yarn.lock", "requirements.txt", "setup.py",
            "pyproject.toml", "Gemfile", "Gemfile.lock", "go.mod", "go.sum",
            "pom.xml", "build.gradle", "Dockerfile", "docker-compose.yml",
            ".dockerignore", "Makefile", "README.md", "CHANGELOG.md",
            "robots.txt", "sitemap.xml", "crossdomain.xml", "clientaccesspolicy.xml",
            "web.config", "app.config", "config.json", "config.php",
            "configuration.php", "settings.py", "settings.php", "application.yml",
            "application.properties", "database.yml", "database.properties",
            # ===== 备份/老版本 =====
            "backup", "backup.sql", "backup.zip", "backup.tar.gz", "backup.db",
            "db.sql", "dump.sql", "database.sql", "mysql.sql", "backup.sql.gz",
            "old", "old_site", "legacy", "archive", "archives", "bak",
            "site.bak", "index.php.bak", "index.php~", "index.bak", "tmp",
            "temp", ".tmp", "tempfile", "storage", "upload_tmp",
            # ===== 上传/资源 =====
            "upload", "uploads", "uploaded", "files", "file", "media",
            "images", "img", "assets", "static", "public", "public_html",
            "html", "data", "contents", "download", "downloads", "attachments",
            # ===== 管理面板 =====
            "phpmyadmin", "phpmyadmin/index.php", "pma", "mysql", "adminer",
            "adminer.php", "dbadmin", "sqlbuddy", "mongo-express",
            "console", "manage", "management", "setup", "install",
            "install.php", "installer", "update", "upgrade", "migrate",
            # ===== 常见功能 =====
            "register", "signup", "forgot", "forgot-password", "reset",
            "search", "search.php", "contact", "contact.php", "feedback",
            "profile", "user", "users", "account", "member", "members",
            "home", "index", "main", "portal", "homepage", "news",
            "news.php", "article", "articles", "blog", "forum", "forums",
            "board", "topic", "topics", "thread", "threads",
            # ===== 目录索引/敏感文件 =====
            ".bash_history", ".ssh", ".ssh/id_rsa", ".aws", ".aws/credentials",
            "id_rsa", "id_rsa.pub", "server-status", "server-info",
            "cgi-bin", "cgi", "bin", "logs", "log", "error.log", "access.log",
            "phpinfo.php", "info.php", "test.php", "check.php", "ping.php",
            "actuator", "actuator/health", "actuator/env", "actuator/beans",
            "actuator/heapdump", "actuator/trace", "metrics", "health",
            "monitor", "monitoring", "status", "info", "trace", "heapdump",
            # ===== 扩展：目录列表 & 深层 =====
            "admin/backup", "admin/upload", "admin/config", "admin/user",
            "api/admin", "private", "protected", "restricted", "confidential",
            "dev", "develop", "development", "staging", "pre", "prod",
            "production", "uat", "qa", "test1", "test2", "demo", "stage",
            "cache", "caches", "session", "sessions", "cookie", "cookies",
            "graphql/console",
            "graphql/schema",
            "graphql/playground",
            "graphql/explorer",
            "api/v3",
            "api/v4",
            "api/v1/users",
            "api/v1/admin",
            "api/v2/auth",
            "api/internal",
            "api/private",
            "api/debug",
            "oauth2/token",
            "oauth2/authorize",
            "oauth/token",
            "oauth/authorize",
            "auth/token",
            "auth/refresh",
            "auth/oauth",
            "actuator/prometheus",
            "actuator/metrics",
            "actuator/loggers",
            "actuator/threaddump",
            "actuator/httptrace",
            "actuator/mappings",
            "swagger-ui/index.html",
            "swagger-ui.html",
            "swagger-ui/",
            "api/swagger-ui",
            "api/swagger-ui.html",
            "redoc",
            "redoc.html",
            "api/redoc",
            "openapi.json",
            "openapi.yaml",
            "openapi.yml",
            "api/openapi.json",
            "api/openapi.yaml",
            "v1/api-docs",
            "v2/api-docs",
            "v3/api-docs",
            "webpack",
            "webpack.config.js",
            "_next",
            "_next/static",
            "__next",
            "next",
            "next/static",
            "static/js",
            "static/css",
            "static/images",
            "static/assets",
            "assets/js",
            "assets/css",
            "assets/images",
            "dist",
            "dist/js",
            "dist/css",
            "build",
            "build/static",
            "public/static",
            "public/js",
            "public/css",
            ".next",
            ".nuxt",
            "nuxt",
            "nuxt/static",
            "vue",
            "react",
            "angular",
            "svelte",
            "_nuxt",
            "actuator",
            "actuator/info",
            "actuator/health",
            "actuator/env",
            "actuator/beans",
            "actuator/heapdump",
            "actuator/trace",
            "actuator/metrics",
            "actuator/loggers",
            "actuator/threaddump",
            "actuator/httptrace",
            "actuator/mappings",
            "actuator/scheduledtasks",
            "actuator/configprops",
            "actuator/conditions",
            "actuator/flyway",
            "actuator/liquibase",
            "actuator/shutdown",
            "actuator/refresh",
            "actuator/restart",
            "actuator/features",
            "actuator/pause",
            "actuator/resume",
            "admin/login",
            "admin/logout",
            "admin/password_change",
            "admin/auth",
            "admin/auth/user",
            "admin/auth/group",
            "static/admin",
            "media",
            "media/uploads",
            "media/files",
            "storage/app",
            "storage/logs",
            "storage/framework",
            "bootstrap/cache",
            "config/app.php",
            "config/database.php",
            "routes/web.php",
            "routes/api.php",
            "artisan",
            "vendor",
            "composer.lock",
            "node_modules",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "npm-debug.log",
            "yarn-error.log",
            "pm2.json",
            "ecosystem.config.js",
            "server.js",
            "app.js",
            "index.js",
            "routes",
            "controllers",
            "models",
            "middleware",
            "views",
            "public",
            "config/routes.rb",
            "config/database.yml",
            "config/secrets.yml",
            "config/credentials.yml.enc",
            "db/schema.rb",
            "db/seeds.rb",
            "Gemfile",
            "Gemfile.lock",
            "Rakefile",
            "app/controllers",
            "app/models",
            "app/views",
            "log/development.log",
            "log/production.log",
            "tmp/cache",
            "Dockerfile",
            "docker-compose.yml",
            "docker-compose.yaml",
            ".dockerignore",
            "k8s",
            "kubernetes",
            "helm",
            "charts",
            "deployment.yaml",
            "service.yaml",
            "ingress.yaml",
            "configmap.yaml",
            "secret.yaml",
            ".kube",
            ".kube/config",
            ".github",
            ".github/workflows",
            ".gitlab-ci.yml",
            ".travis.yml",
            "Jenkinsfile",
            "azure-pipelines.yml",
            "bitbucket-pipelines.yml",
            "circle.yml",
            ".circleci",
            ".circleci/config.yml",
            "vite.config.js",
            "vite.config.ts",
            "tsconfig.json",
            "jsconfig.json",
            ".babelrc",
            "babel.config.js",
            "postcss.config.js",
            "tailwind.config.js",
            "next.config.js",
            "next.config.mjs",
            "nuxt.config.js",
            "nuxt.config.ts",
            "svelte.config.js",
            "astro.config.mjs",
            "remix.config.js",
            "gatsby-config.js",
            ".eslintrc",
            ".eslintrc.js",
            ".prettierrc",
            ".prettierrc.js",
            "jest.config.js",
            "vitest.config.ts",
            "cypress.json",
            "playwright.config.ts",
        ],
        alias="COMMON_DIRS"
    )
    # 可选：外部目录字典文件路径（如果存在，会与上面的默认字典合并去重）
    directory_dict_path: Optional[str] = Field(None, alias="DIRECTORY_DICT_PATH")

    # ========== Sprint 1: Provider 故障转移 ==========
    provider_priority: List[str] = Field(
        default_factory=lambda: ["zhipu", "aliyun", "siliconflow"],
        alias="PROVIDER_PRIORITY"
    )

    # ========== Sprint 1: 插件市场 ==========
    plugin_market_repo: str = Field("vulnclaw/plugins", alias="PLUGIN_MARKET_REPO")

    # ========== Sprint 1: 自适应并发 ==========
    adaptive_concurrency_initial: int = Field(3, alias="ADAPTIVE_CONCURRENCY_INITIAL")
    adaptive_concurrency_min: int = Field(1, alias="ADAPTIVE_CONCURRENCY_MIN")
    adaptive_concurrency_max: int = Field(20, alias="ADAPTIVE_CONCURRENCY_MAX")

    # ========== Sprint 1: Slack 通知插件 ==========

    # ========== Sprint 1: Jira 集成插件 ==========

    # ========== Sprint 1: 插件目录 ==========
    PLUGIN_DIR: str = Field(str(_PKG_ROOT_DIR / "thirdparty" / "plugins"))

    @field_validator("ai_models", mode="before")
    @classmethod
    def parse_ai_models(cls, v):
        if isinstance(v, str):
            try:
                v_clean = re.sub(r',\s*\]', ']', v)
                parsed = json.loads(v_clean)
                if isinstance(parsed, list):
                    return parsed
            except BaseException:
                pass
            items = [m.strip() for m in v.split(",") if m.strip()]
            return items
        return v

    @field_validator("remote_agents", mode="before")
    @classmethod
    def parse_remote_agents(cls, v):
        if isinstance(v, str):
            v_clean = re.sub(r',\s*([}\]])', r'\1', v)
            try:
                parsed = json.loads(v_clean)
                if isinstance(parsed, list):
                    return parsed
            except BaseException:
                pass
            return []
        return v

    @field_validator("ai_model_configs", "ai_model_aliases", "ai_task_allocation", "remote_task_routing", mode="before")
    @classmethod
    def parse_json_dict(cls, v):
        if isinstance(v, str):
            v_clean = re.sub(r',\s*([}\]])', r'\1', v)
            v_clean = re.sub(r',\s*\}', '}', v_clean)
            v_clean = re.sub(r',\s*\]', ']', v_clean)
            try:
                return json.loads(v_clean)
            except json.JSONDecodeError:
                v_clean = re.sub(r',\s*,', ',', v_clean)
                v_clean = re.sub(r',\s*([}\]])', r'\1', v_clean)
                try:
                    return json.loads(v_clean)
                except BaseException:
                    return {}
        return v

    @field_validator("extra_headers", mode="before")
    @classmethod
    def parse_extra_headers(cls, v):
        if isinstance(v, str):
            v_clean = re.sub(r',\s*([}\]])', r'\1', v)
            try:
                return json.loads(v_clean)
            except BaseException:
                return {}
        return v

    @field_validator("proxy_list", "common_dirs", "dangerous_allow_list", mode="before")
    @classmethod
    def parse_list(cls, v):
        if isinstance(v, str):
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()

# ===== P3-2: 注册到 DI 容器（供测试注入 mock，避免依赖真实 .env）=====
try:
    from vulnclaw.core.container import get_container
    get_container().register("settings", settings)
except Exception:  # noqa: BLE001
    pass

# ============================================================
# ===== 运行时临时目录管理 =====
# ============================================================

_RUNTIME_TEMP = tempfile.mkdtemp(prefix="pentest_scan_")
TMP_DIR = _RUNTIME_TEMP

from vulnclaw.paths import PROJECT_ROOT as _PKG_PROJECT_ROOT  # noqa: E402
PROJECT_ROOT = str(_PKG_PROJECT_ROOT)
PROJECT_CACHE_DIR = os.path.join(PROJECT_ROOT, "_runtime_cache")
os.makedirs(PROJECT_CACHE_DIR, exist_ok=True)


def _cleanup_runtime():
    shutil.rmtree(_RUNTIME_TEMP, ignore_errors=True)


atexit.register(_cleanup_runtime)

__all__ = ['settings', 'Settings', 'TMP_DIR', 'PROJECT_CACHE_DIR']
