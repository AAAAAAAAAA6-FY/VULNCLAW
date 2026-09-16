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
from typing import Annotated, Any, Optional, List, Dict
from pydantic import Field, field_validator, model_validator
# NoDecode：禁止 pydantic-settings 在 source 层对复杂字段做 JSON 解析（否则
# DANGEROUS_ALLOW="op1,op2" 这类逗号串写法会在 validator 之前就抛 SettingsError 崩溃）。
# 解析交给下方 parse_list（同时兼容 JSON 数组与逗号串）。
from pydantic_settings import BaseSettings, SettingsConfigDict, NoDecode
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
    dangerous_allow_list: Annotated[List[str], NoDecode] = Field(default_factory=list, alias="DANGEROUS_ALLOW")

    # ========== 网络与性能 ==========
    rps: float = Field(2.0, alias="RPS")
    timeout: int = Field(30, alias="TIMEOUT")
    max_concurrent: int = Field(10, alias="MAX_CONCURRENT")
    proxy: Optional[str] = Field(None, alias="PROXY")
    proxy_list: Annotated[List[str], NoDecode] = Field(default_factory=list, alias="PROXY_LIST")
    # ===== 带外回连（OOB）声明线（2026-09-12）=====
    # 盲漏洞（盲 SSRF / 盲 RCE / 盲 XXE）的证据不在响应里，而在"目标是否回连我们"。
    # 未配置时 oob 型声明一律不探测（fail-closed：宁可漏报不误报）。
    oob_base_url: str = Field("", alias="OOB_BASE_URL")       # 注入到载荷里的回调基址
    oob_hits_file: str = Field("", alias="OOB_HITS_FILE")     # 命中通道：监听器把回调路径逐行写入
    oob_wait_seconds: float = Field(6.0, alias="OOB_WAIT_SECONDS")
    # 组件漏洞知识库（由 scripts/build_component_kb.py 用 OSV 数据生成，产物不入库）。
    # 缺失时 component 判据自动降级为内置手写签名 —— 不会因 KB 不可用而误报。
    component_kb_path: str = Field(os.path.join("thirdparty", "osv", "component_kb.json"),
                                   alias="COMPONENT_KB_PATH")
    # 外部现成知识源生成的声明签名（sqlmap 报错 / gitleaks 密钥 / Retire.js 组件）
    external_sigs_path: str = Field(os.path.join("thirdparty", "rules", "external_sigs.json"),
                                    alias="EXTERNAL_SIGS_PATH")
    max_scan_time: int = Field(3600, alias="MAX_SCAN_TIME")
    # E5.1 scope 硬约束白名单（逗号分隔：example.com 匹配自身及子域；*.*.example.com 通配；10.0.0.0/8 CIDR；精确 IP）
    allowed_scope: str = Field("", alias="ALLOWED_SCOPE")

    # ========== 供应链安全：出站白名单 + 平台级 SSRF/DNS-rebinding 防护（工作流8）==========
    # 三者默认均为 off，绝不改变现有扫描行为（内部靶场/本地 lab 靠 SSRF_ALLOW_PRIVATE 放行）。
    # EGRESS_ALLOWLIST：非空才启用出站白名单。逗号分隔 host，支持 fnmatch 通配（*.corp.internal），空值段忽略。
    egress_allowlist: str = Field("", alias="EGRESS_ALLOWLIST")
    # SSRF_GUARD：非 "1" 即关闭平台级 SSRF/DNS-rebinding 防护。"1" 时解析 host，对解析出的每个 IP 做
    # loopback/private/link-local 判定（不在 SSRF_ALLOW_PRIVATE 内即拒绝），并做首次/重解析一致性（防 DNS-rebinding）。
    ssrf_guard: str = Field("0", alias="SSRF_GUARD")
    # SSRF_ALLOW_PRIVATE：SSRF_GUARD=1 时的私网/回环放行白名单（逗号分隔 CIDR/单 IP，如 10.0.0.0/8,127.0.0.1）。
    ssrf_allow_private: str = Field("", alias="SSRF_ALLOW_PRIVATE")

    # ========== OSINT 外发合规（2026-09-08） ==========
    # 默认开启：recon 会把目标域名发往公网 OSINT 源（crt.sh / AlienVault OTX / urlscan.io）。
    # 对敏感目标可设 OSINT_DISABLE=1 关闭全部公网子域枚举，仅保留本地工具。
    osint_disable: bool = Field(False, alias="OSINT_DISABLE")

    # ========== Dashboard 安全（2026-09-08） ==========
    # 非空时 Dashboard 所有 API/WebSocket 需携带 X-Dashboard-Token / ?token= 才能访问。
    dashboard_token: str = Field("", alias="DASHBOARD_TOKEN")

    # ========== 目标请求能力探测（Target Capacity Probe） ==========
    # 扫描早期测出目标安全 QPS/并发，动态应用到爬虫/全局 HTTP/引擎全链路；
    # 探测失败自动回退静态默认值（probed=False，零风险开关）。
    enable_target_probe: bool = Field(True, alias="ENABLE_TARGET_PROBE")
    target_probe_timeout_s: int = Field(45, alias="TARGET_PROBE_TIMEOUT_S")
    target_probe_levels: Annotated[List[float], NoDecode] = Field(
        default_factory=lambda: [2, 4, 8, 16], alias="TARGET_PROBE_LEVELS"
    )
    target_probe_duration_s: float = Field(1.0, alias="TARGET_PROBE_DURATION_S")
    target_probe_burst_multiplier: float = Field(2.5, alias="TARGET_PROBE_BURST_MULTIPLIER")
    target_probe_burst_duration_s: float = Field(0.5, alias="TARGET_PROBE_BURST_DURATION_S")
    target_probe_safety_factor: float = Field(0.7, alias="TARGET_PROBE_SAFETY_FACTOR")
    target_probe_qps_cap: float = Field(50, alias="TARGET_PROBE_QPS_CAP")
    target_probe_concurrency_cap: int = Field(64, alias="TARGET_PROBE_CONCURRENCY_CAP")
    target_probe_ok_ratio: float = Field(0.95, alias="TARGET_PROBE_OK_RATIO")
    target_probe_max_body: int = Field(65536, alias="TARGET_PROBE_MAX_BODY")

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
    # 单目标 Nuclei 运行超时（秒）：SPA 大站 120s 跑不完 CVE 模板，默认放宽到 240s
    nuclei_run_timeout: int = Field(240, alias="NUCLEI_RUN_TIMEOUT")

    # ===== C 方案: 通用检测外置到 Nuclei/社区（2026-09-08）=====
    # 总开关。关闭则 _run_nuclei_community_line 不挂载，recon 保持旧行为（仅主域根单发）。
    nuclei_community_line: bool = Field(True, alias="NUCLEI_COMMUNITY_LINE")
    # 模板健康阈值：模板 yaml 计数 < 此值 → 醒目 WARNING + 整线 fail-closed（不产出、不误报）。
    nuclei_line_min_templates: int = Field(300, alias="NUCLEI_LINE_MIN_TEMPLATES")
    # 端点级覆盖预算：每轮最多对多少个存活资产/端点发 nuclei（0=仅主域根，兼容旧行为）。
    nuclei_line_endpoint_budget: int = Field(10, alias="NUCLEI_LINE_ENDPOINT_BUDGET")
    # 社区线 severity 档（默认高优两级，可控时耗；需要覆盖低危再显式放开）。
    nuclei_line_severity: str = Field("critical,high", alias="NUCLEI_LINE_SEVERITY")
    # 单端点 nuclei 超时（秒）。
    nuclei_line_timeout: int = Field(300, alias="NUCLEI_LINE_TIMEOUT")
    # 结果是否走证据增强 AI 验证（升级 prompt）。false 回退旧 4 行文本 prompt。
    nuclei_ai_evidence: bool = Field(True, alias="NUCLEI_AI_EVIDENCE")

    # ===== E 方案: 交叉验证层（开源工具对照，2026-09-08）=====
    # 总开关：对引擎候选用 Commix/Nuclei 定向模板做独立二次判定（双杀），
    # 并把结论写入 cross_tool_confirmed / cross_tool_pending 供审核门消费。
    cross_check_enabled: bool = Field(True, alias="CROSS_CHECK_ENABLED")
    # 单条 Nuclei 对照总超时（秒）；定向 tags+单 URL，通常远小于社区线全量
    cross_check_timeout: int = Field(120, alias="CROSS_CHECK_TIMEOUT")
    # 对照并发上限（Semaphore），避免验证阶段打爆 QPS
    cross_check_batch: int = Field(3, alias="CROSS_CHECK_BATCH")
    # E3 业务逻辑规则化：IDOR/竞态等无开源对照时，强制差分/双源证据，否则标记 pending
    cross_check_biz_rule: bool = Field(True, alias="CROSS_CHECK_BIZ_RULE")

    # ===== D 方案: 调度弹性护栏 + 引擎目标域硬约束 + 报告证据运营（2026-09-08）=====
    # D2: 引擎任务目标域硬约束（fail-closed）。true 时所有引擎任务 target 必须落在
    # 主扫描目标域/子域内（或命中 ALLOWED_SCOPE），外域任务在被消费前剔除，不发请求。
    engine_target_scope_enforce: bool = Field(True, alias="ENGINE_TARGET_SCOPE_ENFORCE")
    # D1: 粘滞剔除阈值——同一 (engine,target,param) 累计超时/失败达到此值即入墓碑黑名单，
    # 后续新生成的同键任务直接跳过，阻止 taskgen 每轮重复生成造成的占位死循环。
    sticky_fail_threshold: int = Field(2, alias="STICKY_FAIL_THRESHOLD")
    # D1: 孤儿协程运行时长阈值（秒）——诊断用，超过即打 WARNING 定位泄漏源。
    orphan_task_age_s: int = Field(180, alias="ORPHAN_TASK_AGE_S")
    # D3: 报告证据运营——每条 finding 附加 evidence_chain + sigma 置信度分档并参与排序。
    report_sigma_enable: bool = Field(True, alias="REPORT_SIGMA_ENABLE")

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
    remote_deep_enabled: bool = Field(True, alias="REMOTE_DEEP_ENABLED")
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

    # ========== A4.4: 任务分层模型路由（便宜粗筛 / 贵验证，复用 AI_MODE 档位 + provider_failover） ==========
    model_tier_routing: bool = Field(True, alias="MODEL_TIER_ROUTING")  # 默认关=零行为变更；开=粗筛/分类走 cheap 档，验证/计划走 expensive 档
    tier_cheap_codes: List[str] = Field(default_factory=lambda: ["1", "2"], alias="TIER_CHEAP_CODES")  # 便宜快模型码（粗筛/分类）
    tier_expensive_codes: List[str] = Field(default_factory=lambda: ["4", "5"], alias="TIER_EXPENSIVE_CODES")  # 贵模型码（验证/计划）
    ai_api_base: str = Field("https://open.bigmodel.cn/api/paas/v4/", alias="AI_API_BASE")
    ai_api_key: str = Field("", alias="AI_API_KEY")

    # ========== SP24: 通用硬编码参数 env 化（超时/重试/批大小，原散落各模块的字面量统一收口） ==========
    request_timeout: int = Field(10, alias="REQUEST_TIMEOUT")                    # 单次 HTTP 请求超时（秒，原 async_get/async_post 硬编码 10/30）
    ai_call_timeout: int = Field(300, alias="AI_CALL_TIMEOUT")                   # AI 模型调用超时（verify 档原 300）
    model_call_timeout_long: int = Field(3600, alias="MODEL_CALL_TIMEOUT_LONG")  # 长推理超时（plan/长上下文档原 3600）
    ai_delegate_timeout: int = Field(25, alias="AI_DELEGATE_TIMEOUT")            # 远程/委派分析单次超时（原 25）
    ai_router_timeout: int = Field(90, alias="AI_ROUTER_TIMEOUT")                # 分层路由/候选粗筛超时（原 90）
    ai_batch_size: int = Field(5, alias="AI_BATCH_SIZE")                         # AI 批处理大小（BatchProcessor 原 5）
    subprocess_timeout: int = Field(30, alias="SUBPROCESS_TIMEOUT")              # 外部工具子进程超时（原 30）
    chain_flush_timeout: int = Field(900, alias="CHAIN_FLUSH_TIMEOUT")           # 流式落盘最终冲刷超时（原 900）
    oob_domain_timeout: int = Field(20, alias="OOB_DOMAIN_TIMEOUT")              # OOB 域名申请超时（原 20）
    oob_poll_timeout: int = Field(10, alias="OOB_POLL_TIMEOUT")                  # OOB 轮询超时（原 10）

    # ========== 硬编码参数改为 env 读取（新增通用字段） ==========
    # 自动成长-方向2 读取端（2026-09-15）：经验账本反哺扫描主链路。
    # 默认 False：吸收端（maybe_absorb_scan）与读取端（误报抑制签名 / 历史 payload 推荐）
    # 全部保持关闭，现有扫描行为零影响；显式开启后才会查账本产生抑制/注入。
    enable_growth_feedback: bool = Field(False, alias="ENABLE_GROWTH_FEEDBACK")
    # 成长飞轮影子模式（growth/bridges，T11）：即使 enable_growth_feedback=False，
    # 也照常**计算**推荐/抑制判定，但**不应用**（不注入 payload、不拦截 finding），
    # 只累计命中率 —— 用真实流量积累"该不该翻转主开关"的数据背书，避免裸开主链路。
    # 默认开（零行为影响，纯统计）；主开关打开后统计照常，以实盘为准。
    growth_shadow_mode: bool = Field(True, alias="GROWTH_SHADOW_MODE")
    enable_waf_bypass: bool = Field(True, alias="ENABLE_WAF_BYPASS")
    agent_max_iterations: int = Field(15, alias="AGENT_MAX_ITERATIONS")
    agent_max_failures_per_param: int = Field(3, alias="AGENT_MAX_FAILURES_PER_PARAM")
    agent_consecutive_failures_threshold: int = Field(6, alias="AGENT_CONSECUTIVE_FAILURES_THRESHOLD")
    max_paths: int = Field(150, alias="MAX_PATHS")  # 默认提高到150，避免漏扫
    # ========== S1: ReActAgent 接入 V100 主链路（深挖阶段） ==========
    enable_react_dive: bool = Field(True, alias="ENABLE_REACT_DIVE")  # 默认开（深挖受预算/无AI降级保护）；--deep 或 env 显式控制
    # 验收/调试用：跳过"本地判定模糊"门槛强制深挖（默认关）。
    # 正常扫描下引擎判出高危的参数会被排除，深挖候选常为空 → agent 线零产出、零审计；
    # 需要验收 ReActAgent 链路或排查误报根因时显式开启（会产生真实 LLM 调用）。
    react_dive_force: bool = Field(False, alias="REACT_DIVE_FORCE")
    react_dive_max_params: int = Field(3, alias="REACT_DIVE_MAX_PARAMS")  # 每轮最多深挖参数数
    react_dive_max_iterations: int = Field(5, alias="REACT_DIVE_MAX_ITERATIONS")  # 每参数 ReAct 轮数
    react_dive_budget: float = Field(150.0, alias="REACT_DIVE_BUDGET")  # 每参数总预算（秒）
    # ========== T09: 通用 ReAct 工具循环 MVP（走 tool_registry 治理链路） ==========
    # 与 enable_react_dive（扫描深挖 agent）不同：本开关控制通用 think→act→observe 循环，
    # 工具经 CLITool→tool_registry.run_tool 治理执行。默认关闭 = 零行为变更。
    react_tool_loop: bool = Field(False, alias="REACT_TOOL_LOOP")
    react_tool_loop_max_steps: int = Field(6, alias="REACT_TOOL_LOOP_MAX_STEPS")  # 每轮循环硬上限（防 runaway）
    react_tool_loop_max_context_chars: int = Field(4000, alias="REACT_TOOL_LOOP_MAX_CONTEXT_CHARS")  # 上下文长度保护（防爆 token）
    # ========== P2: AgentCoordinator 多智能体协调器（strix 式 agent 树，Tier-1 确定性引擎） ==========
    agent_coordinator_enabled: bool = Field(True, alias="AGENT_COORDINATOR_ENABLED")  # 默认开：与 enable_agent_roles 协同深挖（预算软截止保护）
    # ========== DualAgent 双智能体并行（广度=主链路 scan 与 深度=AgentCoordinator 同时执行） ==========
    # 开启后 agent_coordinator 不再串行追加在 scan 之后，而是与 scan 阶段 gather 并行：
    # 副 agent 仍受 phase_timeout_agent_coordinator_s 预算软截止（到点结果照常合并），
    # 总墙钟 = max(主链路, 副通道) 而非相加。默认关闭=零行为变更。
    dual_agent_parallel: bool = Field(True, alias="DUAL_AGENT_PARALLEL")
    # ========== P5: 韧性（LLM 调用指数退避） ==========
    llm_retry_rounds: int = Field(2, alias="LLM_RETRY_ROUNDS")  # 全模型轮询外的额外重试轮数（0=单轮兼容旧行为）
    llm_backoff_base: float = Field(2.0, alias="LLM_BACKOFF_BASE")  # 退避基数秒：2s→4s→8s…（+抖动，封顶 30s）
    # ========== P3/P7: 沙箱执行层（高危动作隔离；exploit_verify 联动） ==========
    # 注：这几个字段此前从未定义，而 P3 的 sandbox_run 用 getattr 默认值读取，
    # 导致沙箱"实现存在但永远关闭"——与 agent_coordinator_enabled 同型陷阱。
    sandbox_enabled: bool = Field(True, alias="SANDBOX_ENABLED")  # 总开关（默认开：local 进程隔离沙箱，后端不可用自动降级）
    sandbox_backend: str = Field("local", alias="SANDBOX_BACKEND")  # local / docker
    sandbox_image: str = Field("alpine:latest", alias="SANDBOX_IMAGE")
    sandbox_mem_limit: str = Field("512m", alias="SANDBOX_MEM_LIMIT")
    sandbox_require_for_browser: bool = Field(True, alias="SANDBOX_REQUIRE_FOR_BROWSER")  # 浏览器 JS 确认必须隔离
    # ========== S2: 跨引擎攻击链路由（chain_router） ==========
    enable_chain_router: bool = Field(True, alias="ENABLE_CHAIN_ROUTER")  # SSRF->内网/Redis、上传->RCE
    # ========== S3: 唤醒闲置资产（VectorMemory/ClueEngine/上下文压缩） ==========
    enable_clue_engine: bool = Field(True, alias="ENABLE_CLUE_ENGINE")  # ReAct 深挖前预生成线索
    # ========== A2: 多 Agent 协作（角色化子 Agent + 共享黑板 + 竞争协作） ==========
    enable_agent_roles: bool = Field(True, alias="ENABLE_AGENT_ROLES")  # 深挖改用多 Agent 编排
    multi_agent_max_params: int = Field(1, alias="MULTI_AGENT_MAX_PARAMS")
    multi_agent_max_iterations: int = Field(4, alias="MULTI_AGENT_MAX_ITERATIONS")
    enable_agent_race: bool = Field(True, alias="ENABLE_AGENT_RACE")  # 竞争协作：取先确认者
    # ========== Z3: AI 生成式 0day（动态 PoC 生成开关） ==========
    enable_llm_poc: bool = Field(True, alias="ENABLE_LLM_POC")  # 无模板漏洞走 LLM 动态生成 PoC
    # ========== A4: 上下文管理（分层/裁剪） ==========
    context_clip_max_chars: int = Field(1500, alias="CONTEXT_CLIP_MAX_CHARS")  # 工具原始输出裁剪阈值

    # ========== Burp 配置 ==========
    burp_api_url: str = Field("http://127.0.0.1:1337", alias="BURP_API_URL")
    burp_api_key: str = Field("", alias="BURP_API_KEY")

    # ========== 工具路径 ==========
    thirdparty_dir: str = Field(str(_PKG_ROOT_DIR / "thirdparty"), alias="THIRDPARTY_DIR")
    nuclei_template_dir: str = Field(os.path.expanduser("~/nuclei-templates"), alias="NUCLEI_TEMPLATE_DIR")
    # 方案②：工具体检——缺失第三方工具启动时尽力而为自动安装（默认开，GitHub 不通静默跳过）
    tool_auto_install: bool = Field(True, alias="TOOL_AUTO_INSTALL")
    # 方案②+：下载健壮性——GitHub 直连失败时按序尝试的镜像前缀（逗号分隔，镜像 URL=前缀+原始完整 URL；空=仅直连）
    tool_download_mirrors: str = Field("https://gh-proxy.com/,https://ghproxy.net/", alias="TOOL_DOWNLOAD_MIRRORS")
    # 方案②+：单个工具下载重试轮数（每轮遍历 直连+全部镜像；连接级失败的源本进程内自动跳过）
    tool_download_retries: int = Field(3, alias="TOOL_DOWNLOAD_RETRIES")

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
    # 默认关：同目标重复扫描默认全量（防静默漏扫参数级任务）；--diff 显式开启时才走增量
    incremental_scan: bool = Field(False, alias="INCREMENTAL_SCAN")
    incremental_state_file: str = Field("", alias="INCREMENTAL_STATE_FILE")
    # A3.2: 目标画像 TTL（小时）——画像超龄视为过期，全量重扫（防陈旧指纹掩盖真实变化）
    asset_profile_ttl_hours: float = Field(168.0, alias="ASSET_PROFILE_TTL_HOURS")
    # E4: 请求复用（core/utils.get_shared_session）开关
    reuse_shared_session: bool = Field(True, alias="REUSE_SHARED_SESSION")
    # E6: 分布式分片（无 Redis 走 fakeredis 模拟）
    distributed_scan: bool = Field(False, alias="DISTRIBUTED_SCAN")

    # ========== C组 AI 架构 ==========
    # C3: 成本预算熔断（美元），超预算后自动降级为纯引擎模式（ai_mode=0）
    ai_cost_budget_usd: float = Field(0.5, alias="AI_COST_BUDGET_USD")
    ai_cost_circuit_breaker: bool = Field(True, alias="AI_COST_CIRCUIT_BREAKER")
    # A4.4: 任务分层成本路由——filter 档便宜模型先粗筛，verify 档贵模型只做真验证
    filter_first_verify: bool = Field(True, alias="FILTER_FIRST_VERIFY")
    verify_llm_call_budget: int = Field(120, alias="VERIFY_LLM_CALL_BUDGET")
    # ===== A 方案: AI 层认知升级——证据包 + 探测前置 =====
    # 关闭则回退旧行为（evidence[:200] + 无 probe 观测），零行为变化
    verify_evidence_pack: bool = Field(True, alias="VERIFY_EVIDENCE_PACK")
    verify_probe_before_ai: bool = Field(True, alias="VERIFY_PROBE_BEFORE_AI")
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
    enable_metrics: bool = Field(True, alias="ENABLE_METRICS")
    metrics_port: int = Field(9090, alias="METRICS_PORT")
    http2: bool = Field(True, alias="HTTP2")
    # ---- SP27 指令上下文（运行时注入，非 env；--instruction 解析结果，taskgen 消费）----
    instruction_context: object = None
    max_response_size_mb: int = Field(50, alias="MAX_RESPONSE_SIZE_MB")
    cache_ttl: int = Field(7200, alias="CACHE_TTL")
    cache_backend: str = Field("memory", alias="CACHE_BACKEND")
    redis_url: str = Field("redis://localhost:6379/0", alias="REDIS_URL")
    # K.2 JS 沙箱单次执行超时(s)：原硬编码 10s 在高负载（全量测试/多任务并发）下
    # 会把 node 冷启动+执行挤爆 → B 路误降级 C。加宽默认并允许 env 覆盖。
    js_sandbox_timeout: float = Field(30.0, alias="JS_SANDBOX_TIMEOUT")
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
    # ===== B 方案: 双会话差分业务逻辑 oracle（2026-09-08）=====
    # 总开关。关闭则 _scan_idor 回退旧行为（>= 2 角色才跑，无匿名兜底）。
    idor_dual_session: bool = Field(True, alias="IDOR_DUAL_SESSION")
    # 单身份时自动配对"匿名身份"（剥离 Cookie/Authorization）做差分；无真实第二账号也能验证无鉴权越权。
    idor_anon_pair: bool = Field(True, alias="IDOR_ANON_PAIR")
    # 第二账号 Cookie 文件（可选，覆盖匿名兜底）：{"target_domain": {"identity_a": {...}, "identity_b": {...}}}
    idor_role_cookies_file: str = Field("", alias="IDOR_ROLE_COOKIES_FILE")
    # victim ID 池规模（相邻/随机突变数量），直接喂给 IDOREngine._generate_id_mutations
    idor_victim_mutations: int = Field(6, alias="IDOR_VICTIM_MUTATIONS")
    # 公开资源/SPA 壳排除阈值：A/B 均为 200 且 body_sim>=阈值 且无私有标记 → 丢弃
    idor_shell_sim_threshold: float = Field(0.85, alias="IDOR_SHELL_SIM_THRESHOLD")
    # 本阶段探测预算（每个候选端点的最大请求对数量）
    idor_max_probes: int = Field(40, alias="IDOR_MAX_PROBES")
    # ===== 多步序列 / 并发竞态（2026-09-10）=====
    # ⚠️ 竞态探测会真实重复提交业务动作（重复下单/领券/扣减），存在业务副作用；
    #    默认关闭，仅在明确授权且接受副作用时开启。
    # 默认开启：已由"串行预检 + 只测可逆动作"兜底——有防重的正常系统在预检阶段即被判无竞态
    #    并完全不并发；只有疑似无防重时才并发，且只针对可逆动作（领券/加购/收藏，可撤销）。
    # ===== B2: L3 差分不变量引擎（2026-09-11）=====
    # 对动作语义端点跑绑定/金额/一次性/状态跳跃检查器（角色差分走 idor_dual_session 线）
    invariant_diff_enabled: bool = Field(True, alias="INVARIANT_DIFF_ENABLED")
    invariant_diff_max_probes: int = Field(30, alias="INVARIANT_DIFF_MAX_PROBES")

    # ===== B3: L3 剧本生成器（LLM 功能语义标注 + 差分剧本，2026-09-11）=====
    # 从首页/robots/JS 端点提取功能清单 → 领域模板生成结构化剧本 → 逐动作差分
    playbook_enabled: bool = Field(True, alias="PLAYBOOK_ENABLED")
    # 剧本生成上限（LLM 标注可能产生多个功能×端点，保守起见限额）
    playbook_max_playbooks: int = Field(10, alias="PLAYBOOK_MAX_PLAYBOOKS")
    # 单剧本执行预算（秒，所有动作差分合计）
    playbook_budget_s: int = Field(120, alias="PLAYBOOK_BUDGET_S")
    # ===== A1 符号执行复核（2026-09-11，对面落地）=====
    # B3 剧本 -> BusinessIR -> A1 确定性求解；候选默认不入报告（needs_verification）
    symbolic_enabled: bool = Field(True, alias="SYMBOLIC_ENABLED")
    # 候选自动入账开关（默认关：未经验证的推导绝不污染报告，验证层裁决后转真实）
    symbolic_auto_report: bool = Field(False, alias="SYMBOLIC_AUTO_REPORT")
    sequence_chain_enabled: bool = Field(True, alias="SEQUENCE_CHAIN_ENABLED")
    # 单个端点并发请求数（引擎内部再夹到 [2,20]）
    sequence_race_concurrency: int = Field(8, alias="SEQUENCE_RACE_CONCURRENCY")
    # 候选端点预算（写操作端点数）
    sequence_max_probes: int = Field(3, alias="SEQUENCE_MAX_PROBES")
    # 多步序列最大步数
    sequence_max_steps: int = Field(5, alias="SEQUENCE_MAX_STEPS")
    # 资金类端点（pay/transfer/withdraw/支付/转账/提现/退款…）默认排除——竞态成功即真实资金变动，
    # 仅在明确知情并接受资金损失风险时开启。
    sequence_allow_financial: bool = Field(False, alias="SEQUENCE_ALLOW_FINANCIAL")
    # 不可逆动作（order/pay/checkout/settle/buy/下单/支付/结算/购买…）默认排除。
    #    可逆动作（领券/加购/收藏/申请/兑换）即使命中也可撤销；不可逆动作命中即真实业务后果，
    #    仅在明确知情时开启（且资金类还需同时开 sequence_allow_financial）。
    sequence_allow_irreversible: bool = Field(False, alias="SEQUENCE_ALLOW_IRREVERSIBLE")
    # 端点白名单（逗号分隔的 URL 片段）。非空时**只**对这些端点做竞态探测——最安全的用法：
    # 先在靶场/预发确认端点语义，再定点跑，避免自动爬取误伤关键业务。
    sequence_endpoint_allowlist: str = Field("", alias="SEQUENCE_ENDPOINT_ALLOWLIST")
    # ===== 元orphic 不变量探针（2026-09-10）：跨业务通用的逻辑漏洞元规则 =====
    # 总开关。只读元规则（ID 越权候选）零副作用，随本开关默认开启。
    metamorphic_enabled: bool = Field(True, alias="METAMORPHIC_ENABLED")
    # 会改变业务状态的元规则（金额篡改会创建订单、重放会重复提交）需显式授权。
    metamorphic_allow_state_changing: bool = Field(False, alias="METAMORPHIC_ALLOW_STATE_CHANGING")
    # ===== 编排产线开关（2026-09-10）：把声明引擎与元orphic 探针接入 extras =====
    vulnspec_line_enabled: bool = Field(True, alias="VULNSPEC_LINE_ENABLED")
    vulnspec_max_endpoints: int = Field(10, alias="VULNSPEC_MAX_ENDPOINTS")
    metamorphic_line_enabled: bool = Field(True, alias="METAMORPHIC_LINE_ENABLED")
    metamorphic_max_endpoints: int = Field(10, alias="METAMORPHIC_MAX_ENDPOINTS")
    max_forms: int = Field(0, alias="MAX_FORMS")                           # 表单数
    max_js_endpoints: int = Field(0, alias="MAX_JS_ENDPOINTS")             # JS/API 端点数（含静态收割、迭代）
    max_api_endpoints: int = Field(0, alias="MAX_API_ENDPOINTS")           # API 端点任务数
    max_found_dirs: int = Field(0, alias="MAX_FOUND_DIRS")                 # 目录爆破结果
    max_nuclei_results: int = Field(0, alias="MAX_NUCLEI_RESULTS")         # 报告/简报保留的 nuclei 条数（0=全部）
    max_crawl_endpoints: int = Field(0, alias="MAX_CRAWL_ENDPOINTS")       # 爬虫端点喂给引擎的数量（替代原 CRAWL_ENDPOINT_CAP）
    # ---- D3.5 参数挖掘（SP14.1，A 线；探测/消费两侧各自独立开关）----
    # enable_param_mining：挖掘器本体开关（探测侧，默认关控成本）；
    # scan_param_mining：挖掘结果入任务生成（消费侧总开关，可与探测侧独立控制）。
    scan_param_mining: bool = Field(True, alias="SCAN_PARAM_MINING")
    enable_param_mining: bool = Field(True, alias="ENABLE_PARAM_MINING")
    # ---- D4.2 采集→任务实时生成（SP15.3/SP15.5，A 线；默认开，含预算软截止保护）----
    live_intake_enabled: bool = Field(True, alias="LIVE_INTAKE_ENABLED")
    live_intake_min_score: int = Field(8, alias="LIVE_INTAKE_MIN_SCORE")   # >=8 仅带参注入面放行
    live_intake_priority: int = Field(8, alias="LIVE_INTAKE_PRIORITY")
    # ---- SP16.1 RL 决策层：上下文多臂老虎机（A 线；默认开，飞轮反馈 feed 目录为空时不落盘）----
    rl_bandit_enabled: bool = Field(True, alias="RL_BANDIT_ENABLED")
    rl_bandit_influence: int = Field(2, alias="RL_BANDIT_INFLUENCE")            # 浮/降权幅度上限（试验超参）
    rl_bandit_feed_dir: str = Field("", alias="RL_BANDIT_FEED_DIR")             # 空=不落盘；JSONL 反馈飞轮目录
    # ---- SP16.2 TLS 指纹伪装（A 线；curl_cffi 可选后端，默认开，缺库自动降级 aiohttp）----
    http_impersonate: bool = Field(True, alias="HTTP_IMPERSONATE")
    http_impersonate_browser: str = Field("chrome", alias="HTTP_IMPERSONATE_BROWSER")
    # ---- SP17.3 TLS 指纹链（A 线；基于 SP16.2，把"单指纹"升级为"指纹链"；池默认非空+轮换默认开，仅 http2 编排位保持关闭）----
    # 可用的指纹轮换池（兼容 JSON 数组与逗号串，见 parse_list；默认值即出厂默认）
    http_impersonate_pool: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["chrome", "firefox", "safari"],
        alias="HTTP_IMPERSONATE_POOL",
    )
    # 轮换开关：开着时请求按池 round-robin 轮换，命中（连续成功 N 次）保持当前指纹
    http_impersonate_rotate: bool = Field(True, alias="HTTP_IMPERSONATE_ROTATE")
    # ---- SP16.3 调用链上下文（A 线；enrich_findings 入口可达性证据增强）----
    scan_callgraph: bool = Field(True, alias="SCAN_CALLGRAPH")
    # ---- SH17.1 阶段预算：per-phase wall-clock 上限（带默认值启用；单阶段超时只中断本阶段跳过继续）----
    phase_timeout_recon_s: int = Field(240, alias="PHASE_TIMEOUT_RECON_S")
    phase_timeout_taskgen_s: int = Field(60, alias="PHASE_TIMEOUT_TASKGEN_S")
    phase_timeout_scan_s: int = Field(600, alias="PHASE_TIMEOUT_SCAN_S")
    phase_timeout_chain_router_s: int = Field(90, alias="PHASE_TIMEOUT_CHAIN_ROUTER_S")
    phase_timeout_react_deep_dive_s: int = Field(180, alias="PHASE_TIMEOUT_REACT_DEEP_DIVE_S")
    # ---- attack 阶段内部预算（P0 预算口径统一：原 getattr 兜底 130s 硬编码收口为正式字段）----
    # attack_node_budget 必须小于 phase_timeout_scan_s（外层 wait_for 兜底），
    # 默认 500s：给 10 worker×多任务留足执行窗口，同时保留 100s 余量给宽限/收尾。
    attack_node_budget: float = Field(500.0, alias="ATTACK_NODE_BUDGET")
    # 超时工作量自适应：无容量探测时的单任务经验耗时(秒，含引擎执行+AI验证)，有探测RT时按真实RT缩放
    attack_per_task_s: float = Field(4.0, alias="ATTACK_PER_TASK_S")
    # SP21.2 动态补测任务（param_mining / live:*）宽限窗口（原 getattr 兜底 45s 收口为正式字段）
    attack_dynamic_grace_s: float = Field(45.0, alias="ATTACK_DYNAMIC_GRACE_S")
    phase_timeout_agent_coordinator_s: int = Field(120, alias="PHASE_TIMEOUT_AGENT_COORDINATOR_S")
    phase_timeout_extras_s: int = Field(480, alias="PHASE_TIMEOUT_EXTRAS_S")
    phase_timeout_verify_s: int = Field(120, alias="PHASE_TIMEOUT_VERIFY_S")
    phase_timeout_report_s: int = Field(60, alias="PHASE_TIMEOUT_REPORT_S")
    phase_timeout_fallback_s: int = Field(180, alias="PHASE_TIMEOUT_FALLBACK_S")

    # ---- B4 资产面枚举端（道3，2026-09-11）----
    # 总开关与预算：默认 90s 总硬超时（各面并发+独立限流+超时降级，绝不影响主流程）
    asset_surface_enabled: bool = Field(True, alias="ASSET_SURFACE_ENABLED")
    asset_surface_budget_s: int = Field(90, alias="ASSET_SURFACE_BUDGET_S")
    # 公开仓库线索开关（受 osint_disable 总闸约束；无 GitHub token 时按公共 API 限流静默降级）
    asset_surface_repos: bool = Field(True, alias="ASSET_SURFACE_REPOS")
    # 可选的 GitHub Token（授予仓库搜索一定配额；空=匿名公共搜索）
    github_token: str = Field("", alias="GITHUB_TOKEN")

    max_param_mining: int = Field(0, alias="MAX_PARAM_MINING")                   # 参数挖掘条目喂给引擎的上限（0=不限制）
    max_crawl_seed_urls: int = Field(0, alias="MAX_CRAWL_SEED_URLS")       # 迭代爬虫种子 URL
    max_crawl_batch: int = Field(0, alias="MAX_CRAWL_BATCH")               # 每轮爬虫批处理 URL
    max_crawl_rounds: int = Field(8, alias="MAX_CRAWL_ROUNDS")             # 迭代爬虫轮数（原固定 3）
    max_crawl_concurrency: int = Field(16, alias="MAX_CRAWL_CONCURRENCY")  # 爬虫并发数（同源爬虫+迭代探索器共用，默认16）
    max_iterative_urls: int = Field(0, alias="MAX_ITERATIVE_URLS")         # 迭代发现 URL 上限
    max_js_files: int = Field(0, alias="MAX_JS_FILES")                     # 深度分析的 JS 文件数
    max_intranet_addrs: int = Field(0, alias="MAX_INTRANET_ADDRS")         # SSRF 内网探测地址数
    max_upload_urls: int = Field(0, alias="MAX_UPLOAD_URLS")               # 上传产物验证 URL 数
    max_url_pool: int = Field(0, alias="MAX_URL_POOL")                     # 深挖线索 URL 池
    max_engines_per_param: int = Field(0, alias="MAX_ENGINES_PER_PARAM")   # 单参数选用的引擎数
    max_total_tasks: int = Field(300, alias="MAX_TOTAL_TASKS")              # 任务生成总上限（控制膨胀：关增量后端点级bundle爆炸；0=不限制）
    # 覆盖兜底：为参数循环未覆盖到的引擎补任务，避免尾部引擎长期 never_ran（8766 实测 67/81）。
    # 默认只补 20 个——小目标上无条件补满会让请求量翻倍，宁可少补、逐轮摊薄。
    coverage_fallback_max: int = Field(20, alias="COVERAGE_FALLBACK_MAX")     # 最多补多少引擎（0=不限）
    coverage_fallback_chunk: int = Field(4, alias="COVERAGE_FALLBACK_CHUNK")  # 每个兜底 bundle 的引擎数
    negative_endpoints: str = Field("", alias="NEGATIVE_ENDPOINTS")          # 已知负样本端点（逗号分隔，如 /safe）；命中则落库前判误报丢弃
    max_test_params_per_endpoint: int = Field(0, alias="MAX_TEST_PARAMS_PER_ENDPOINT")  # 单端点测试参数数
    max_burp_history: int = Field(0, alias="MAX_BURP_HISTORY")             # Burp 历史解析条数
    max_subdomains: int = Field(0, alias="MAX_SUBDOMAINS")                  # 子域收集上限（0=不限制）
    # 子域资产级任务（2026-09-07）：让 recon 发现的子域进入引擎任务池，弥合大站"子域零消费"漏洞
    enable_subdomain_taskgen: bool = Field(True, alias="ENABLE_SUBDOMAIN_TASKGEN")
    max_subdomain_targets: int = Field(10, alias="MAX_SUBDOMAIN_TARGETS")   # 每轮最多测多少个子域（预算分摊；0=不限制）
    # ---- AntiScan 反制判定阈值（2026-09-07 配置化；默认值=原硬编码值，行为不变）----
    anti_scan_uuid_threshold: int = Field(15, alias="ANTI_SCAN_UUID_THRESHOLD")              # 蜜罐：动态UUID数量阈值
    anti_scan_honeypot_min_text: int = Field(8000, alias="ANTI_SCAN_HONEYPOT_MIN_TEXT")      # 蜜罐：配合UUID的正文长度阈值
    anti_scan_placeholder_threshold: int = Field(10, alias="ANTI_SCAN_PLACEHOLDER_THRESHOLD")  # 蜜罐：随机占位符数量阈值
    anti_scan_fake404_min_text: int = Field(5000, alias="ANTI_SCAN_FAKE404_MIN_TEXT")        # 假404：正文长度阈值
    anti_scan_rate_limit_keywords: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["rate limit", "too many requests", "429", "slow down", "try again later"],
        alias="ANTI_SCAN_RATE_LIMIT_KEYWORDS",
    )  # 限流：响应体命中词（基线量级过滤在 AntiScanDetector.is_rate_limited 内实现）
    anti_scan_blocked_keywords: Annotated[List[str], NoDecode] = Field(
        default_factory=lambda: ["blocked", "banned", "blacklisted", "denied", "forbidden", "unauthorized"],
        alias="ANTI_SCAN_BLOCKED_KEYWORDS",
    )  # 封禁：响应体命中词
    anti_scan_backoff_base: float = Field(3.0, alias="ANTI_SCAN_BACKOFF_BASE")                # 退避：wait=min(base*2^retry, max)
    anti_scan_backoff_max: float = Field(30.0, alias="ANTI_SCAN_BACKOFF_MAX")
    anti_scan_honeypot_consecutive: int = Field(3, alias="ANTI_SCAN_HONEYPOT_CONSECUTIVE")      # 蜜罐消极区：同主机连续 N 条蜜罐/假404 后放弃其请求（大站防拖死）
    # ---- 目标反检测基线（2026-09-07 自动校准蜜罐/假404 阈值；Audible 类 SPA 大站免误判）----
    enable_anti_scan_baseline: bool = Field(True, alias="ENABLE_ANTI_SCAN_BASELINE")
    anti_scan_baseline_samples: int = Field(6, alias="ANTI_SCAN_BASELINE_SAMPLES")        # 采样页面数（含随机路径）
    anti_scan_baseline_factor: float = Field(1.5, alias="ANTI_SCAN_BASELINE_FACTOR")      # 阈值 = 峰值 x 系数（宁钝勿误）


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
            self.max_param_mining = 40
            self.max_crawl_seed_urls = 15
            self.max_crawl_batch = 30
            self.max_crawl_rounds = 3
            self.max_crawl_concurrency = 16
            self.max_iterative_urls = 100
            self.max_js_files = 5
            self.max_intranet_addrs = 3
            self.max_upload_urls = 3
            self.max_url_pool = 3
            self.max_engines_per_param = 3
            self.max_test_params_per_endpoint = 5
            self.max_burp_history = 50
            self.max_total_tasks = 200  # safe 模式更保守（控制任务膨胀）
            self.coverage_fallback_max = 8  # safe 档兜底更保守：只补最缺的少数引擎
            self.max_subdomains = 50
            self.enable_target_probe = True  # safe 档保留探测——动态测容量反而降低压力
        return self

    # 目录爆破字典（200+ 条，按 OWASP 常见路径分类）
    # 也支持通过环境变量 COMMON_DIRS="/path/to/dict.txt" 指定外部文件
    common_dirs: Annotated[List[str], NoDecode] = Field(
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
            # ===== 扩充：中间件/管控面/SSO/云原生（2026-09-13） =====
            # SSO / 身份
            "sso", "saml", "saml/login", "saml/acs", "simplesaml", "simplesamlphp",
            "adfs", "adfs/ls", "openid", ".well-known/openid-configuration",
            ".well-known/webfinger", ".well-known/security.txt",
            # CMS / 框架
            "wp-json", "wp-json/wp/v2", "wp-content", "wp-includes", "xmlrpc.php",
            "wp-trackback.php", "wp-admin/setup-config.php", "wp-admin/install.php",
            "drupal", "joomla/administrator", "moodle", "moodle/login",
            # 运维/监控管控面
            "grafana", "grafana/login", "prometheus", "prometheus/api/v1", "alertmanager",
            "kibana", "elasticsearch", "_cat", "_cluster/health", "_nodes",
            "consul", "consul/ui", "vault", "vault/ui", "etcd/v2", "etcd/v3",
            "traefik", "traefik/api", "caddy", "caddy/api", "portainer", "portainer/api",
            "minio", "minio/login", "minio/health", "nacos", "nacos/v1",
            "druid", "druid/index.html", "druid/webview", "sonarqube", "sonar", "sonar/login",
            "nexus", "nexus/#/", "artifactory", "jenkins", "jenkins/login",
            "j_acegi_security_check", "hudson", "cacti", "cacti/index.php",
            "zabbix", "zabbix/index.php", "nagios", "nagios/cgi-bin",
            "manager/html", "host-manager/html", "activemq", "activemq/web", "activemq/admin",
            "spark", "spark/master", "flink", "jolokia", "jolokia/list", "jmx", "jmxrmi",
            # K8s / 云原生
            "api/v1", "apis", "healthz", "readyz", "livez", "kube-public", "kubernetes",
            "metrics/cadvisor", ".kube/config",
            # 其他常见暴露面
            "phpinfo", "phpinfo.php", "info.php", "phpMyAdmin", "pma/index.php",
            "webmail", "roundcube", "owa", "ecp", "exchange", "rpc",
            "socket.io", "socket.io/?EIO=4",
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
    # H.3: 本地/私网目标的并发起步倍率（initial×boost，封顶 max）；
    # 外部目标不受影响。1 = 关闭动态起步（行为退回原状）。
    adaptive_concurrency_local_boost: int = Field(3, alias="ADAPTIVE_CONCURRENCY_LOCAL_BOOST")
    adaptive_concurrency_min: int = Field(1, alias="ADAPTIVE_CONCURRENCY_MIN")
    adaptive_concurrency_max: int = Field(20, alias="ADAPTIVE_CONCURRENCY_MAX")

    # ========== P3 能力开关（2026-09-15：此前消费端全靠 getattr 默认关，未声明=写了不生效）==========
    # 扫描队列背压闸门（core/backpressure.py）：pending ≥ 高水位阻塞新任务、< 低水位放行。
    backpressure_enabled: bool = Field(False, alias="BACKPRESSURE_ENABLED")
    # 多智能体辩论复核（verification_gateway.multi_agent_verify_batch）：
    # 3 视角多数票（≥2）判误报，与单模型粗筛互斥替代；不可用时自动回退粗筛。
    multi_agent_verify: bool = Field(False, alias="MULTI_AGENT_VERIFY")
    # 三层 AI 决策（ai/v100/decision_layers.py）：战略/战术层规划以 strategic_priority 注入任务生成。
    ai_three_layer: bool = Field(False, alias="AI_THREE_LAYER")
    # RL bandit 状态持久化路径（ai/v100/bandit.py）：非空才落盘（tmp+os.replace 原子写）。
    rl_bandit_state_path: str = Field("", alias="RL_BANDIT_STATE_PATH")
    # 自动成长：OSV 情报增量摄入 → 组件声明草稿台账（growth/component_osv_ingest.py）。
    enable_growth_ingest: bool = Field(False, alias="ENABLE_GROWTH_INGEST")
    # Redis 断连 fail-stop（distributed/redis_backend，P0-8）：开启后 Redis 不可用
    # 直接抛错，禁止降级到节点本地内存（默认关，保持无 Redis 单机可用性）。
    redis_fail_stop: bool = Field(False, alias="REDIS_FAIL_STOP")
    # Redis 降级 WAL（distributed/redis_backend，P0-8 补）：Redis 不可用降级到节点
    # 本地内存期间的写入追加落盘，Redis 恢复后回放，避免"降级期写入永久丢失"
    # （此前降级写入只活在本进程内存，进程一退就丢，且从不回灌 Redis）。
    # 默认开（数据正确性优先）；仅降级路径触发，Redis 正常时不产生磁盘开销。
    redis_wal_enabled: bool = Field(True, alias="REDIS_WAL_ENABLED")
    # WAL 落盘路径；留空=默认 `_runtime_cache/redis_ctx_wal.jsonl`。
    redis_wal_path: str = Field("", alias="REDIS_WAL_PATH")
    # 代码审计批准根目录（code/repo_manager 本地目录边界，P0-2）：
    # 逗号分隔的 realpath 前缀；**为空=不强制**（保持旧可用性，仅日志），
    # 生产/MCP 暴露场景务必配置，拒绝批准根之外的本地目录。
    code_audit_allowed_roots: str = Field("", alias="CODE_AUDIT_ALLOWED_ROOTS")
    # 沙箱网络命令出口防护（core/sandbox.py，P0-3）：开启后拒绝指向
    # loopback/link-local/RFC1918/ULA/云元数据 的网络命令目标，只放行授权外部目标。
    sandbox_egress_guard: bool = Field(True, alias="SANDBOX_EGRESS_GUARD")
    # 原生 YAML 模板解释器一致性审计（cve_nuclei._native_template_audit）：
    # nuclei 跑完后用纯 Python 解释器对同目标双跑单请求模板子集，按 template-id
    # 对比一致/差异（只审计不改主结果）。
    native_templates_compare: bool = Field(False, alias="NATIVE_TEMPLATES_COMPARE")
    # WAF 绕过有界预算（engines/base.try_waf_bypass，P1-15b）：
    # 单参数单轮绕过的最大请求数 / 最长墙钟秒数。绕过链是四段式
    # （签名确认→静态绕过→本地变异→AI 生成），对"一律 403"的硬拦截目标
    # 会退化为无界放大；设 0/负值=不启用绕过。AI 段额外受墙钟限制。
    waf_bypass_max_requests: int = Field(8, alias="WAF_BYPASS_MAX_REQUESTS")
    waf_bypass_max_seconds: float = Field(15.0, alias="WAF_BYPASS_MAX_SECONDS")

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

    @field_validator("proxy_list", "common_dirs", "dangerous_allow_list", "http_impersonate_pool", mode="before")
    @classmethod
    def parse_list(cls, v):
        # 兼容两种写法：JSON 数组 '["a","b"]'（旧 .env 格式）与 逗号串 'a,b'
        # （danger_guard 文档即逗号串）。NoDecode 已禁止 source 层 JSON 预解析，
        # 此处统一收口，避免两种写法任取其一导致另一种崩溃。
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            if s.startswith("["):
                try:
                    data = json.loads(s)
                except BaseException:
                    data = None
                if isinstance(data, list):
                    return [str(x).strip() for x in data if str(x).strip()]
            return [item.strip() for item in s.split(",") if item.strip()]
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
