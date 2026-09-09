# VULNCLAW 系统架构图

> 版本基准：v103（src-layout）｜生成日期：2026-09-07
> 源码锚点：`src/vulnclaw/`（入口 `scan.py` → `src/vulnclaw/cli.py`）
> 本文件为「图集」，配套文字说明见 `system_design.md`。

---

## 图 1：总体分层架构

```mermaid
flowchart TB
    subgraph L1["① 接入层 · Interface"]
        direction LR
        A1["scan.py<br/>薄壳：sys.path 修正 + numpy 兼容桩"]
        A2["cli.py<br/>子命令分发 scan/code/health/mcp/verify/tools/archive/bandit"]
        A3["runners/*_runner.py<br/>scan_runner · code_audit_runner · health_runner · distributed_runner"]
    end

    subgraph L2["② 编排层 · Orchestration"]
        direction LR
        B1["ai/v100/orchestrator.py<br/>V100Orchestrator 主链路"]
        B2["ai/v100/phases/*<br/>recon · taskgen · executor · verify · report"]
        B3["dag/*<br/>DAGScheduler 多目标调度（--dag）"]
        B4["distributed/*<br/>Master / Worker / Redis 后端（--distributed）"]
    end

    subgraph L3["③ 能力层 · Capability"]
        direction LR
        C1["engines/*<br/>74 个确定性检测引擎"]
        C2["modules/*<br/>recon · vuln_scanner · collectors · intelligence"]
        C3["ai/*<br/>LLMClient · ModelRouter · ReActAgent · AgentCoordinator · VectorMemory"]
        C4["deepsec/*<br/>利用链 · POC · SQLMap · MSF · Shell"]
        C5["code/*<br/>代码审计 · 依赖 CVE · 调用图"]
    end

    subgraph L4["④ 治理层 · Governance（横切）"]
        direction LR
        D1["danger_guard<br/>deny/prompt/allow"]
        D2["rate_limiter · target_capacity_probe<br/>adaptive_concurrency"]
        D3["tool_registry · tool_governance<br/>tool_output_guard"]
        D4["dedupe · finding_lifecycle<br/>verification_gateway · audit_receipt"]
        D5["coverage 账本 · logger<br/>metrics · alerting"]
    end

    subgraph L5["⑤ 输出层 · Output"]
        direction LR
        E1["report_generator<br/>JSON · HTML · Markdown · SARIF · PoC"]
        E2["report_diff 基线<br/>archive 归档 · review_exporter"]
        E3["core_modules/persistence<br/>SQLite 断点续扫"]
    end

    subgraph L6["⑥ 集成层 · Integration"]
        direction LR
        F1["mcp_server<br/>15 个工具 · stdio/HTTP + Token"]
        F2["dashboard/server.py<br/>FastAPI + WebSocket /ws"]
        F3["plugin_market · plugin_integration"]
        F4["growth/*<br/>CVE 摄入 · 实战回灌"]
    end

    L1 --> L2
    L2 --> L3
    L2 --> L5
    L4 -.->|"全程拦截"| L3
    L4 -.->|"全程拦截"| L2
    L3 --> L5
    L6 --> L1
    L6 --> L2
    L5 --> F1
    L5 --> F2
```

**要点**

- 接入层刻意做薄：`scan.py` 只负责把 `src/` 顶到 `sys.path` 最前（防止陈旧 `.pth` 影子副本劫持 import）并注入 numpy 兼容桩，业务逻辑全在包内。
- 编排层是**逐层复用**而非三套平行实现：分布式 Worker 复用 `dag/executor.NODE_EXECUTORS`（`distributed/worker.py:249`），DAG 的 recon/attack 节点复用 `V100Orchestrator` 的阶段方法（`_recon` / `_generate_tasks` / `_execute_with_limiting`，`dag/executor.py:192-397`）。差异只在「谁驱动阶段顺序」。
- 治理层是**横切而非纵向**——限流、危险门卫、去重、审计账本在每一层都通过钩子介入。

---

## 图 2：主链路阶段编排（V100Orchestrator）

源码：`ai/v100/orchestrator.py` 的 `scan()`（约 L1617–L1722），阶段方法由 `ai/v100/phases/__init__.py::bind_phase_methods` 以 `MethodType` 动态绑定。

```mermaid
flowchart TB
    S0(["入口 run_v100_scan"]) --> S1

    subgraph P["阶段管道（每阶段可独立超时 _run_phase_timeboxed）"]
        direction TB
        S1["① recon<br/>侦察：子域/存活/端口/JS/爬虫/参数挖掘"]
        S2["② taskgen<br/>任务生成：端点×参数×引擎 组合成任务"]
        S3["③ scan<br/>引擎执行：SmartTaskQueue 多 worker"]
        S4["④ chain_router<br/>跨引擎攻击链路由 SSRF/LFI→RCE"]
        S5["⑤ react_deep_dive<br/>ReAct 单点深挖（--deep）"]
        S6["⑥ agent_coordinator<br/>多智能体树（--agent-coordinator）"]
        S7["⑦ extras<br/>补充分支：业务逻辑/越权/越权链"]
        S8["⑧ verify<br/>AI 审讯 + 交叉验证 + 幻觉抑制"]
        S9["⑨ report<br/>报告生成 + 落盘"]
        S1 --> S2 --> S3 --> S4 --> S5 --> S6 --> S7 --> S8 --> S9
    end

    SV["StreamVerify 流水线<br/>scan 阶段启动，边产出边验证"]
    LI["live_intake 实时喂料<br/>taskgen 之后注入动态任务"]
    MEM["收尾：VectorMemory 落盘<br/>增量状态 · A3.2 目标画像"]

    S3 -.->|"启动后台协程"| SV
    SV -.->|"验证结论回流"| S8
    S2 --> LI --> S3
    SV --> MEM
    S9 --> OUT(["report dict → scan_runner 落盘"])

    DUAL{{"DualAgent 并行开关<br/>dual_agent_parallel=True"}}
    S3 -.->|"gather 并行广度+深度"| DUAL
    DUAL -.->|"仅记账不重跑"| S6
```

**要点**

- 阶段顺序即 `_STAGES`：recon → taskgen → scan → chain_router → react_deep_dive → agent_coordinator → extras → verify → report。
- `scan` 阶段一开始即启动 **StreamVerify** 后台协程，findings 边产出边验证，不堆到最后集中判定。
- `DualAgent` 开启时，`scan`（广度）与 `agent_coordinator`（深度）用 `asyncio.gather` 并行，汇合墙钟 = `max(主链路, 副通道)`；副 agent 受软截止收割，不拖累主链路。

---

## 图 3：端到端数据流（数据对象视角）

```mermaid
flowchart LR
    T["目标 URL<br/>-t / -l 目标列表"] --> AUTH

    subgraph PRE["前置"]
        AUTH["认证会话建立<br/>Cookie 文件 / 浏览器 / Burp / 默认凭证 / --instruction 指令登录"]
        PROBE["target_capacity_probe<br/>探测目标安全 QPS/并发"]
    end

    AUTH --> CTX
    PROBE --> RATE

    CTX["ScanContext（core/context.py）<br/>url_graph · param_index · responses(LRU)<br/>tech_stack · sensitive_leaks · verified/suspected_vulns"]

    CTX --> GEN["任务生成 phases_taskgen<br/>端点 × 参数 × 引擎名 = Task"]

    GEN --> Q["SmartTaskQueue（ai/v100/smart_queue.py）<br/>PrioritizedTask 优先级堆 1-10<br/>bandit 可选 RL 排序 · 受保护任务豁免清理"]

    Q --> W["worker 池（并发上限由 adaptive_concurrency + safe_qps 决定）"]

    W --> ENG["引擎执行 core/scanner.run_engine<br/>scan(目标级) / check(参数级)"]

    ENG --> RAW["原始 findings<br/>type · severity · url · parameter · evidence · curl_command"]

    RAW --> FILT["本地预筛选 local_filter<br/>0 成本规则过滤 → 降 AI 调用"]

    FILT --> AI["AI 批判定 _ask_ai<br/>ModelRouter 选模 · batch_processor 合批<br/>A4.4 分层：明确项不进 LLM"]

    AI --> VERRY["验证与治理<br/>StreamVerify · 交叉验证 · OOB 回调<br/>hallucination_suppress 幻觉抑制"]

    VERRY --> DED["去重 + 生命周期<br/>dedupe · finding_lifecycle<br/>confirmed / refuted / pending_review"]

    DED --> REP["报告 report_generator<br/>JSON · HTML · Markdown · SARIF 2.1.0 · PoC 产物"]

    REP --> LEDGER["账本与回流<br/>coverage.json 覆盖账本<br/>report_diff 基线 · growth 实战回灌"]

    RATE["rate_limiter 自适应限流"] -.-> W
    DG["danger_guard 危险门卫"] -.-> ENG
    DG -.-> EXP["deepsec 深度利用<br/>需 --dangerous 放行"]
    VERRY -.-> EXP
```

**关键数据对象**

| 对象 | 定义位置 | 主要字段 |
| --- | --- | --- |
| `ScanContext` | `core/context.py:25` | `url_graph`、`param_index`、`responses`(LRU)、`normal_responses`、`tech_stack`、`sensitive_leaks`、`verified_vulns`、`suspected_vulns`、`burp_issues` |
| `PrioritizedTask` | `ai/v100/smart_queue.py:49` | `task_id`、`priority`(1–10)、`data`、`created_at`；`is_protected_task` 保护动态补测任务 |
| Finding（dict） | 引擎产出，规范见 `core/models.py:Vulnerability` | `type`、`severity`、`url`、`parameter`、`payload`、`evidence`、`confidence`、`ai_analysis`、`cve_ids`、`cvss_score`、`curl_command`、`reproduction_steps`、`oob_evidence` |
| `VulnerabilityStrict` / `WebAsset` / `ScanContextModel` | `core/models.py` | pydantic 严格模型，用于边界校验 |
| DAG 节点 | `dag/graph.py:DAGNode` | `node_id`、`node_type`、`target`、`params`、`depends_on`、`status`、`retry_count` |

---

## 图 4：引擎调度与验证闭环

```mermaid
flowchart TB
    DISC["引擎自动发现 core/scanner._do_load_engines<br/>扫描 engines/*.py → inspect 找 BaseEngine 子类<br/>要求：有 name 属性 + enabled=True → 实例化缓存"]

    DISC --> REG["注册表 _ENGINES / _ENGINE_MAP<br/>get_all_engines() · get_engine_by_name()"]

    REG --> SEL["引擎选择：三信号判定<br/>1 漏洞类型映射 get_engine_by_vuln_type<br/>2 参数名启发式<br/>3 技术栈/指纹命中"]

    SEL --> BUNDLE["engine_bundle 打包<br/>单个 URL 参数取 top-N 引擎"]

    BUNDLE --> GATHER["asyncio.gather 并发执行<br/>bundle 耗时 = max(t_i) 而非 sum(t_i)"]

    GATHER --> GLOBAL["global 引擎（目标级）<br/>phases_taskgen.global_engines 列表<br/>api_version · smuggling · cache_poison · info_leak …"]

    GLOBAL --> OUT1["findings"]

    OUT1 --> LOCAL["本地规则预筛选 local_filter"]
    LOCAL -->|"明确命中/明确无害"| DECIDE{"需要 LLM 判定？"}
    LOCAL -->|"模糊"| DECIDE

    DECIDE -->|"否（0 成本）"| KEEP["直接定级"]
    DECIDE -->|"是（合批）"| LLM["_ask_ai → ProviderFailover<br/>zhipu / aliyun / siliconflow 自动降级"]

    LLM --> JUDGE["AI 判定 + 置信度"]
    JUDGE --> VERIFY["验证层<br/>HTTP 重放 · OOB 回调 · Burp Repeater<br/>SafeExploit 沙箱复现"]

    VERIFY -->|"confirmed"| KEEP
    VERIFY -->|"refuted"| PEND["pending_review 待人工复核<br/>（验证层不一票否决）"]
    VERIFY -->|"证据不足"| PEND

    KEEP --> REPORT["进入报告"]
    PEND --> REPORT

    CB["成本熔断 _maybe_trip_cost_breaker<br/>AI 花费超预算 → 降级纯引擎模式"] -.-> LLM
    RL["限流 safe_qps + 自适应并发"] -.-> GATHER
```

**要点**

- 引擎是**确定性底座**，AI 只做"模糊判定"与"深挖"，两者解耦：弱模型/无模型时仍能产出引擎级结论。
- 验证层铁律：**refuted 不直接删除**，降级为 `pending_review` 待人工复核，避免误杀导致的漏报。

---

## 图 5：DAG 模式节点拓扑（`--dag`）

源码：`dag/graph.py`（15 种 `NodeType`）、`dag/scheduler.py`、`dag/executor.py`（`NODE_EXECUTORS`）、构建逻辑在 `runners/scan_runner.py:1395+`。

```mermaid
flowchart LR
    RS["recon_sub<br/>子域名收集"]
    RA["recon_alive<br/>存活探测"]
    RN["recon_nuclei<br/>Nuclei 扫描"]
    RJ["recon_js<br/>JS 分析"]
    RP["recon_port<br/>端口扫描"]
    RF["recon_ffuf<br/>目录爆破"]
    AT["attack<br/>引擎攻击"]
    VE["verify<br/>验证"]
    EX["exploit<br/>利用"]
    ED["exploit_deep<br/>深度利用（--deep）"]
    RE["report<br/>报告"]

    RS --> RA
    RS --> AT
    RA --> AT
    RN --> AT
    RJ --> AT
    RP --> AT
    RF --> AT
    AT --> VE
    VE --> EX
    EX --> ED
    ED --> RE
    EX --> RE

    DL["失败节点 → 死信队列<br/>_runtime_cache/dag_dead_letter/scan_id.jsonl"]
    AT -.->|"异常"| DL
    VE -.->|"异常"| DL
    DL -.->|"scan.py --resume --scan-id"| AT
```

**要点**

- 多目标时按 `t0/t1/...` 前缀复制子图，并共享一个 `batch_recon_sub` 批量子域节点。
- 上下文隔离靠 `dag/context.py::DAGContext` + `dag/executor.py::_ctx_key(prefix, key)`，节点间通过 context key 传数据。
- DAG **不另起炉灶**：`dag/executor.py` 的 recon 节点实例化 `V100Orchestrator` 并跑 `_recon()`（L192-218，实例存入 `DAGContext`），attack 节点取回同一实例跑 `_generate_tasks()` + `_execute_with_limiting()`（L387-395）；分布式 Worker 进一步复用 `NODE_EXECUTORS`。
- 因此 DAG/分布式**少跑 4 段**：`chain_router`、`react_deep_dive`、`agent_coordinator`、`extras` 属于 v100 `scan()` 的线性编排，DAG 模式下改由 `exploit` / `exploit_deep` 节点承担深挖。

---

## 图 6：运行形态与外部依赖

```mermaid
flowchart TB
    subgraph RUN["运行形态"]
        direction LR
        R1["CLI：python scan.py scan -t URL"]
        R2["MCP Server：stdio / HTTP<br/>供 Cursor · Claude Desktop 等外部 Agent 调用"]
        R3["Dashboard：FastAPI + /ws 实时状态"]
        R4["分布式：Master + N Worker（Redis）"]
    end

    subgraph EXT["外部依赖"]
        direction LR
        X1["LLM Provider<br/>OpenAI-compatible /chat/completions"]
        X2["第三方工具<br/>nuclei · sqlmap · ffuf · subfinder · httpx"]
        X3["Burp Suite<br/>Scanner / Intruder / Repeater / Collaborator"]
        X4["Redis（分布式）· ChromaDB（向量记忆，可降级内存）"]
        X5["OOB 通道<br/>dnslog / interactsh / Burp Collaborator"]
    end

    subgraph TGT["被测目标"]
        direction LR
        Y1["Web 应用 / API / 主机"]
    end

    RUN --> EXT
    RUN --> TGT
    X5 -->|"带外回调回连"| RUN
    X3 -->|"issues 收割"| RUN
```

---

## 附录：模块 ↔ 图元速查

| 图元 | 路径 |
| --- | --- |
| CLI 入口 | `scan.py`、`src/vulnclaw/cli.py`、`scan_main.py` |
| 扫描 runner | `src/vulnclaw/runners/scan_runner.py`（`main_async`） |
| 主编排器 | `src/vulnclaw/ai/v100/orchestrator.py`（`V100Orchestrator`） |
| 阶段实现 | `src/vulnclaw/ai/v100/phases/{phases_recon,phases_taskgen,phases_executor,phases_verify,phases_report}.py` |
| 任务队列 | `src/vulnclaw/ai/v100/smart_queue.py` |
| 引擎注册/分发 | `src/vulnclaw/core/scanner.py` |
| 引擎实现 | `src/vulnclaw/engines/*.py`（基类 `engines/base.py`） |
| 侦察 | `src/vulnclaw/modules/recon.py`、`modules/vuln_scanner/*` |
| AI 基座 | `src/vulnclaw/ai/core.py`、`ai/dispatcher.py`、`ai/provider_failover.py` |
| 治理 | `core/danger_guard.py`、`core/tool_registry.py`、`core/verification_gateway.py`、`core/finding_lifecycle.py` |
| 报告 | `core/report_generator.py`、`core/report_diff.py`、`core/coverage.py` |
| 集成 | `core/mcp_server.py`、`dashboard/server.py`、`core/plugin_market.py` |
