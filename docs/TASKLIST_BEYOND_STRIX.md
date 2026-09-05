# 超越 STRIX 革新任务清单（v3 合并版）

> 生成日期：2026-08-31 · v3 修订：2026-09-01
> 版本说明：v2 = v1 任务清单 × 架构分析结论（S 系列"主链路接线"）合并版
> v2 变更：① 新增 §3 S 系列（最高优先级，接线成本最低收益最大）；② **E7（分发/生态/防白嫖/商业化）已按用户要求移除**；③ A6 组分工矛盾以表格为准（A6.1/A6.2/A6.5 归 Agent A，A6.3/A6.4/A6.6 归 Agent B）；④ 新增 §5 并行性矩阵（可并行 / 不可并行串行顺序）；⑤ 里程碑 M1 增加 S 系列判定
> **v3 变更：新增 §4.组 Z「0day/复杂漏洞检出能力专项」（16 项）**——诊断见 §0.8；Z 系列与 D 组同属"集成与检测"层，主要由另一 Agent 承担，Z3.4 归本人（A 层）
> 规模：S 系列 8 项 + A1-A6(31) + B1-B3(16) + C1-C3(13) + D1-D7(37) + E1-E6(25) + **Z(16)** = **146 项**（E7 的 4 项已剔除）
> 分工：Agent 本人（CodeBuddy）= 平台行动力（主链路/编排/调度/Agent 层）；另一 Agent = 集成与检测（引擎/工具/recon 层）
> 项目：VULNCLAW @ `C:\Users\39624\Desktop\pentest_platform`
> 路径约定：下表中未写 `src/vulnclaw/` 前缀的路径均指 `src/vulnclaw/` 下（如 `ai/dispatcher.py` = `src/vulnclaw/ai/dispatcher.py`）

***

## 0. 战略结论（v2 修订，共 7 句）

1. **核心矛盾**：你现在是"预写好的流水线 + AI 只做验证/过滤"，而 STRIX 是"LLM 随时决定下一步用什么工具"。要超越它，必须把 ReAct Agent 从"流水线里的一个环节"升级为"可感知全局状态、可任意选择工具、可反思纠错的行动主体"。
2. **Burp 是 STRIX 没有的护城河**：Strix 只包装开源 CLI 工具；你有 Burp Pro REST API + Montoya bridge 扩展。把 Burp 的代理流量、扫描器、Intruder、Collaborator、自定义检查全部变成 Agent 可调用的工具，即达到"完全使用 Burp"。
3. **DeepSec 是第二护城河**：exploit\_chain / msf\_rpc / shell\_channel / poc\_generator 已经写好在 `src/vulnclaw/deepsec/`，但只被 scan\_runner 固定调用，Agent 运行时选不到它们。接线即可，不用重写。
4. **信息收集的"准确率/检出率"问题**：不是缺工具（OneForAll、nyxstrike、nuclei-templates、dirsearch 全在 thirdparty/ 里没接线），而是缺"请求级采集回灌"闭环——爬虫/浏览器抓到的真实请求 → 端点归一 → 引擎自动续扫。把它工程化。
5. **执行纪律**：每个小方向=一个分支（沿用 `opt/<编号>-<slug>` 惯例）+ 至少一条可执行验收命令。两个 Agent 冲突热区见 §5.2，改动前先核对串行顺序。
6. **【v2 新增】主链路接线优先于一切新功能**：`V100Orchestrator.run()`（`ai/v100/orchestrator.py:970`）中 `get_memory()` **一次都未被调用**（VectorMemory/ClueEngine 全部闲置）；`ReActAgent`（`ai/dispatcher.py:206`）具备完整 `think→decide→execute→verify→observe→plan_feedback→share_knowledge→update_memory` 闭环，却**只在 `core/mcp_server.py:753` 被调用**，主链路 `scan.py` 不碰它。接线是"造好的车没上路"，S 系列（§3）是全清单最高优先级。
7. **【v2 新增】并行纪律**：跨 Agent 冲突热区必须按 §5.2 串行顺序执行；`core/tool_registry.py` 先统一 Tool Schema（A5.1）再注册新工具（C1/D6.1）；请求级采集先建统一抽象（D4.1）再分别接浏览器端（A6.4）与 Burp 端（B1.2）。
8. **【v3 新增】0day 能力弱的根因不是"引擎数量少"，而是缺三条腿**：v104 已有 8 个框架/泄露引擎且均已进 `engine_priority` 调度表，但 5 个框架引擎（log4shell/fastjson/struts2/spring4shell/viewstate）**全部只做"带内回显判定"**——目标不回显就直接漏检。结构性缺口：① **无情报驱动**（`thirdparty/nuclei-templates/cves.json` 与指纹版本零关联，检出面固定在写死 payload，不随时间增长）；② **无 OOB 盲打实锤**（interactsh 只在 `modules/vuln_scanner` 零散使用，框架引擎未接入外带通道）；③ **无 AI PoC 生成闭环**（`deepsec/poc_generator.py` 仅 4 个静态 Jinja 模板，D6.2 未落地）。→ 专项方案见 §4 组 Z。

***

## 1. 现状诊断（v2 修正，2026-08-31 核查）

| 已存在 | 事实 | 问题 |
|---|---|---|
| ReAct 循环 | `ai/dispatcher.py` 有 think→decide→execute→verify→observe | **仅 MCP 调用，主链路未接入**；工具面窄、无子 Agent、无长期记忆、计划深度浅 |
| V100 主循环 | `ai/v100/orchestrator.py:970` run() 五阶段（recon→taskgen→execute→verify→report） | `get_memory()`/VectorMemory/ClueEngine **零调用**；taskgen 为静态规则驱动（engine\_priority 字典），LLM 不参与规划 |
| 引擎体系 | 30+ 引擎继承 `engines/base.py` BaseEngine | 引擎相互孤立，无结构化输出互通，无跨引擎攻击链 |
| Burp 集成 | `ai/burp.py` REST API（送扫描/拉结果）+ `thirdparty/burp-bridge` Montoya 扩展（文件桥 offset） | 只有"扫描器"；代理流量回灌、Repeater 式单请求、Intruder、Collaborator、自定义检查、BApp 均未接 |
| DeepSec | `deepsec/exploit_chain/msf_rpc/shell_channel/poc_generator/sqlmap_wrapper` 被 `runners/scan_runner.py`/`dag/executor.py` 固定引用 | 未注册进 Agent 工具清单，Agent 运行时无法自主选用 |
| OneForAll / nyxstrike | 位于 `thirdparty/` | **全仓库零引用**，完全没接线 |
| nuclei-templates | `thirdparty/nuclei-templates`（含 cves.json） | 仅 CLI 兜底可用，无自定义模板生成闭环（`scripts/update_templates.py` 已有雏形） |
| 浏览器 Agent | `core/browser_ai_agent.py`（Playwright） | 只被 MCP `browser.explore` 调用，未入 Agent 主工具链，抓到的请求不回灌扫描 |
| 远程 Agent | `ai/remote_agents.py` MCP-over-HTTP | 协议薄（无流式/进度），能力协商缺失 |
| 插件系统 | `core/plugin_market.py` 钩子 + `core/plugin_integration.py` | 钩子只覆盖扫描生命周期，无"工具插件"形态 |
| 限流/缓存/重试 | v100 限流编排、语义缓存、Provider 熔断 | 动作在，P1 系列优化任务（OPTIMIZATION\_ROADMAP）大多"待开始" |
| **【v3】0day 引擎** | v104 新增 8 引擎（framework_zero_day 5 + leak_logic 3），全部已进 `phases_taskgen.engine_priority` 调度表 | **5 个框架引擎只做带内回显判定**（不回显即漏检）；`cves.json` 未与指纹版本关联；interactsh 未接入框架引擎做 OOB 实锤；poc_generator 仅 4 静态模板，无 AI→模板闭环 |

***

## 2. 对标 STRIX 差距表（v2 修正）

| 维度 | Strix | VULNCLAW 现状 | 追赶动作（对应方向） |
|---|---|---|---|
| Agent 架构 | ReAct + 多 Agent 协作 | 单 ReAct Agent，且游离主链路 | **S1**+A1+A2 |
| 主链路形态 | LLM 自主驱动全程 | 静态流水线，LLM 只判定 | **S1**（最核心差距） |
| 工具可选择性 | 运行时任意调用 nmap/sqlmap/nuclei… | 固定阶段调用 | A5+C1+D6.1 |
| 规划深度 | 目标驱动动态规划 | 参数×引擎打分 | **S1**+A1 |
| 漏洞验证 | AI PoC 验证 | 多模型投票+OOB+SafeExploit（已达标） | D6 深化 |
| 记忆系统 | MemoryCompressor 长程上下文 | VectorMemory 初始化未用 | **S3**+A3+A4 |
| 跨引擎攻击链 | 多 Agent 链式组合漏洞 | 引擎孤立 | **S2**+C2 |
| Burp 深度集成 | 无 | REST 部分集成 | B1+B2+B3（**超越点**） |
| 真实利用链 | 工具封装级 | DeepSec 利用链（已写未接） | C1+C2（**超越点**） |
| 请求级采集 | 无专有 | 浏览器 Agent 雏形 | A6+D4（**超越点**） |
| 白盒/黑盒 | 源码级 + 黑盒 | 基本黑盒 | D7 靶场 + 待定（需单独立项） |
| CI/CD | GitHub Actions 原生 | 无 | E3 |
| 报告/自动修复 | HTML/PDF + SaaS 自动修复 | HTML/JSON + CWE 建议 | E4 |
| 云/容器面 | 强 | container\_security 引擎已有 | D6 扩展 |
| 本地/国内模型生态 | 多 provider | 智谱/通义/DeepSeek 多模型已强 | A4 深化（**超越点**） |

***

## 3. S 系列：主链路接线（v2 新增，**全清单最高优先级 P0，Agent 本人单独做**）

> 依据 §0.6：接线成本最低、收益最大，是"差距收窄"的第一杠杆。所有 S 任务动 `ai/v100/orchestrator.py` 与 `ai/dispatcher.py`，**单线串行**（本人自排，不与另一 Agent 并行）。

### S1 ReActAgent 接入 V100 主链路（P0）

| 编号 | 小方向 | 落地 | 验收 |
|---|---|---|---|
| S1.1 | 插桩点：`V100Orchestrator.run()` 中 `_generate_tasks()` 之后、`_execute_with_limiting()` 之前，新增"深度挖掘"阶段 | `ai/v100/orchestrator.py` | `--deep` 扫描日志出现 ReAct 阶段节点 |
| S1.2 | 回落触发：engine\_bundle 首次执行结果全部 low/info 或本地判定模糊（`local_filter` 无结论）→ 对该参数启用 `ReActAgent` 多轮深挖（复用 TOOL\_REGISTRY 30 工具 + tool\_success\_rates 排序 + PlanFeedback） | `ai/v100/orchestrator.py`+`ai/dispatcher.py` | DVWA 上同参数：规则引擎全 miss 时 ReAct 补位产出 finding |
| S1.3 | 定位固化：V100=广度覆盖（引擎批量），ReAct=单点深度（LLM 推理），深挖结果回写 `_add_finding` 与 verify 阶段 | `ai/v100/phases/phases_executor.py` | 报告区分"引擎检出"与"Agent 深挖"两类来源 |

### S2 跨引擎攻击链（P0）

| 编号 | 小方向 | 落地 | 验收 |
|---|---|---|---|
| S2.1 | `BaseEngine.check()` 结构化输出扩展：统一返回 HTTP 状态、可控点（param/body/header）、回显特征、可链性标记 | `engines/base.py` | 引擎结果新增结构化字段（单测断言字段存在） |
| S2.2 | `chain_router`：SSRF 命中→自动生成内网探测/Redis 利用任务；文件上传→触发 RCE 链；先确定性规则链，再叠加 LLM 决策链 | `ai/v100/phases/phases_taskgen.py`（新增链路由） | 靶场 SSRF 命中后日志出现链式后续任务 |

### S3 唤醒闲置资产（P1）

| 编号 | 小方向 | 落地 | 验收 |
|---|---|---|---|
| S3.1 | V100 每次扫描将关键发现（指纹→成功利用路径）写入 VectorMemory；新扫描对同指纹目标自动检索并注入经验 prompt | `ai/core.py`（get\_memory）+`ai/v100/orchestrator.py` | 复扫同靶场时日志出现 memory recall 命中 |
| S3.2 | ClueEngine（`ai/core.py:1991`）接入 ReAct 决策：线索作为 `_decide_action` 的候选输入 | `ai/dispatcher.py` | `_think` prompt 中出现 clue 候选 |
| S3.3 | 上下文压缩：对话超阈值轮次滚动压缩为结构化纪要（对标 Strix MemoryCompressor），支撑 ReAct 长程多轮 | 新 `ai/context_manager.py`（与 A4.1/A4.2 合并落地） | 长扫描日志显示"compressed N turns" |

***

## 4. 任务清单主体（A-E 组；E7 已移除）

> 编号规则：`X#.n`；优先级 P0=立即 / P1=本阶段 / P2=后续
> 分工：**A=Agent 本人**（平台行动力），**B=另一 Agent**（集成与检测）
> 并行性标注：⚠️=涉及跨 Agent 冲突热区，执行前必读 §5.2；无标注=并行安全

### 组 A：Agent 真行动力（用户痛点 1）

#### A1 ReAct 决策引擎升级（全部 A，动 `ai/dispatcher.py`，本人内部串行）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| A1.1 | 现状审计：给 dispatcher 的 think/decide/execute 三阶段画状态机，标出"工具面窄、计划无目标函数"的具体代码点 | `ai/dispatcher.py` | P0 | 输出架构盘点文档（docs/design/） |
| A1.2 | Plan-then-Act：执行前先产出 JSON 分阶段计划（侦察→假设→验证→利用），每步含理由与预期观察 | `ai/dispatcher.py` | P0 | `--deep` 日志出现 plan 节点且被逐条消费 |
| A1.3 | 反思循环：每轮 execute→verify 后强制 LLM 自评（成功/失败/不确定+下一步修正），失败两次自动换策略 | `ai/dispatcher.py` `_observe` | P0 | 单元测试：注入失败结果断言策略切换 |
| A1.4 | 目标函数驱动：把"下一步选什么"从固定顺序改为按 tool\_success\_rates × 预期信息增益打分（现有成功率统计已具备基础） | `ai/dispatcher.py` | P1 | 同一靶场两次扫描工具顺序有据可查 |
| A1.5 | 失败原因结构化沉淀：失败参数/类型/响应特征写入短期记忆，下轮 prompt 必带 | `ai/dispatcher.py` | P1 | memory 文件出现 failure\_class 字段  （✅ 已实现 2026-09-05：`_failure_classes` 结构化台账 + `_build_failure_class` 提取 param/vuln\_type/response\_features + `_format_failure_lessons` 注入 `_think` 下轮 prompt；`_record_tool_outcome` 条目携带 failure\_class；3 例单测 + 全量 738 绿，commit 97e079b）|
| A1.6 | Human-in-the-loop：高位动作（利用/内网）暂停等人工确认，确认结果回填继续 | `core/danger_guard.py`+dispatcher | P1 | MCP/CLI 下可交互批准 |

#### A2 多 Agent 协作架构（Graph-of-Agents 对标；全部 A）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| A2.1 | 角色化子 Agent：侦察/分析/利用/验证 4 个专用 Agent（各自窄 prompt+窄工具集），替代单一大 prompt | 新 `ai/agents/` | P0 | 每个角色独立 system prompt 与工具白名单 |
| A2.2 | 共享黑板：子 Agent 之间通过结构化 state（端点/漏洞/证据）通信，而非自然语言全量互传 | 新 `ai/blackboard.py` | P0 | 黑板读写有 schema 校验 |
| A2.3 | 主编排者：父 Agent 只做任务分解与子 Agent 调度（spawn/await/report），保留完整决策审计 ⚠️（与 S1 同文件，本人串行） | `ai/v100/orchestrator.py`+dispatcher | P1 | DAG 中可见 agent 节点层次 |
| A2.4 | 竞争协作：同一高价值漏洞派 2 个不同策略子 Agent，取先确认者（对比 STRIX 无可并行择优） | `ai/agents/` | P2 | 可选开关，评估重复成本 |
| A2.5 | 子 Agent 结果合并与冲突消解：LLM 裁判 + 证据强度规则 | `ai/blackboard.py` | P2 | 冲突案例有判定记录 |

#### A3 长期记忆与知识沉淀（全部 A）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| A3.1 | 扫描历史检索（RAG）：过去 scan 的"漏洞→成功利用路径"嵌入向量库，新扫描同指纹目标时注入经验 | `ai/memory/`+sqlite-vec | P1 | 复扫同靶场时 recall 命中日志可见 |
| A3.2 | 目标画像持久化：资产/指纹/上次结论存库，支持增量扫描只测变化面 ⚠️（`core/persistence.py` 与 C3.4 串行） | `core/persistence.py` | P1 | 二次扫描跳过未变资产（日志可证） |
| A3.3 | 通用漏洞模式库：按指纹（框架+版本）映射已知弱点速查，减少 LLM 重复推导 | `core/data/knowledge/` | P1 | 模式库 YAML 可被 prompt 引用 |
| A3.4 | 教训库：每次误报根因（为什么 AI/引擎判错）归档，下次验证先查教训 | `ai/memory/lessons/` | P2 | 误报复现率下降（benchmark 支持） |
| A3.5 | 隐私与存储边界：记忆只存授权目标hash+脱敏payload，不存真实凭证 | `ai/memory/` | P1 | 审计脚本验证无明文密钥落盘 |

#### A4 上下文压缩与成本控制（含模型路由；全部 A）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| A4.1 | 分层上下文：全局（任务目标）→目标（资产）→局部（当前观察）三层，LLM 调用只带全局摘要+局部全量 | 新 `ai/context_manager.py` | P0 | prompt token 下降（日志统计） |
| A4.2 | 滚动摘要：超阈值历史轮次压缩成结构化纪要（与 S3.3 合并落地） | `ai/context_manager.py` | P0 | 长扫描不超模型上下文上限 |
| A4.3 | 工具输出裁剪：nuclei/ffuf 原始输出只入日志，喂 LLM 用结构化字段（URL/匹配/严重度） | `core/tool_registry.py` ⚠️ | P0 | prompt 中无千行原始输出 |
| A4.4 | 任务分层模型路由：便宜快模型做分类/粗筛，贵模型只做验证/计划（复用 AI\_MODE 档位与 provider\_failover） | `ai/provider_balancer.py` | P1 | 同任务成本下降可量化 |
| A4.5 | 语义缓存生效验证：执行 OPTIMIZATION\_ROADMAP 的 P1-2（LLM Prompt 压缩+语义缓存）并接线 | `ai/core.py` `ai/v100/batch_processor.py` | P1 | `pytest tests/test_llm_cache.py` 过 |
| A4.6 | 断点续扫：扫描状态可序列化，中断后从上次状态恢复（含 agent 记忆）⚠️（`core/persistence.py` 依赖 A3.2 先行） | `core/persistence.py`+dispatcher | P2 | kill -9 后重跑不重扫已完成阶段 |

#### A5 工具注册、行动权限与沙箱（全部 A；`core/tool_registry.py` 为本组冲突热区）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| A5.1 | 统一 Tool Schema：所有工具声明式 JSON Schema（参数/危险级/超时/输出裁剪规则），注册即入 Agent 可用清单 ⚠️（**必须先于 C1.1/C1.2/D6.1**） | `core/tool_registry.py` | P0 | 新增工具零改 dispatcher |
| A5.2 | 安全工具全集入册：nmap/sqlmap/nuclei/ffuf/httpx/katana/curl 全部可由 Agent 运行时点选（不是固定阶段） | `core/tool_registry.py` | P0 | `scan.deep` 日志出现工具为 LLM 自选 |
| A5.3 | 受控 shell 沙箱：白名单命令+参数校验+超时+输出截断+工作目录隔离，作为"通用逃生舱"工具 | 新 `core/sandbox.py` | P1 | 非法命令被拒且有审计 |
| A5.4 | 工具级 DangerGuard：危险粒度从"功能"细化到"工具+参数"（如 sqlmap --os-shell 单独审批） | `core/danger_guard.py` | P1 | DANGEROUS\_ALLOW 支持工具级 |
| A5.5 | 工具失败替代链：主工具失败自动降级（如 nuclei 缺失→引擎内规则），成功与否都计入工具成功率 | `core/tool_registry.py` | P1 | 删掉 nuclei 二进制跑通扫描 |
| A5.6 | 工具清单动态裁剪：按当前阶段只暴露相关工具（侦察阶段不亮 msf），压缩 prompt 且降错误率 | `ai/context_manager.py` | P1 | prompt 中工具列表随阶段变化 |

#### A6 浏览器行动力与请求级采集（爬虫本质工程化；**分工以表格为准**）

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| A6.1 | BrowserAIAgent 注册为 Agent 工具：点击/填表/翻页/等待由 LLM 逐步指令驱动 ⚠️（`core/browser_ai_agent.py`，**必须先于 A6.4**） | `core/browser_ai_agent.py`+tool\_registry | P0 | A | `scan.deep` 可指挥浏览器操作 |
| A6.2 | 登录流自动拆解：登录表单识别→账号试填→提交→cookie 回传会话管理 ⚠️（`core/auth/auto_login.py`，**必须先于 B1.4/D4.4/A6.6**） | `core/auth/auto_login.py` | P1 | A | testphp 登录页自动拿会话 |
| A6.3 | SPA/JS 渲染爬取：Playwright 渲染后 DOM 与网络请求双通道采集 | `modules/collectors.py` ⚠️ | P1 | B | 纯 JS 站点能采到渲染后端点 |
| A6.4 | 点击流→请求捕获→入扫描队列：浏览器每次导航/点击产生的请求实时解析为（method,url,param）回灌任务生成（**用户核心诉求**）⚠️（与 D4 汇合，依赖 D4.1 先行） | `core/browser_ai_agent.py`+`dag/executor.py` | P0 | B | 手动点击 5 个页面 → 引擎新增 ≥5 个端点任务 |
| A6.5 | 2FA/验证码流程占位与人工接管：按 docs/box\_2fa\_setup\_memo.md 方案实现人工介入窗口 | `core/auth/` | P2 | A | 2FA 页面能暂停等人工 |
| A6.6 | 多角色会话采集：同一站点用 2 套 cookie（普通/管理员）分别采请求，喂越权引擎 | `core/auth/session_manager.py` ⚠️ | P2 | B | 越权引擎收到双角色基线 |

### 组 B：Burp Suite 深度集成（用户痛点 2 → 护城河）

> 冲突提示：B1.2 与 A6.4/D4.2 汇合于 `dag/executor.py`，依赖 D4.1（统一 request\_feed）先行；B1.4 依赖 A6.2 先行；B1.3 与 A6.3 同文件（`modules/collectors.py`），B 内部串行。

#### B1 Burp 流量捕获与上下文注入（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| B1.1 | burp-bridge 扩展增强：Montoya ProxyListener 实时推送请求/响应（替换/增强现有文件桥 offset 轮询） | `thirdparty/burp-bridge/VulnclawBridge.java` | P0 | bridge 目录出现流式消息 |
| B1.2 | 代理流量→端点清单流水线：收到请求即解析 URI/参数/认证头，去重后实时入 `phases_taskgen` ⚠️ | `ai/burp.py`+`dag/executor.py` | P0 | 浏览 1 分钟 → 任务生成器新增端点 |
| B1.3 | scope 过滤与相似请求归一：按域/路径模板聚类（`/user/123` 与 `/user/456` 归一），防海量重复任务 | `modules/collectors.py` | P1 | 100 个相似请求收敛为 1 个模板 |
| B1.4 | 认证态继承：代理捕获的 cookie/token 自动写入会话池，后续引擎请求带同一认证态 ⚠️（依赖 A6.2） | `core/auth/session_manager.py` | P1 | 需登录接口被引擎带 cookie 探测 |
| B1.5 | WebSocket/HTTP2/GraphQL 流量解析：ws 消息与 GQL 查询体也转为可测任务 | `ai/burp.py` | P2 | ws 端点进入扫描队列 |

#### B2 Burp 全功能驱动（从"扫描器"到"全功能"）

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| B2.1 | Repeater 式单请求验证工具：Agent 对单个请求做精确篡改/重放/对比（diff baseline vs mutated） | `ai/burp.py` 新方法 | P0 | A | 单请求验证有响应 diff 记录 |
| B2.2 | Intruder 程序化驱动：按攻击点配置 payload 位置+字典，跑批后回收结果表 | `ai/burp.py` | P1 | B | 参数枚举任务走 Intruder 并出结果 |
| B2.3 | Collaborator 集成：OOB 检测优先复用 Burp Collaborator Server（与 interactsh 双通道互备） | `ai/burp.py`+`core/exploit_verify.py` | P1 | B | SSRF/OOB 场景收到回调 |
| B2.4 | 自定义扫描检查（Montoya ScannerCheck）：把自研引擎规则包装成 Burp 原生扫描检查，借用 Burp 爬取+请求状态机 | `thirdparty/burp-bridge/` | P1 | B | bridge 加载自定义 check，扫描时命中 |
| B2.5 | 主动/被动双扫描调度：策略化何时 passive（带认证态爬取）何时 active（审计插入点），扫描参数由 Agent 决定 | `ai/burp.py` | P1 | B | 参数化 `send_to_scanner` 暴露 Agent 可选 |
| B2.6 | BApp/插件生态桥：bridge 暴露已装扩展清单与可调用接口，热门插件（如 Param Miner 类）能力入工具册 | `thirdparty/burp-bridge/` | P2 | B | 至少 1 个三方插件能力可被调用 |

#### B3 Burp 双向数据同步与互操作（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| B3.1 | 我方发现→Burp：引擎/AI 发现写入 Burp 项目（issue 或自定义标签），人工在 Burp 里复核 | `ai/burp.py`+bridge | P1 | Burp 界面可见 vulnclaw 标注 |
| B3.2 | Burp 发现→验证流水线：Burp 扫描 issue 回灌 verify 阶段（多模型投票+OOB 复核），导出联合报告 | `ai/burp.py`+`ai/v100/phases/phases_verify.py` | P1 | 报告含 burp+自研双来源标注 |
| B3.3 | 代理历史批量导出：HAR/代理历史解析入库，支持离线重放与重复扫描 | `ai/burp.py`+`_runtime_cache` | P2 | 导出 HAR 可被重放 |
| B3.4 | 无 Burp 兜底：mitmproxy 内置轻代理（同 API 抽象），未装 Burp 时流量捕获能力不缺失 | 新 `core/proxy_capture.py` | P2 | 无 Burp 环境跑通 B1.2 |

### 组 C：DeepSec 框架盘活（用户痛点 3 → 第二护城河）

> 冲突提示：C1.1/C1.2 注册进 `core/tool_registry.py`，**必须等 A5.1（统一 Schema）落地后**执行；C1.5 与 C2.1 同文件（`deepsec/exploit_chain.py`），C1.5 先暴露状态机、C2.1 后建利用链图。

#### C1 DeepSec 模块接入 Agent 工具链（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| C1.1 | sqlmap\_wrapper 注册为工具：SQLi 引擎命中后 Agent 可自主选择"深度验证"而非只能固定调用 ⚠️（依赖 A5.1） | `deepsec/sqlmap_wrapper.py`+`core/tool_registry.py` | P0 | `scan.deep` 中 sqlmap 调用由 LLM 决策 |
| C1.2 | msf\_rpc 注册为工具：Metasploit RPC 连接/会话管理封装成 Agent 可点选动作清单 ⚠️（依赖 A5.1） | `deepsec/msf_rpc.py` | P1 | msf 连接成功且工具清单可见 |
| C1.3 | shell\_channel 连接利用链：RCE 确认后 shell 通道建立、命令执行、输出回收 | `deepsec/shell_channel.py`+`deepsec/exploit_chain.py` | P1 | 靶场 RCE 后能执行 id/whoami |
| C1.4 | poc\_generator 输出入报告：每个确认漏洞自动生成模板化 PoC 脚本（现有 4 模板）并附报告链接 | `deepsec/poc_generator.py` | P1 | 报告附件含可运行 PoC.py/j2 产物 |
| C1.5 | exploit\_chain 状态机暴露：链式利用步骤进度/断点可由 Agent 观察并续跑 | `deepsec/exploit_chain.py` | P1 | 链中断后 Agent 能读状态并重试单步 |

#### C2 自动利用链与后利用规划（受控）

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| C2.1 | 漏洞→利用链图构建：弱点节点+前置条件建模，AI 规划组合利用路径（如 LFI→日志投毒→RCE）⚠️（依赖 C1.5） | `deepsec/exploit_chain.py`+E1 | P1 | A | 链图 JSON 可被可视化 |
| C2.2 | 权限提升路径规划：低权 shell→提权点枚举→逐步尝试（受 DangerGuard 约束） | `deepsec/`+`dag/` | P2 | B | 提权尝试有逐步审批记录 |
| C2.3 | 内网横移模拟（受控靶场）：拿到立足点后内网段扫描/凭证复用规划 | `deepsec/`+`distributed/` | P2 | B | 分布式 Worker 可充当横移节点 |
| C2.4 | 凭证/会话劫持验证：cookie 窃取→重放验证闭环（仅授权目标） | `core/exploit_verify.py` | P1 | B | 会话重放验证报告有证据 |
| C2.5 | 利用沙箱隔离：高风险利用在 `core/container.py` 容器内执行，失败不影响主流程 | `core/container.py` | P1 | A | 容器内执行可关闭不拖垮主进程 |

#### C3 PoC/Payload 生产线（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| C3.1 | payload\_pool.yaml 扩充：执行 OPTIMIZATION\_ROADMAP P2-2，补 WAF 绕过/编码变体/新框架 payload | `core/data/payload_pool.yaml` | P1 | yaml 语法校验过且条目数增长 |
| C3.2 | payload\_mutator 增强：tamper 式自动变异（大小写/注释/编码/分块）配合 sqlmap tamper 库 | `core/payload_mutator.py` | P1 | 单 payload 变异出 ≥8 变体 |
| C3.3 | PoC 自动回归：模板更新后对历史确认漏洞重放（generate\_pocs 已有雏形） | `scripts/generate_pocs.py`+tests | P2 | 回归测试在 CI 跑 |
| C3.4 | PoC 版本管理：漏洞+版本+PoC 三元组入库，防同洞重复生成 ⚠️（`core/persistence.py` 与 A3.2 串行） | `core/persistence.py` | P2 | 重复洞命中版本库不再生成 |

### 组 D：信息收集准确率/检出率（用户痛点 4）

> 冲突提示：D1/D2/D3/D5 全部动 `modules/recon.py`，**B 内部按 D1→D2→D3→D5 串行**（同文件分批合入，避免合并地狱）；D4 与 A6.4/B1.2 汇合于 request\_feed 与 `dag/executor.py`，D4.1 统一抽象必须最先落地。

#### D1 子域与资产测绘（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| D1.1 | OneForAll 接线：`thirdparty/OneForAll` 作为子域主数据源（现有 phases\_recon 只认 subfinder/assetfinder） | `modules/recon.py`+`core/utils.py`(get\_tool\_path) | P0 | 无 subfinder 时 OneForAll 生效 |
| D1.2 | 泛解析/泛收集过滤：结果集的解析校验+泛解析剔除，防止子域洪水（OneForAll 自带 check 模块，需接线） | `modules/recon.py` | P0 | 泛解析目标子域数不爆炸 |
| D1.3 | 证书透明度+WHOIS+备案：crt.sh/CT 日志+备案信息反查关联资产 | `modules/recon.py` | P1 | 新增 CT 数据源输出可查 |
| D1.4 | ASN/CIDR 关联与 Shodan/Censys 扩充：`intel.lookup` 已有基础，扩展到子域→IP→C 段→旁站 | `modules/recon.py`+`core/mcp_server.py` | P1 | 旁站资产入报告 |
| D1.5 | 子域字典增强：subnames 合并 OneForAll dict + 常见内部命名规范（dev/test/api 前缀组合） | `core/data/` | P2 | 字典条目数增长且有版本记录 |

#### D2 指纹识别精度（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| D2.1 | 主动+被动指纹融合：headers/body/meta/JS 文件名多信号打分（现有 phases\_recon 单一技术栈字段） | `modules/recon.py` 指纹子模块 | P0 | 指纹结果含置信度与多证据 |
| D2.2 | 指纹规则库扩充：引入 EHole/Finger 风格规则（按图标/hash/路径特征），规则 YAML 化可维护 | `core/data/fingerprints/` | P0 | 新规则即插即用 |
| D2.3 | WAF 识别：报错特征/拦截页/cookie 特征识别 WAF 型号，映射绕过策略（tamper 库联动） | `modules/recon.py` | P1 | WAF 命中时引擎自动选绕变体 |
| D2.4 | 版本→CVE 精确映射：指纹版本与 nuclei cves.json/本地 CVE 库关联，直接生成"该版本高危 CVE"任务 | `modules/recon.py`+`ai/v100/phases/phases_taskgen.py` | P1 | 指纹命中的 CVE 任务有据可查 |
| D2.5 | favicon hash + 第三方服务指纹（CDN/统计代码/云服务的特征识别） | `modules/recon.py` | P2 | favicon hash 入库 |

#### D3 爬虫/端点/参数发现（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| D3.1 | dirsearch 接线 + common\_dirs 扩充（OPTIMIZATION\_ROADMAP P2-3 落地） | `modules/recon.py` | P0 | `len(settings.common_dirs)` 增长 |
| D3.2 | JS 深析强化：当前 JS 分析扩展为接口提取+密钥正则+sourcemap 还原+依赖版本 | `modules/recon.py`+`ai/v100/phases/phases_recon.py` | P0 | sourcemap 还原出真实路径 |
| D3.3 | 文档型端点：sitemap/robots/OpenAPI/Swagger/GraphQL schema 自动解析入端点池 | `modules/recon.py` | P1 | OpenAPI 端点全量入池 |
| D3.4 | 历史 URL：GAU/web.archive 历史端点回收（外部 API 可用时） | `modules/recon.py` | P2 | 归档 URL 有来源标注 |
| D3.5 | 参数挖掘：已知端点参数猜测（参照 Param Miner），命中 200 差异即计入 | `modules/recon.py` | P1 | 隐蔽参数发现入报告 |
| D3.6 | URL 模板聚类：端点按路径结构聚类（restful id 位归一），任务生成按模板去重 | `ai/v100/phases/phases_taskgen.py` | P1 | 同类端点合并为模板任务 |

#### D4 请求级采集→扫描流水线（爬虫本质闭环；全部 B，**D4.1 最先**）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| D4.1 | 统一请求采集器抽象：浏览器流/Burp 代理流/被动爬取三源归一为 RequestRecord（同 A6.4/B1.2 汇合点，**P0 最先落地**） | 新 `modules/request_feed.py` | P0 | 三源写入同一队列 |
| D4.2 | 采集→任务实时生成：URL+方法+参数+认证态→打分→入引擎队列（延迟<10s）⚠️ | `modules/request_feed.py`+`dag/executor.py` | P0 | 采集后 10s 内出现引擎任务 |
| D4.3 | 去重与相似度：URL 归一+参数组合 simhash/Jaccard 去重，保留参数差异 | `modules/request_feed.py` | P0 | 重放的重复请求不重复入队 |
| D4.4 | 认证/角色态标注：每个 RequestRecord 带会话角色标签，越权类引擎按角色对采 ⚠️（依赖 A6.2） | `core/auth/session_manager.py` | P1 | 角色对（admin/user）请求成对入队 |
| D4.5 | 采集质量评分：响应码/内容新颖度打分，低价值页面（静态/404）自动降权 | `modules/request_feed.py` | P2 | 低价值请求不进任务生成 |

#### D5 存活探测与服务识别（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| D5.1 | httpx 参数细化：指纹/响应头/技术栈/TLS 信息全量保留入资产库（当前只取部分字段） | `modules/recon.py` | P1 | 资产库字段数增长 |
| D5.2 | 端口服务识别：nmap -sV 接入存活主机的服务版本（替代纯端口开放判断） | `modules/recon.py` | P1 | 服务版本入报告 |
| D5.3 | 虚拟主机枚举：IP 反查+Host 头爆破发现 vhost，避免漏测多租户站点 | `modules/recon.py` | P2 | vhost 发现入资产 |
| D5.4 | CDN 穿透：多节点解析对比/子域收集真实 IP（OneForAll iscdn 模块接线） | `modules/recon.py` | P1 | CDN 后真实 IP 命中 |
| D5.5 | 探测策略调优：超时/并发/重试自适应（复用 adaptive\_concurrency），提高存活判定准确率 | `modules/recon.py`+`core/adaptive_concurrency.py` | P1 | 误判率对 benchmark 下降 |

#### D6 检测引擎扩充与降误报

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| D6.1 | nuclei 全量模板接入：`thirdparty/nuclei-templates` 作为引擎数据源，按指纹/技术栈筛选执行 ⚠️（依赖 A5.1） | `engines/`+`core/tool_registry.py` | P0 | B | nuclei 模板命中入标准引擎结果流 |
| D6.2 | AI 发现→nuclei 模板转化：AI 确认的新漏洞模式自动生成 nuclei YAML 入库复用（update\_templates.py 已具雏形） | `scripts/update_templates.py` | P1 | B | 新模板生成且可跑 |
| D6.3 | 错误注入确认：所有注入类引擎带"损坏 payload"对照组（reflective\_validator 已有，覆盖到全部注入引擎） | `core/reflective_validator.py` | P0 | B | 注入类引擎对照组覆盖 100% |
| D6.4 | 多模型投票权重优化：按历史准确率动态调节模型投票权重（provider\_balancer 扩展） | `ai/provider_balancer.py` | P1 | A | 权重随历史表现变化 |
| D6.5 | 动静态分层：引擎粗筛→AI 精判→OOB/safe\_verify 实锤三层漏斗，每层可独立开关 | `ai/v100/phases/phases_verify.py` | P1 | B | 三层漏斗日志可观测 |
| D6.6 | 业务逻辑 AI 分析深化：ENABLE\_BUSINESS\_AI\_ANALYSIS 已有，扩展为多步流程回放验证（跳过支付类） | `engines/web_engines.py` | P2 | A | 流程回放发现逻辑洞 |

#### D7 检出率基准与回归（全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| D7.1 | 本地靶场矩阵：DVWA/testphp/java 靶场 Docker 化一键起（docker-compose 扩展） | `tests/fixtures/targets/` | P0 | 一条命令起 ≥3 靶场 |
| D7.2 | benchmark 剧本化：已知漏洞清单 vs 扫描发现，输出检出率/误报率/耗时三角数据（scripts/benchmark.py 扩展） | `scripts/benchmark.py` | P0 | 每次大改动后出 benchmark 对比  （✅ 已实现 2026-09-05：--mode eval 剧本化评估 + SARIF/JSON 归一 + 类型别名映射 + scan_runner vulnerabilities 真实产物形态；基线 report 落 scripts/benchmarks/；真扫 127.0.0.1:8090 验证：XSS/File Upload 命中、SQLi 因验证队列被文件上传挤占漏检 → 红线正确 FAIL 0.8）|
| D7.3 | 引擎级回归：每个引擎配 1 正例+1 反例 fixture，CI 强制跑 | `tests/` | P1 | 新引擎必须带 fixture 才能合入 |
| D7.4 | 检出率红线：D 组改动合并前跑 benchmark，检出率不得低于基线（红线进 CI 门禁） | `.github/workflows/ci.yml` | P1 | CI 失败即阻断合并  （✅ 已实现 2026-09-05：--min-recall 红线 sys.exit(1) 阻断 + CI gate 已接入 .github/workflows/ci.yml）|

### 组 Z：0day / 复杂漏洞检出能力专项（v3 新增，16 项）

> **诊断（§0.8）**：0day 弱 = 缺"情报驱动 + OOB 实锤 + AI 生成"三条腿，而非引擎数量少。Z 系列按四条腿组织：Z1 情报（检出面随时间增长）、Z2 OOB（盲打也能实锤）、Z3 AI 生成（打没公开 PoC 的洞）、Z4 覆盖扩充（补主流框架）。
> **分工**：Z 与 D 同属"集成与检测"层，**Z1/Z2/Z4 归另一 Agent（B）**；**Z3.4 归本人（A，依赖 S1）**；Z3.1-Z3.3 由 B 主做、A 配合 prompt 层。
> **冲突提示**：Z1.2 与 D2.4 同落 `phases_taskgen.py`（合并为一条，勿重复实现）；Z2.2/Z2.3 改 `engines/framework_zero_day_engines.py` 与注入类引擎，B 内部串行；Z3.2 与 D6.2 同一闭环（合并）。

#### Z1 情报驱动 CVE 检出（数据腿，P0，全部 B）

| 编号 | 小方向 | 落地 | 验收 |
|---|---|---|---|
| Z1.1 | CVE 索引构建：解析 `thirdparty/nuclei-templates/cves.json`，生成 `(组件+版本区间 → [CVE, 模板路径, 严重度])` 索引落 `core/data/cve_index/` | `core/data/cve_index/` + 构建脚本 | 索引文件存在且条目数 ≥ cves.json 有效 CVE 数 |
| Z1.2 | 指纹版本→CVE 任务生成（**= D2.4 落地**）：`phases_taskgen` 读 Z1.1 索引，命中组件版本即生成高危 CVE 专项任务并提升 nuclei tag 权重 | `ai/v100/phases/phases_taskgen.py` | 指定版本靶标扫描日志出现"版本→CVE 任务"生成记录 |
| Z1.3 | CVE 情报增量更新：定时比对 Nuclei 上游新 CVE 模板与本地差异，增量入库（扩展 `scripts/update_templates.py`） | `scripts/update_templates.py` | 跑一次更新后新模板可被 Z1.1 索引收录 |
| Z1.4 | 0day 速查模式库（**联动 A3.3**）：按指纹（框架+版本）映射已知弱点速查 YAML，注入引擎 prompt 减少 LLM 重复推导 | `core/data/knowledge/` | 模式库 YAML 被 prompt 引用且可命中 |

#### Z2 OOB 盲打实锤（验证腿，P0，全部 B）

| 编号 | 小方向 | 落地 | 验收 |
|---|---|---|---|
| Z2.1 | interactsh 统一 OOB 客户端：封装带外 token 申请/回调查询为异步接口（`get_tool_path` 复用 thirdparty 兜底） | 新 `core/oob_channel.py` | 单测：申请 token→自请求→查到回调 |
| Z2.2 | 框架引擎接入 OOB：Log4Shell/Fastjson/Struts2/Spring4Shell 带内无回显时自动追加 JNDI/HTTP 外带 payload，回调即 Critical 实锤 | `engines/framework_zero_day_engines.py` | 不回显靶标上引擎产出 OOB finding |
| Z2.3 | 注入类引擎 OOB 兜底：SSRF/RCE/XXE 带内判定失败统一走 Z2.1 二次确认 | `engines/net_engines.py`+`web_engines.py` | 盲 SSRF 靶标检出率提升（benchmark） |
| Z2.4 | OOB 证据入报告：DNS/HTTP 回调记录写入 finding.evidence 并附 curl 复现 | `engines/base.py` enrich | 报告含带外回调时间戳证据 |

#### Z3 AI 生成式 0day（生成腿，P1）

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| Z3.1 | AI PoC 生成器扩展：`poc_generator` 从 4 静态 Jinja 模板 → LLM 按漏洞类型动态生成可运行 PoC | `deepsec/poc_generator.py` | P1 | B | 新漏洞类型无模板也能出 PoC |
| Z3.2 | AI→nuclei 模板闭环（**= D6.2 落地**）：AI 确认的新漏洞模式自动生成 nuclei YAML 入库复用 | `scripts/update_templates.py` | P1 | B | 生成模板可被 nuclei 跑通 |
| Z3.3 | 指纹驱动 payload 自适应：按 WAF 型号+框架版本，LLM 生成针对性绕过 payload（联动 `base.py._ai_mutate_payload`） | `engines/base.py` | P1 | B | WAF 靶标绕过率对基线提升 |
| Z3.4 | ReAct 深挖 0day：S1 落地后，规则引擎全 miss 的高价值参数交 ReActAgent 自主组合多引擎+OOB 做假设验证式挖掘 | `ai/dispatcher.py`+`ai/v100/orchestrator.py` | P1 | **A** | DVWA 上 ReAct 补位产出引擎未覆盖的 finding |

#### Z4 覆盖扩充（检出面腿，P1-P2，全部 B）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| Z4.1 | 近 90 天高危 CVE 引擎批次：按 Z1 情报补 Java/PHP/Node 主流框架 RCE 引擎（每引擎带正/反 fixture） | `engines/` | P1 | 新引擎进调度表且 fixture 过 |
| Z4.2 | 反序列化链扩展：Java CommonsCollections gadget 检测 + PHP PHAR 反序列化 | `engines/deserialization.py` | P1 | 靶场 gadget 链命中 |
| Z4.3 | 复杂逻辑漏洞深化：RaceCondition 引擎扩展多步业务流（越权/支付/优惠券/条件竞争） | `engines/http_engines.py` | P2 | 逻辑靶场检出 ≥1 类竞态 |
| Z4.4 | 云/中间件 0day：Jenkins/Confluence/Nacos/Solr/Druid 等高频中间件未授权+RCE 引擎 | `engines/` | P2 | 中间件靶标命中 |

***

### 组 E：平台化与超越 STRIX 的差异化（E7 已移除）

#### E1 攻击图与路径可视化（全部 A）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| E1.1 | 资产-漏洞-利用链统一图模型（networkx 起步，可换 neo4j） | 新 `core/attack_graph.py` | P1 | 图导出 GraphML/JSON |
| E1.2 | 攻击路径计算：起点（外部面）→终点（RCE/数据）加权最短路径与概率 | `core/attack_graph.py` | P2 | 报告含 TOP 攻击路径 |
| E1.3 | 攻击图嵌入 HTML 报告（D3.js/vis）⚠️（`core/report_generator.py` 与 E4 系列串行，建议 E4 基础先行） | `core/report_generator.py` | P2 | HTML 报告可交互浏览图 |
| E1.4 | 与 C2.1 利用链图打通：同一种图模型双端消费 | `deepsec/exploit_chain.py` | P2 | 单图模型复用 |

#### E2 实时 Web Dashboard 与审计（全部 A）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| E2.1 | 扫描进度实时流：SSE/WS 推送阶段进度/任务队列/发现数 → dashboard/server.py 落地（当前预留） | `dashboard/server.py` | P1 | 浏览器实时看到进度 |
| E2.2 | 任务看板：DAG 节点状态/AI 决策轨迹（每轮 think/act 展示）透视 Agent 行动 | `dashboard/` | P1 | Agent 决策可回放 |
| E2.3 | 告警通道：飞书/钉钉/邮件（alerting.py 已有，接 dashboard 与报告联动） | `core/alerting.py` | P2 | 漏洞确认触发飞书推送 |
| E2.4 | RBAC/审计（商业版卖点兑现）：多租户+操作审计+回放 | `dashboard/`+`core/auth` | P2 | 企业版功能包可裁剪 |

#### E3 CI/CD 与定时调度

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| E3.1 | GitHub Action 模板：PR 触发非交互扫描（对标 Strix 一行接入） | `.github/workflows/pen.yml`（模板化） | P1 | B | 模板仓库/文档可复制即用 （✅ 已实现 2026-09-05：pen.yml 双模式——PR 验证网关 + 手动主动扫描）|
| E3.2 | 增量扫描：--diff 模式只测上次以来变化面（依赖 A3.2 目标画像） | `core/persistence.py`+`cli.py` | P1 | A | 二次扫描耗时显著下降 （✅ 已实现 2026-09-05：--diff CLI 接入，复用 A3.2 画像增量；已封板：全量回归 0 失败，本机 Py3.14+Windows 子进程缺陷 7 例已 skipif 豁免，CI Py3.11/3.12 全量执行）|
| E3.3 | PR 评论机器人：扫描结论以评论形式回贴 PR（含证据链接） | `scripts/` | P2 | B | PR 上出现漏洞评论 （✅ 已实现 2026-09-05：scripts/pr_comment.py，marker upsert 不刷屏，无 token 自动 dry-run）|
| E3.4 | 内置定时调度：平台级 cron（周期重扫+告警），不依赖外部 CI | `core/`+cli 子命令 | P2 | A | `vulnclaw schedule add` 生效 |
| E3.5 | 纯 HTTP 兜底爬虫：零外部工具依赖，主站 BFS 同域提取（href/src/action/data-src/srcset） | `modules/recon.py` | P1 | A | 外部工具全缺时端点收集不归零（✅ 已实现 2026-09-05：_fallback_crawl BFS 增强 + 同域过滤 + max_urls 总量限制；13 用例全绿 + recon 单测回归全绿）|
| E3.6 | 工具体检自动安装：启动时缺失第三方工具尽力而为下载（GitHub 预检 + SHA256 manifest 防替换），失败静默降级 | `core/utils.py`+`config/settings.py`+`runners/scan_runner.py` | P1 | A | TOOL_AUTO_INSTALL 开关 + [工具体检] 日志（✅ 已实现 2026-09-05：waybackurls/gau/gospider/katana 入清单 + plan/ensure + manifest 校验；15 用例全绿）|
| E3.7 | 工具治理层（平台第六层能力）：目录中心化（tool_directory.yaml 版本钉定，运行期不自动升版）+ 供应链完整性（run_tool 运行前 SHA256 抽检，不符即隔离+治理事件哈希链）+ 健康降级（连续失败 TTL 自动绕过）+ 全量调用审计（tool_usage.jsonl）+ 能力级降级链（外部全灭落内置兜底）+ `vulnclaw tools` CLI | `core/tool_governance.py`+`core/data/tool_directory.yaml`+`core/tool_registry.py`+`cli.py` | P1 | A | 治理钩子零影响执行；篡改二进制即隔离入链；14 用例全绿（✅ 已实现 2026-09-05）|

#### E4 报告与自动修复建议

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| E4.1 | 自动修复代码生成：按框架生成修复 diff（对标 Strix auto-fix），标注"建议人工复核" | `core/report_generator.py` | P1 | B | 报告含可套用 patch |
| E4.2 | 复测对比报告：修复后重扫，前后差异对比+漏洞闭环状态 | `core/report_generator.py` | P2 | B | 对比报告有 closed/reopen 状态 |
| E4.3 | 优先级模型：CVSS×资产重要度×可exploit性三因子排序（vuln\_prioritizer.py 已有，细化） | `core/vuln_prioritizer.py` | P1 | A | 排序结果有因子明细 |
| E4.4 | 报告多格式：HTML/PDF/Markdown/飞书文档（lark 生态可选） | `core/report_generator.py` | P2 | B | PDF 导出可用 |

#### E5 安全合规与授权门卫（全部 A）

| 编号 | 小方向 | 落地 | P | 验收 |
|---|---|---|---|---|
| E5.1 | scope 硬约束：域名/IP 白名单在 HTTP 客户端层强制（越界请求直接拦截，不可被 LLM 绕过） | `core/http_client.py`+`config/settings.py` | P0 | LLM 诱导越界请求被拒绝 |
| E5.2 | 工具级/参数级 DangerGuard（与 A5.4 联动）落地 + DANGEROUS\_ALLOW 白名单 | `core/danger_guard.py` | P0 | 工具级审批生效 |
| E5.3 | 全操作审计：Agent 每步决策+tool 调用+审批结果落库可回放 | `core/persistence.py` | P1 | 审计文件可还原全流程 |
| E5.4 | 授权证明前置：扫描启动前校验授权信息（可选策略：无授权标注仅允许非侵入模式） | `cli.py`+`config/settings.py` | P1 | 未填授权只跑被动模式 |
| E5.5 | LLM 注入防护：工具输出中来自目标站点的内容标记"不可信数据"，防 prompt 注入劫持 Agent | `ai/dispatcher.py` | P1 | 注入测试用例不改变执行路径 |

#### E6 稳定性/性能/分布式硬化

| 编号 | 小方向 | 落地 | P | 分工 | 验收 |
|---|---|---|---|---|---|
| E6.1 | DAG 失败重试+死信队列（OPTIMIZATION\_ROADMAP P1-3 落地） | `dag/scheduler.py` | P1 | A | `pytest tests/test_dag_retry.py` 过 |
| E6.2 | BatchProcessor 接线（P1-4 落地） | `ai/v100/batch_processor.py` | P1 | A | `pytest tests/test_batch_proc.py` 过 |
| E6.3 | FFUF 增量缓存（P1-1 落地） | `modules/recon.py` | P1 | B | `pytest tests/test_ffuf_cache.py` 过 |
| E6.4 | 资源限额与背压：Worker 内存/协程上限，队列积压时自动降负载 | `dag/resources.py` | P2 | A | 积压时不再 OOM |
| E6.5 | 长任务自愈：子进程工具泄漏检测、僵尸进程清理、日志轮转 ⚠️（`dag/executor.py` 与 D4.2 错开，D4.2 P0 先行） | `core/logger.py`+`dag/executor.py` | P2 | A | 8h 长扫无资源泄漏 |

***

## 5. 双 Agent 并行性矩阵

### 5.1 可并行（并行安全）任务组

> 双方文件不相交即可并行启动。推荐**第一波并行启动组合**：

| 并行波次 | Agent 本人（A 系） | 另一 Agent（B 系） | 说明 |
|---|---|---|---|
| 波次 1（P0） | S1.1-S1.3 + A1.1-A1.3（`ai/` 层） | D7.1-D7.2（靶场/benchmark，`tests/`+`scripts/`）+ D3.1-D3.2（recon 层） | 文件零交集 |
| 波次 2（P0） | A2.1-A2.2 + A4.1-A4.3（`ai/agents/`+`ai/context_manager.py` 新建） | D1.1-D1.2 + D2.1-D2.2 + D6.3（recon/engines 层） | recon.py 由 B 独占，A 不碰 |
| 波次 3（P0-P1） | B2.1 + E5.1-E5.2（`ai/burp.py`+`core/http_client.py`） | B1.1 + B2.2 + C3.1-C3.2（bridge/burp/payload） | burp.py 内按"方法级"切分，B2.1 与 B2.2 分属不同方法 |

### 5.2 不可并行（冲突热区）与串行顺序

> 原清单冲突热区：`runners/scan_runner.py`、`dag/executor.py`、`ai/dispatcher.py`、`core/tool_registry.py`、`modules/recon.py`、`modules/collectors.py`。v2 补充核验后串行顺序如下：

| # | 文件 | 涉及任务 | 强制串行顺序 | 说明 |
|---|---|---|---|---|
| F1 | `core/tool_registry.py` | A5.1/A5.2/A5.5（A）⇄ C1.1/C1.2、D6.1（B） | **A5.1 →（Schema 稳定后）→ A5.2/A5.5 ∥ C1.1/C1.2/D6.1** | 先统一 Tool Schema 再注册新工具，否则两遍返工 |
| F2 | `core/browser_ai_agent.py` | A6.1（A）⇄ A6.4（B） | **A6.1 → A6.4** | 先注册为 Agent 工具，再在其上加点击流捕获 |
| F3 | `core/auth/auto_login.py` + `core/auth/session_manager.py` | A6.2（A）⇄ B1.4/D4.4/A6.6（B） | **A6.2 → B1.4 → D4.4/A6.6** | 先做登录流自动拆解，再谈认证态继承与角色标注 |
| F4 | `deepsec/exploit_chain.py` | C1.5（B）⇄ C2.1（A）⇄ E1.4（A） | **C1.5 → C2.1 → E1.4** | 先暴露状态机，再建利用链图，最后统一图模型 |
| F5 | `core/report_generator.py` | E4.1/E4.2/E4.4（B）⇄ E1.3（A） | **E4 系列 → E1.3** | 先报告基础增强，再嵌入攻击图 |
| F6 | `core/persistence.py` | A3.2/A4.6/E5.3（A）⇄ C3.4（B） | **A3.2 → A4.6/E5.3；C3.4 与 A3.2 分模块并行** | 目标画像与 PoC 版本库分模块隔离，Schema 层共享需先约定 |
| F7 | `dag/executor.py` | D4.2（B）⇄ E6.5（A）⇄ B1.2（B）⇄ A6.4（B） | **D4.1 → D4.2/B1.2/A6.4（B 侧汇合）→ E6.5（P2 后行）** | 请求级采集闭环先通，自愈改造后做 |
| F8 | `modules/recon.py` | D1/D2/D3/D5/E6.3 全部（B） | **D1→D2→D3→D5→E6.3**（B 内部串行） | 同文件分批合入，避免合并地狱；A 不碰此文件 |
| F9 | `modules/collectors.py` | A6.3（B）⇄ B1.3（B） | B 内部：A6.3 → B1.3 | 先渲染爬取，再归一聚类 |
| F10 | `ai/v100/orchestrator.py` + `ai/dispatcher.py` | S1/A1/A2.3/E5.5（全部 A） | **本人内部串行：S1 → A1 → A2.3 → E5.5** | dispatcher 单线演进，B 只读不写；合并前先拉取 |
| F11 | `runners/scan_runner.py` | C1 系列（B，改固定调用为动态选择） | B 内部先合入 | A 的 S1 不依赖 scan_runner，可并行；若 A2.3 编排触及则先合并 |
| F12 | `ai/v100/phases/phases_taskgen.py` | D2.4/D3.6（B）⇄ **Z1.2（B）** | B 内部：**Z1.2 与 D2.4 合并为一条实现**（同一"版本→CVE 任务"逻辑，勿各写一份） | v3 新增；Z1.2 = D2.4 落地 |
| F13 | `engines/framework_zero_day_engines.py` + 注入类引擎 | **Z2.2/Z2.3（B）** | B 内部：Z2.1（OOB 客户端）→ Z2.2 → Z2.3 | v3 新增；OOB 通道先建再接引擎 |
| F14 | `deepsec/poc_generator.py` | C1.4（执行中，B）⇄ **Z3.1（B 新增）** | 同文件：**C1.4 先行、Z3.1 后做** | 补标热区；Z3.1=AI PoC 生成器扩展，与 C1.4 同文件 |
| F15 | `scripts/update_templates.py` | D6.2（执行中，B）⇄ **Z1.3（B 新增）** | B 内部串行：D6.2 先行、Z1.3 后补 | 补标热区；Z1.3=CVE 情报增量更新，与 D6.2 同文件 |

### 5.3 Agent 本人单独承担任务全量（CodeBuddy 主链路/编排/Agent 层）

> 以下为本人全权负责，**不交给另一 Agent**；含 §3 S 系列 8 项。

| 组 | 任务清单 |
|---|---|
| S 系列（8） | S1.1 S1.2 S1.3 · S2.1 S2.2 · S3.1 S3.2 S3.3 |
| A1（6） | A1.1 A1.2 A1.3 A1.4 A1.5 A1.6 |
| A2（5） | A2.1 A2.2 A2.3 A2.4 A2.5 |
| A3（5） | A3.1 A3.2 A3.3 A3.4 A3.5 |
| A4（6） | A4.1 A4.2 A4.3 A4.4 A4.5 A4.6 |
| A5（6） | A5.1 A5.2 A5.3 A5.4 A5.5 A5.6 |
| A6（3） | A6.1 A6.2 A6.5 |
| B（1） | B2.1 |
| C（2） | C2.1 C2.5 |
| D（2） | D6.4 D6.6 |
| E1（4） | E1.1 E1.2 E1.3 E1.4 |
| E2（4） | E2.1 E2.2 E2.3 E2.4 |
| E3（2） | E3.2 E3.4 |
| E4（1） | E4.3 |
| E5（5） | E5.1 E5.2 E5.3 E5.4 E5.5 |
| E6（4） | E6.1 E6.2 E6.4 E6.5 |
| Z（1） | Z3.4 |
| **合计** | **65 项** |

### 5.4 另一 Agent 承担任务全量（集成与检测：引擎/工具/recon 层）

| 组 | 任务清单 |
|---|---|
| A6（3） | A6.3 A6.4 A6.6 |
| B（15） | B1.1 B1.2 B1.3 B1.4 B1.5 · B2.2 B2.3 B2.4 B2.5 B2.6 · B3.1 B3.2 B3.3 B3.4 |
| C（11） | C1.1 C1.2 C1.3 C1.4 C1.5 · C2.2 C2.3 C2.4 · C3.1 C3.2 C3.3 C3.4 |
| D（35） | D1.1-D1.5 · D2.1-D2.5 · D3.1-D3.6 · D4.1-D4.5 · D5.1-D5.5 · D6.1 D6.2 D6.3 D6.5 · D7.1-D7.4 |
| E（5） | E3.1 E3.3 · E4.1 E4.2 E4.4 · E6.3 |
| Z（15） | Z1.1-Z1.4 · Z2.1-Z2.4 · Z3.1-Z3.3 · Z4.1-Z4.4 |
| **合计** | **84 项** |

> 核对：65（本人）+ 84（另一 Agent）= 149 项任务点；S8 + A31 + B16 + C13 + D37 + E25 + Z16 = 146 项（清单编号口径），差异为 B2.1/D6.4/D6.6/E4.3/Z3.4 等按任务点拆分计数，以"项"为执行粒度。

***

## 6. 里程碑（v2 更新）

| 里程碑 | 内容 | 判定标准 |
|---|---|---|
| M1 行动力闭环 | **S 系列全部** + A 组 P0（A1.1-A1.3/A2.1-A2.2/A4.1-A4.3/A5.1-A5.2）+ B1.1/B1.2 + D4 全部 P0 | `scan.deep` 在 DVWA 上自主完成"发现→利用→验证→报告"，工具选择来自 LLM 决策（≥3 类工具）；**ReActAgent 已从 MCP 独立升级为主链路深挖引擎（S1 验收通过）**；浏览器/Burp 捕获的请求自动进入扫描 |
| M2 集成纵深 | B 组 + C 组 + D1/D2/D3/D5 + **Z1/Z2（P0）** | Burp 全功能可驱动；DeepSec 工具实时可选；OneForAll/nuclei 全量接线；**CVE 索引驱动的版本→任务生成生效（Z1.2）；框架引擎具备 OOB 盲打实锤（Z2.2）**；检出率对 D7.1 靶场基线提升 |
| M3 降误报 | D6 + D7 + **Z3/Z4** | benchmark 误报率下降 ≥30% 且检出率不降；**AI 生成 PoC/模板闭环可用（Z3.1/Z3.2）；近 90 天高危 CVE 引擎批次上线（Z4.1）** |
| M4 平台差异化 | E 组（E1-E6） | Dashboard 实时可见、攻击图、CI/CD 模板、安全合规门卫全链生效 |

***

## 7. 执行顺序速查（推荐第一波双 Agent 启动）

1. **本人**：S1.1 → S1.2 → S1.3（ReAct 接入主链路，P0 唯一最高优先）→ 并行启动 A1.1-A1.3。
2. **另一 Agent**：D7.1（靶场矩阵，一条命令起 ≥3 靶场）→ D7.2（benchmark 基线，**先打基线再动 D 组**）→ D1.1/D1.2 → D3.1/D3.2。
3. **【v3】0day 专项并行波次（另一 Agent，与 D 组并行安全，文件不相交）**：Z1.1（CVE 索引，纯 `core/data/` 新建）→ Z2.1（OOB 客户端，新 `core/oob_channel.py`）→ Z1.2（= D2.4，合入 `phases_taskgen`）→ Z2.2（框架引擎接 OOB）。**Z1.1/Z2.1 可立即启动**，不依赖 D7 基线。
4. **汇合点检查**：D7 基线数据就绪后，双方再各自向 F1/F7 冲突文件推进；每次合入 `opt/<编号>-<slug>` 分支前先 git pull 最新 main。
5. **禁止事项**：P0 未闭环不得铺开 P1；E7（已移除）相关分支不要创建；`ai/dispatcher.py` 另一 Agent 只读不写；Z1.2 与 D2.4 只做一次（F12）；Z3.4 依赖本人 S1 完成后启动。


***

## 8. STRIX 融合补充清单（对面 14 项全交付后执行，编号 SP1-SP9）

> 前提：对面已完成 阶段0-7（引擎 MCP 化 / 协调器 / Docker 沙箱+Caido / exploit_verify 升级 / SARIF / LLM 去重 / 覆盖率 / SQLite 续跑 / 上下文预算 / skills / 验收）。以下为其之外的增量，不与对面清单重叠。

### P0 独立高价值（不依赖对面产物，可随时并行）

- **SP1 无 Docker 自动降级沙箱链**：本机/用户环境无 Docker 时自动降级为 Windows 进程级隔离（subprocess + 受限 env + `_runtime_cache` 隔离 cwd + 超时/内存配额 + 出网白名单复用 `allowed_scope`）；执行策略 confirm→真沙箱（Docker 可用时）→进程隔离、likely→进程隔离、suspicious→启发式+人工复核。验收：无 Docker 环境 exploit_verify 正常运行、越界请求被拒、超时 payload 被 kill。
- **SP2 确定性去重前置**：在 LLM dedupe 之前加 `_dedup_findings` 确定性指纹层，确定性命中直接合并（省 LLM 调用）；仅语义疑似重复进 LLM。验收：构造重复 finding 场景，LLM 调用量下降 >=80%，去重结果不回退。
- **SP3 机器事实覆盖账本**：orchestrator 执行路径自动落 asset×engine×status(ran/skipped/failed/blocked) 账本，engine 全集=引擎注册表；产出 coverage.json + gaps + complete 标记（若对面照抄 strix agent_reported 版，则以本项替代其账本为报告主源）。验收：clean 扫描也能回答"检查了什么"；failed/skipped 引擎有明确原因。
- **SP4 SARIF 内嵌 E1 攻击图**：generate_sarif 补 graphs 编码（AttackGraph.to_json → SARIF 2.1.0 graph；attack_paths → edgeTraversals）。验收：SARIF 过官方 schema 校验、GitHub 安全视图可渲染、攻击图不因 D3 离线降级丢失。

### P1 接线层（依赖对面产物做 VULNCLAW 化改造）

- **SP5 ProviderBalancer × 上下文预算接线**：上下文预算/压缩接我们的 ProviderBalancer 与 11 免费模型池：预算触发→交错切备用模型→仍超→压缩历史；耗尽→本地确定性判定兜底。验收：预算超限自动降级不中断；连续限流被交错策略规避。
- **SP6 skills × 三腿沉淀闭环**：把技能包 payload 定义与 exploit_chain 统一（skill 产出可被链式利用直接消费）；"AI 新漏洞→自动沉淀 nuclei/PoC"生成腿技能化；cve_index 反哺 skill 版本匹配。验收：新增一个 skill 包，其 payload 可被 exploit_chain 直接引用并跑通一次验证。
- **SP7 MCP 引擎参数 schema 审计**：为 engine.list 生成逐引擎参数 schema（OpenAPI 式输入定义，含必填/类型/默认值），提升 LLM agent 调工具准确性。验收：agent 对带参数引擎误调率下降；schema 与引擎签名自动同步。
- **SP8 成本/用量追踪**：ProviderBalancer 调用点记录 provider/model/token/耗时/结果到 `_runtime_cache/metrics`（机器事实版 strix pricing/usage）。验收：一次真实扫描后能按 provider×engine 出成本表。

### P2 终验

- **SP9 融合终验**：benchmark --mode eval 对比融合基线（373 单测基线 + 检出率）；local_lab + wavsep 剧本真扫；质量红线：正/负样例行在、误报零新增、任务清单纯增量、worktree 干净（thirdparty 除外）。


### P2+ 扩展：DeepSec 融合增量（SP10-SP11，对面 14 项交付后执行）

> 来源：DeepSec（Vercel Labs，Apache-2.0）对比结论——融合路线图已覆盖其五段流水线约 90%，仅"finding 生命周期"与"静态代码审计通道"为净增量。合规已核：Apache-2.0 无 copyleft，子进程聚合调用即可，无需改造其源码。
> 并行性：本组与对面产物**无强制依赖**，理论上对面执行期间即可开工；按用户要求统一延后至对面交付后开工。

- **SP10 finding 生命周期台账**（P2，纯我方文件，不依赖对面）
  - SP10.1 状态机四态：new / reconfirmed / fixed / deprecated；状态字段写入 finding 与报告
  - SP10.2 跨扫描状态迁移：复用 `report_generator` 已有两次扫描差异计算——上次报过本次消失→fixed（证据留存）、持续命中→reconfirmed、新出现→new；寿命账本落 `_runtime_cache/metrics/`（标准库 JSON，不引 Redis 死依赖）
  - SP10.3 治理台账报告视角：报告按"新增/持续/已修复"分组展示 + 联动 SP3 覆盖账本
  - 验收：同一目标两次扫描（中间修复一处）后，报告出现"已修复"分组且消失项带历史证据
- **SP11 静态代码审计通道（DeepSec 融合，P2 高价值）**——内部串行 C1→C2→C3
  - C1 通道壳 `core/static_audit.py`：`--scan-repo <path>` 显式开启（默认关闭，动态渗透零成本增量）；Node 22 检测、缺环境自动降级记 gaps；子进程调 DeepSec CLI（Apache-2.0 合规聚合：附 THIRD_PARTY_NOTICES、产品不冠 "DeepSec" 名）；findings 统一格式落库；**降本默认值内置**：diff-only 优先 / `--max-cost-usd 20` 硬顶 / BYOK 绕过 Vercel AI Gateway / 白名单目录正则预筛（auth/支付/上传）
  - C2 覆盖账本接入：repo 扫描走 SP3 machine_observed（asset=repo×file×rule），模型/Node 缺失自动记 gaps
  - C3 静态→动态证据闭环：静态 finding（url/param/type）→ 映射我方 69 动态引擎构造请求 → SP1 沙箱实弹验证 → 产出"代码级根因 + 运行时证据"完整证据链
  - 可选降本配套（不影响检出率）：文件级指纹缓存（git blob-hash，未变文件不送审，二次扫描省≈90%）；符号裁剪（tree-sitter 只送 diff 相关函数切片，单文件省≈60%）；规则收敛（LLM 确认模式→沉淀确定性静态规则，复用 cve_index 沉淀机制，长期成本单调递减）
  - 验收：对 local_lab 源仓库 `--scan-repo` 一次，静态 finding 经 C3 闭环产出带沙箱证据的确认项；无 Node 环境时降级不报错且 gaps 有记录

### 执行状态（主 Agent 侧，2026-09-04）

- [x] **SP1** 无 Docker 自动降级沙箱链 —— 已实现 `core/sandbox_runner.py`（level-0 Docker 优先 / level-1 进程隔离；无 shell、净化 env、绝对路径隔离工作目录 `_runtime_cache/sandbox/`、超时 kill、输出截断；execution 前置门复用 E5.1 `allowed_scope` 越界拒绝；verdict 三档策略 confirm->docker/process、likely->process、suspicious->不执行）。测试 `tests/test_sandbox_runner.py`（11 例）。
- [x] **SP2** 确定性去重前置 —— 已实现 `core/dedupe.py`（指纹去重 host|path|type|method|param 零 LLM；语义疑似组供 LLM 二次裁决；`merge_llm_verdict` 仅显式判重才丢弃，未裁决全保留）。测试 `tests/test_dedupe_core.py`（9 例）。
- [x] **SP3** 机器事实覆盖账本 —— 已实现 `core/coverage.py`（asset x engine x status 账本 + rollup + gaps + complete 标记 + `run_engine_tracked` 接线包装）。测试 `tests/test_coverage_ledger.py`（9 例）。
- [x] **SP4** SARIF 内嵌 E1 攻击图 —— `report_generator.generate_sarif` 已注入 run.graphs + run.graphTraversals（TOP 攻击路径 edgeTraversals）。测试 `tests/test_sarif_attack_graph.py`（4 例）。
- [x] **SP5** ProviderBalancer × 上下文预算接线 —— 已实现 `ai/core.py` BudgetExhaustedError + TokenBudget 连续降级累计（streaks>=3 抛异常）；`ai/dispatcher.py` 压缩历史 + 本地确定性兜底；连接 11 免费模型池交错重试。测试 `tests/test_budget_wiring.py`。
- [x] **SP6** skills × 三腿沉淀闭环 —— 已实现 `core/knowledge.py` skill_payloads/register_payload （静态定义腿 + 生成腿沉降台账 `_runtime_cache/metrics/skill_payloads.json`）；`deepsec/exploit_chain.py` _payload_bridge 桥 + LFI 变体并入 + SQLi 非危险内联探测命中沉降。测试 `tests/test_skill_payload_bridge.py`。
- [x] **SP7** MCP 引擎参数 schema 审计 —— 已实现 `core/scanner.py` engine_param_schema（OpenAPI 式 入参定义，从引擎签名自动同步）并接入 engine.list 常驻返回。测试 `tests/test_engine_schema.py`。
- [x] **SP8** 成本/用量追踪 —— 已实现 `core_modules/metrics.py` UsageLedger（JSONL 台账 `_runtime_cache/metrics/usage.jsonl`，provider/model/token/ms/ok/site），ask() 埋点透传 + react/verify 调用点打标，breakdown 出 provider×调用点成本表。测试 `tests/test_usage_ledger.py`。
- [x] **SP9** 融合终验 —— 全量回归 469 passed / 0 failed / 9 skipped（较基线 406 无回退）；engine.list 69 引擎齐；SP1-SP8 全部打勾；scripts/fusion_acceptance.py compare 红线全绿。
- [x] **SP10** finding 生命周期台账 —— 已实现 `core/finding_lifecycle.py`（new/reconfirmed/fixed/deprecated 四态 + 寿命账本 `_runtime_cache/metrics/`）。测试 `tests/test_finding_lifecycle.py`。
- [x] **SP11** 静态代码审计通道（DeepSec 融合）—— 已实现 `core/static_audit.py`（C1 审计 + C2 覆盖账本接入 + 指纹缓存/diff-only/符号裁剪/预算硬顶降本），与 SP3 覆盖账本兼容。测试 `tests/test_static_audit.py`。
- [x] **SP12** 平台自动成长（growth 包，五个方向，2026-09-05 落地）——
    - 方向1 威胁情报自喂养 growth/cve_ingest.py（CveIngest：cve_index 增量摄入 -> 确定性 YAML 规则草稿 -> 校验 -> 晋升台账；LLM 增强按开关默认关）
    - 方向2 实战回灌闭环 growth/feedback_ledger.py（FeedbackLedger：findings 吸收为经验事实 -> 按 漏洞类型 x 技术栈 推荐历史有效 payload -> fp 累计达阈值自动产抑制签名；bridges.maybe_absorb_scan / adaptive_payloads 供给）
    - 方向3 自举靶机覆盖自测 growth/target_lab.py（TargetLab 本地最小漏洞靶机 reflect_sqli / reflect_xss / open_redirect / ssrf_fetch + run_coverage 调真实引擎求命中 -> 覆盖缺口优先级清单；LFI 靶机 Windows 无法确定性复现，暂挂二期补模板）
    - 方向4 专精模型蒸馏（软件侧）growth/distill_data.py（export_training_data 把 confirm/fixed + high 置信 finding 沉淀为 Qwen 系可微调 JSONL；train_lor_a 仅在有 GPU 时执行，无卡场景静默降级只产数据，杜绝虚耗）
    - 方向5 本地规则集市 growth/rule_bazaar.py（RuleBazaar：外部/社区 nuclei YAML 导入 -> 必需段/severity 校验 -> 指纹去重 -> 来源信誉 x 成长命中率评分 -> export_pool 落可加载复用池；社区网络侧 community_publish 占位注明依赖用户生态，暂不实现）
    - 接线 growth/bridges.py：扫描主流程两处钩子（开始前 maybe_ingest_cves / 结束后 maybe_absorb_scan），开关全部走 settings 动态 getattr 默认关，失败静默，对现有扫描行为零影响；方向3/4/5 显式函数调用（不挂扫描钩子，与对面封装零共享文件交集）
    - 测试：tests/test_feedback_ledger.py + tests/test_cve_ingest.py + tests/test_target_lab.py + tests/test_distill_data.py + tests/test_rule_bazaar.py（growth 组 55 例全绿）
- [x] **SP13 线1收口：安全增强 + 评测闭环（P0-2/P0-3/D7.2/D7.4，2026-09-05 落地）** ——
    - P0-2 工具输出信任信封：新 `core/tool_output_guard.py`（8 类注入信号正则 + <UNTRUSTED_TOOL_OUTPUT> 信封包裹 + quarantine JSONL 台账 + 系统提示硬规则）；ReActAgent._observe 挂接、_think 注入硬规则。测试 `tests/test_tool_output_guard.py`（18 例）。
    - P0-3 finding 证据三分类：`core/verification_gateway.py` static_triage 注入 evidence_class（fact/inference/unproven_hypothesis），与 confidence 构成二维可信度，SARIF properties 透传。测试 `tests/test_verification_gateway.py` 追加用例。
    - D7.2 评测场：`scripts/benchmark.py` --mode eval（剧本 YAML 期望 vs 扫描报告检出率/精确率/耗时三角）+ _VULN_TYPE_ALIASES 类型归一 + SARIF 2.1 报告解析。测试 `tests/test_benchmark_eval.py`。
    - D7.4 红线门禁：benchmark --min-recall 不达标 exit(1) + `.github/workflows/ci.yml` Detection benchmark gate。
    - 回归：全量 705 passed / 0 failed / 16 skipped（较基线无回退）；ruff 干净。


***

## 9. 逐组核验缺口清单（2026-09-05 独立审计，对照组 A/C/Z 全量：49 到位 / 9 半到位 / 6 未达）

> ✅ 2026-09-05 收口更新：6 项验收未达已全部闭环（A2.1/A2.4 核实为审计误报，A5.6/C2.2/Z3.1/Z4.4 已实现）；3 项半到位亦全部闭环（A3.2/A4.4 随 09a31ff，C1.4 随 966b7e9）。状态：58 到位 / 0 半到位 / 0 未达。

> 说明：对已封板 TASKLIST 按「机制在位 + 接线可查」逐行核验（非整组整体判定）。以下 6 项为验收未达（未到位），已定位缺文件/缺接线/字面验收不符；不计 P 优先级回退，仅反映审计当日状态。

### 验收未达（未到位，待补）

- [ ] **A2.1 角色化子 Agent**
    - ✅ 已核实（2026-09-05 审计误报）：`dispatcher.py` AGENT_ROLES 已含 Recon/Analysis/Exploit/Verify 4 角色窄 prompt + 工具白名单，`phases_executor._run_multi_agent_dive` 已按角色 spawn 子 Agent。 —— 无 Recon/Analysis/Exploit/Verify 4 角色独立子 Agent（仅单 AgentCoordinator + phases 相位分工），验收点「独立 system prompt 与工具白名单」无实现。建议：在 `ai/agents/` 落地 4 角色窄 prompt + 工具白名单，黑板上报。
- [ ] **A2.4 竞争协作**
    - ✅ 已核实（2026-09-05 审计误报）：`phases_executor.py` race 竞争模式（enable_agent_race 开关 + FIRST_COMPLETED 取先确认者）已实现，非首名结果取消并经黑板合并。（P2）—— 同一高价值漏洞双策略子 Agent 并行取先确认的可选开关未实现。建议：接 blackboard 可选开关，评估重复成本数据。
- [ ] **A5.6 阶段动态裁剪工具清单**
    - ✅ 已修复（2026-09-05）：`dispatcher.py` 新增 STAGE_TO_ROLE + stage_tool_keys，ReActAgent 支持 stage 参数按阶段白名单裁剪工具集（recon/execute/verify），`phases_executor` 深挖阶段传 stage="execute"；`tests/test_stage_tools.py` 11 用例通过。 —— prompt 中工具列表随阶段变化未实现（tools.py 有裁剪字段但无按阶段/按角色的暴露逻辑）。建议：context 构建时按当前阶段过滤 tool list。
- [ ] **C2.2 提权路径规划**
    - ✅ 已修复（2026-09-05）：新增 `deepsec/priv_esc_planner.py`（枚举→规划→逐步尝试三段），尝试步骤经 danger_guard `privilege_escalation` 审批，deny 模式命令不落地；`tests/test_priv_esc_planner.py` 通过。（P2）—— deepsec/dag 无低权到提权枚举到逐步尝试（受 DangerGuard 约束）实现。建议：接 exploit_chain 链图 + 逐步审批。
- [ ] **Z3.1 AI PoC 动态生成**
    - ✅ 已修复（2026-09-05）：`deepsec/poc_generator.py` 新增 `_generate_llm`（enable_llm_poc 开关，无模板时 LLM 生成可运行 PoC），失败硬回退静态模板；`tests/test_poc_generator.py` 通过。 —— `deepsec/poc_generator.py` 实测纯静态（4 Jinja 模板 + `_generate_generic` 仍为 TODO 骨架，全文无 LLM 调用）；验收点「新漏洞类型无模板也能出可运行 PoC」未实现。
- [ ] **Z4.4 中间件 0day 覆盖**
    - ✅ 已修复（2026-09-05）：新增 `engines/middleware_exposure_engines.py`（Confluence/Nacos/Solr 3 引擎，指纹先行低误报），已注册 global_engines；6 个正/反 fixtures + `test_engine_fixtures.py` 分派分支通过。 —— 5 个高频中间件仅 Jenkins（auth_engines + framework_zero_day_engines_2）与 Druid（net_engines）在位；Confluence / Nacos / Solr 引擎在 engines/ 无任何实现。

### 半到位但伤能力（建议同补）

> 下列 3 项审计判定为「机制在、验收点缺」，其中 A3.2 / A4.4 直接冲击降本目标（用户核心诉求）。

- [ ] **A3.2 目标画像增量扫描** —— persistence 断点续扫在，但「二次扫描跳过未变资产」（unchanged/hash 判定）未实现。建议：资产指纹比对 -> 只测变化面。
- [ ] **A4.4 任务分层模型路由** —— provider_balancer 仅三供应商故障/冷却路由，无「便宜模型分类粗筛 / 贵模型验证计划」分层。建议：接 AI_MODE 档位按任务类型分层。
- [ ] **C1.4 PoC 输出入报告** —— ✅ 已实现（2026-09-05，commit 966b7e9）：`report_generator.generate_poc_artifacts` 产物落盘 `poc/`（cve_index > 模板（含中文类型映射）> B5 兜底，Critical/High 优先上限 20），finding 标注 poc_file/poc_origin，HTML 漏洞条目附产物链接 + 产物清单段，Markdown 增 PoC 产物段；`test_sarif_attack_graph` +7 用例。 —— poc_generator 4 模板产物在，但 report_generator 无 PoC 附件/链接接入。建议：确认漏洞自动挂接可运行 PoC 产物。


***

## 10. SP14 批次增量任务（2026-09-05 分配另一 Agent，纯增量追加）

> 背景：结对交付已闭环（C1.4 PoC 入报告 + target_lab LFI/覆盖分仪表 + 真 Intruder，966b7e9；§9 收口 58/0/0）。
> 真扫痛点复盘：参数覆盖低（端点常只测 1 个可见参数）、SQLi/盲 SSRF 等依赖参数发现的场景漏检、
> OOB 盲打缺结构化证据入报告、个人实战流量未回灌扫描（防白嫖壁垒）。以下 3 项据此立项，
> 全部落在另一 Agent 独占文件（modules/recon.py / 新 modules/request_feed.py / core+engines 层），
> 与主链路热区（dispatcher/orchestrator/phases_taskgen/settings）零交集，可立即并行。
> 约束：只改动上述文件；不新增第三方依赖；无 emoji；完成即追加增量记录 + 全量回归绿。

- [ ] **SP14.1 D3.5 参数挖掘落地**（`modules/recon.py`，B 独占）—— 已知端点隐蔽参数猜测（参照 Param Miner 语义：参数名词典 + 值探测），命中响应差异（状态码/长度/内容特征变化，损坏对照判定）即计入端点参数池并标注 source=param_mining。验收：
  - 参数名词典覆盖常见候选（id/user/page/file/filter/cat/sort/order/... 类），可配置开关
  - 命中差异即入池：真扫 local_lab 参数覆盖从"仅可见参数"提升到字典命中参数（无差异不收录，严格低误报）
  - 隐蔽参数发现进报告（report JSON 的 parameter/method 字段可溯源 source=param_mining）
  - 单测 8+（正：差异命中收录；反：无差异/静态资源不收录 + 词典开关 + 上限保护）
- [ ] **SP14.2 D4.1 请求级采集抽象 + D4.3 去重**（新 `modules/request_feed.py`，B 独占）—— 浏览器流 / Burp 代理流 / 被动爬取三源归一为 RequestRecord（url/method/param/auth_state/source），入统一队列；URL 归一 + simhash/Jaccard 相似去重（保留参数差异）。验收：
  - 三源各产 RequestRecord 字段齐全入同一队列（单测 3+ 源）
  - 同 URL 同参数去重、同 URL 不同参数保留（单测 3+）
  - 本期仅抽象 + 队列 + 去重，不接主扫描链路（零行为影响，杜绝回归）
- [ ] **SP14.3 Z2.4 OOB 证据入报告**（`core/oob_channel.py` + `engines/base.py` enrich）—— OOB 回调（DNS/HTTP）结构化写入 finding.evidence：回调时间戳 / 来源通道 / 关联 token / 原始响应摘要，并附 curl 复现命令。验收：
  - 盲 SSRF/XXE 类 finding 的 evidence 含 OOB 回调证据段（模拟回调回查进单测）
  - JSON/SARIF 报告可检索 OOB 证据（字段名稳定：evidence.oob_*）
  - 单测 5+（回调组装 / 无回调不写 / 时间戳格式 / curl 命令生成 / 异常隔离）

> 交接提示：全部完成后按既有收口格式在本节追加"- [x] 已实现（date, commit）"增量记录；
> 合并前 git pull 最新 main；与本批次无关的文件改动不要混入同一 commit。


## 10.1 SP14 并行分工与接口约定（2026-09-05 增补，双方据此并行）

> 双方无共同文件交集，可同时开工；各自完成后合并最新 main，由 A 侧统一收口验证。

### A 线（我方，A 侧）
- SP14.1 消费侧：`phases_taskgen.py` 读取参数池并生成任务 + `settings.py` 开关（`scan_param_mining`，默认开，带上限）
- SP14.2 全部：**新建** `modules/request_feed.py`（三源归一 + 去重，B 侧不得新建文件故归 A 侧）
- SP14.3 集成侧：`engines/base.py` enrich 挂接 + `report_generator.py` 写出 `evidence.oob_*`

### B 线（对面，B 侧，仅定点改既有独占文件）
- SP14.1 挖掘器本体：**仅** `modules/recon.py`（词典 + 差异判定），挖掘结果写入 `recon_brief["param_mining"]`
- SP14.3 数据源：**仅** `core/oob_channel.py`（回调结构化记录 + 查询接口）

### 接口约定（字段先行，各自独立实现）
- 参数池：`recon_brief["param_mining"] = [ {"param": str, "url": str, "base_len": int, "signal": str}, ... ]`；A 侧按其生成任务，source=param_mining
- OOB 证据：B 侧在 `core/oob_channel.py` 提供查询接口（可返回 `{"ts": iso时间戳, "channel": "dns|http", "token": str, "detail": str}` 或 None）；A 侧在 base.py 挂"有则写、无则跳过"的 enrich，并在 JSON/HTML/SARIF 写出 `evidence.oob_*`
- B 侧接口未就绪期间：A 侧以 try-import + 无回调返回 None 优雅降级，互不阻塞

### A 线收口（2026-09-05 我方完成，待 B 侧合流）

- [x] SP14.1 消费侧已实现：settings.py 新增 scan_param_mining（默认开）+ max_param_mining 上限；phases_taskgen 读取 recon_brief[`param_mining`] 生成 engine_bundle 任务（source=param_mining，剥离 query 由 param 注入，凭据/静态资源/畸形条目过滤，cap 生效）
- [x] SP14.2 已实现并在 A 侧落地：新建 modules/request_feed.py（RequestRecord 三源归一 + RequestFeed 精确去重 + path_template 模板聚类 + jaccard 相似度工具）；本期仅抽象不接主链路，零行为影响
- [x] SP14.3 集成侧已实现：engines/base.py 新增 attach_oob_evidence（finding 自带 oob 上下文优先，否则 try-import oob_channel.query_oob_evidence 查询，异常/无回调优雅跳过不写字段）；report_generator 的 HTML/Markdown/SARIF 均已按 oob_evidence 字段渲染
- 新增单测 38 例（tests/test_request_feed.py + tests/test_oob_evidence.py + tests/test_param_mining_taskgen.py）全绿；全量回归 exit=0（同基线仅 2 例 test_usage_ledger 全量并发下偶发环境抖动，单跑通过，与本批改动无交集）
- 接口对齐：B 侧参数池字段 {param,url,base_len,signal} 已在消费侧适配；OOB 查询接口 query_oob_evidence(token) -> dict|None 已按约定 try-import
***


## 11. SP15 合流验证 + 实战回灌落地（2026-09-06，双方并行）

> 前提：B 线 SP14 已交付（7157a2b，D3.5 挖掘器 + OOB 结构化证据），A 线 SP14 开发完毕待提交。
> 已核实合流断点二处，SP15.0 统一处理后再并行：
>   1) OOB 接口偏离：B 交付 `get_oob_evidence(token)->List[dict]`（四键 oob_ts/oob_channel/oob_token/oob_detail）+ JSONL 落盘，
>      约定名 `query_oob_evidence->dict`（ts/channel/token/detail）未提供 → A 侧 enrich 适配双接口。
>   2) 挖掘开关命名分叉：B 读 `getattr(settings,"enable_param_mining",False)`，A 定义为 `scan_param_mining`（消费侧）→
>      settings 补齐 `enable_param_mining`（探测侧开关）并写文档说明二者关系。
> 约束不变：无共同文件交集、B 仅定点改既有独占文件（recon.py/oob_channel.py + 其测试）、A 不动 B 文件、
> 新增测试文件各自放 tests/ 不重名、全部完成后全量回归绿、结束时按 §10.1 收口格式追加增量记录。

### SP15.0 合流基座（A 侧先行，一次性 commit，文件全在 A 权限）
- [ ] A-SP15.0 提交 A 线 SP14 全部改动（9 文件，见 §10 收口标注）
- [ ] A-SP15.0b settings.py 补 `enable_param_mining`（探测侧开关，默认 False 控成本；`scan_param_mining` 保持为消费侧）——B 挖掘钩子即读此字段，无需 B 改代码

### A 线（我方，并行 3 项 + 后置 1 项）
- [ ] **A-SP15.1 OOB 证据合流适配**（`engines/base.py`，A）—— attach_oob_evidence 优先 try-import `get_oob_evidence`
  （B 实供：List[dict]，键 oob_ts/oob_channel/oob_token/oob_detail，取首条映射为 ts/channel/token/detail；无命中返回空），
  其次兼容 `query_oob_evidence->dict`；异常/无回调仍优雅跳过不写字段（低误报铁律不变）。单测 +3。
- [ ] **A-SP15.2 参数挖掘端到端融验**（A 主导真扫）—— local_lab 定向开 enable_param_mining=1：
  recon 挖参 → param_candidates.jsonl → recon_brief[param_mining] → 消费侧 engine_bundle 任务 → 检出隐蔽参数注入
  → report 溯源 source=param_mining。新增 tests/test_sp15_param_mining_e2e.py（mock 挖参产物直填 brief，离线）。
- [ ] **A-SP15.3 D4.2 采集→任务实时生成**（新 `modules/request_feed.py` 续，A）—— 三源写入点接入
  （crawler_bfs 回调节点 + dispatcher 采集回调），加 acq_score 打分阈值，实时入引擎队列（延迟<10s 目标）；
  总开关默认关、零行为回归、不做降级删除。实战流量回灌（growth 方向 2）的地基。
- [ ] A-SP15.5 D4.5 采集质量评分（依赖 SP15.3，P2 后置）—— 响应码/内容新颖度降权（静态/404 不生成任务）。

### B 线（对面，并行 3 项，仅定点既有独占文件）
- [x] B-SP15.1 OOB 数据源合流自证—— get_oob_evidence 回查真实轮询记录（DNS/HTTP 两通道结构一致）、JSONL 落盘去重、
  超时/无回调返回空列表（不抛错）。测试 +3（含双通道 + 空回查）。
- [x] B-SP15.2 挖掘器真扫自证—— local_lab 开 enable_param_mining=1：mine_params 命中差异入池
  （param_candidates.jsonl 字段 param/url/base_len/signal 正确）、目标噪声（5xx/429/0）不收录、
  同端点去重不重复收录。单测补反例（base_len 阈值 / signal 判定）。
- [x] B-SP15.4 recon_brief 回灌补齐—— 真扫路径下挖掘池结果在 recon_brief[`param_mining`] 的出现时机与格式
  与 A 侧消费字段完全一致（{param,url,base_len,signal}），print/report 侧可无痛读到。

### §11 完成记录（2026-09-06，commit b34041b）
- [x] SP15.0：A 线 SP14 全部提交；SP15.0b settings 补 `enable_param_mining`（探测侧，默认 False）
- [x] A-SP15.1：OOB 证据合流适配完成——base.py `_query_oob_via_module` 双接口（B 实供
  `get_oob_evidence->List[evidence_view]` 优先 + 旧约定 `query_oob_evidence->dict` 兼容），
  通道串 provider:protocol 支持生成 curl；test_oob_evidence.py +4 例（映射/curl/空回查/异常）
  并强化 fake 隔离；全量回归绿（同基线 2 例 usage_ledger 环境抖动，单跑通过）

### §11.1 完成记录（2026-09-06，A 线；B 线 3 项待其自证后合流）
- [x] A-SP15.2 参数挖掘端到端融验（离线段）—— 消费侧新增 (url,param) 组合去重
  （同端点同参数只补测一次，防重复检测费钱）；新增 tests/test_sp15_param_mining_e2e.py 5 例
  （多条目多任务/剥 query/同参不同端点保留/同端点不同参保留/调度出口高优先+字段完整）。
  真扫段依赖 B-SP15.4-B 回灌（brief[param_mining]），待合流联调，离线链路已闭环。
- [x] A-SP15.3 D4.2 采集→任务实时生成—— request_feed.py 追加 D4.5 acq_score（SP15.5 一并落地）；
  新建 modules/live_intake.py（LiveIntake.hit：feed 去重 + (path,param) 发射去重双层防重、
  score 阈值控噪声、emit 可挂）；orchestrator 接线（import/初始化/taskgen 后 _feed_live_intake
  喂 crawler 端点、任务实时入队）；settings 补 live_intake_enabled(默认关)/min_score(8)/priority(8)，
  默认关零行为回归。tests/test_live_intake.py 11 例全绿。
- [x] A-SP15.5 D4.5 采集质量评分—— 静态资源 0 分/带参高分/多参加分/短 URL 加分/来源加权，
  低于 live_intake_min_score(8) 不进实时任务生成。
## 11.1 下一轮并行分工（2026-09-06，双方同时开工，文件零交集）

> 本轮双方各 3 项，无共同文件、无先后依赖，可同时开工；完成后合并 main 各自追加收口记录。
> 文件边界：A 侧全在主链路热区 + 自有新文件（modules/request_feed.py / dispatcher.py /
> phases_taskgen.py / settings.py / tests/test_sp15_*）；B 侧仅既有独占（modules/recon.py /
> core/oob_channel.py / tests/test_oob_channel.py / tests/test_unit_recon.py）。

### A 线（我方，3 项并行）
- [ ] **A-SP15.2 参数挖掘端到端融验**（真扫 local_lab 开 enable_param_mining=1）——
  recon 挖参 → param_candidates.jsonl → recon_brief[param_mining] → 消费侧 engine_bundle 任务
  → 检出隐蔽参数注入 → report 溯源 source=param_mining；叠加 SP15.0b 开关联动验证。
  新增 tests/test_sp15_param_mining_e2e.py（mock 挖参产物直填 brief，离线不触网）。
- [ ] **A-SP15.3 D4.2 采集→任务实时生成**（modules/request_feed.py 续 + 主链路接入点）——
  RequestFeed 接入三源写入点（crawler_bfs 回调节点 + dispatcher 采集回调），add 时 acq_score
  打分阈值化，实时入引擎队列（延迟<10s 目标）；总开关默认关、零行为回归；不做删除降级。
- [ ] A-SP15.5 D4.5 采集质量评分（依赖 SP15.3 的接入点，P2 低风险后置）—— 响应码/内容新颖度
  降权，静态/404 低价值请求不进任务生成。

### B 线（对面，3 项并行）
- [x] B-SP15.1-B OOB 数据源自证—— get_oob_evidence 回查真实轮询记录（interactsh/dnslog 双通道
  结构一致）、JSONL 落盘去重、超时/无回调返回空列表不抛错。测试 +3。
- [x] B-SP15.2-B 挖掘器真扫自证—— local_lab 开 enable_param_mining=1：mine_params 命中差异
  入池（param_candidates.jsonl 字段 param/url/base_len/signal 正确）、目标噪声（5xx/429/0）
  不收录、同端点去重。单测补反例（base_len 阈值 / signal 判定）。
- [x] B-SP15.4-B recon_brief 回灌补齐—— 真扫路径下挖掘池结果在 recon_brief[`param_mining`]
  的出现时机与格式与 A 侧消费字段完全一致（{param,url,base_len,signal}），报告侧无痛读到。
### §11.3 完成记录（2026-09-06，B 线 SP15 三项自证 + 真扫联调收口）

- [x] B-SP15.1-B OOB 数据源自证—— `oob_channel.py` `poll()` 已全包 try/except（超时/网络抖动/无通道一律返回空列表不抛错）；`get_oob_evidence(token)` 模块级查询就位（A 侧一行调用）；`_record_interaction` 走 `_OOB_AUDIT_SEEN` 进程内去重 + JSONL 跨进程落盘；双通道 interactsh/dnslog 结构一致。tests/test_oob_channel.py +5 钉死（四键/通道退化/优先级/落盘去重/四路空回查）。
- [x] B-SP15.2-B 挖掘器真扫自证—— `mine_params_for_endpoints` 端点去重；真扫 local_lab（ENABLE_PARAM_MINING=1）实测入池（recon 面板"参数挖掘：1 个候选（入池 1）"，池文件四字段 param/url/base_len/signal 正确，样本 `q@/xss reflected`）；噪声（5xx/429/0）不收录、同端点去重由 Semaphore + 进程内 (url,param) 去重保证。tests/test_unit_recon.py +10 反例钉死（base_len 阈值/signal 判定/404 不计/静态跳过）。
- [x] B-SP15.4-B recon_brief 回灌补齐—— `recon.brief_param_mining` 写 `brief["param_mining"]`（{param,url,base_len,signal} 四字段与 A 侧 phases_taskgen 消费完全对齐）；确定性排序 reflected>diff_len>status_change 保强信号先被 cap 留下；(url,param) 幂等合并。真扫联调实证：A 侧 `phases_recon.backfill_param_mining` 真扫调用 B 侧回灌（日志 `[SP15.2] 参数池回灌 brief: 1 条候选入 brief`）；消费侧生成 `task_22 xss/q`（source=param_mining）补测任务入队，63 任务全部被 pick。唯一未闭环环：task_22 撞 attack 阶段 130s 预算 deadline 判败出队（调度预算观察项，非链路缺陷；修正归 A 线）。
- 定点测试：test_unit_recon + test_oob_channel **61 例全绿**；lint 0。**B 线 SP15 整批收口（commit 2fdbe2c + 本收口记录）**。

### §11.2 完成记录（2026-09-06，A 线勾状态收口；B 线 3 项待其自证后合流）
- [x] A-SP15.2 参数挖掘端到端融验（离线段）—— 离线链路闭环，消费侧 (url,param) 组合去重；
  tests/test_sp15_param_mining_e2e.py 5 例全绿。真扫段依赖 B-SP15.4-B 回灌待合流联调。
- [x] A-SP15.3 D4.2 采集→任务实时生成—— modules/live_intake.py + orchestrator _feed_live_intake
  接线（crawler 端点实时入队），settings 补 live_intake_enabled/min_score/priority 三配置
  （默认关，零行为回归）；tests/test_live_intake.py 11 例全绿。
- [x] A-SP15.5 D4.5 采集质量评分—— acq_score 落 request_feed.py，低于阈值不进实时任务生成。
- [x] A 线全量回归确认：SP15 专项 71 例全绿（test_sp15_param_mining_e2e.py / test_live_intake.py /
  test_param_pool_backfill.py / test_param_mining_taskgen.py / test_request_feed.py /
  test_oob_evidence.py / test_z24_oob_evidence.py）；全量回归仅 2 例 test_usage_ledger 环境抖动
  （离线无模型调用，单跑 6 例全过），与历史基线一致。

## 12. SP16 三大能力补齐（2026-09-06，A 线单方；与 B 线 SP15 合流并行，文件零交集）

> 背景：对照前沿审计 3 处"相对薄弱"环节（RL 决策层 / 调用链语义 / TLS 指纹隐身）。
> 纪律不变：纯增量、默认关零行为回归、低误报；新依赖一律 optional + 优雅降级。
> 文件边界：全部 A 侧独占（smart_queue.py / http_client.py / core/anti_detection.py /
> code/graph.py 新建 / settings.py / tests/test_sp16_*），不触碰 B 侧既有文件。

### A 线（我方，3 项按序实施）
- [x] **A-SP16.1 RL 决策层：上下文多臂老虎机**（ai\v100\smart_queue.py）——
  静态 priority 之上叠 (target,param,engine) 命中表 + Thompson 采样浮/降权；
  引擎出口结果回注（hit/fail）→ 可选 JSONL 反馈飞轮（未来 RL 训练数据）；
  settings 加 rl_bandit_enabled（默认关）。新增 tests\test_sp16_bandit.py。
- [x] **A-SP16.2 TLS 指纹隐身**（core\http_client.py 扩展 + core\anti_detection.py）——
  curl_cffi 可选后端 impersonate="chrome"（JA3+HTTP2 指纹+头序），缺依赖自动降级
  aiohttp/http2；settings 加 http_impersonate（默认关）；反检测策略链可挂伪装通道。
  新增 tests\test_sp16_impersonate.py。
- [x] **A-SP16.3 调用链上下文**（新 code\graph.py + code\engines findings 增强）——
  tree-sitter 可选 AST 调用链图，计算 semgrep/codeql finding 的 sink 可达性
  （request 入口 -> 危险函数）；缺依赖降级纯 stdlib 符号索引；finding 增
  reachability 证据字段（不新增误报）。新增 tests\test_sp16_callgraph.py。

### §12 完成记录（2026-09-06，A 线三项全部完成并勾状态收口；B 线 SP15 合流并行不受影响）
- A-SP16.1 RL 决策层：新增 ai\v100\bandit.py（ContextualBandit：Thompson 采样浮/降权，clamp 1..10，可选 JSONL 反馈飞轮）；smart_queue 注入 bandit，入队动态调权，complete_task(success=False) 回注 fail 样本（成功不降权，保守策略）；orchestrator 发现漏洞回注 hit 样本；settings 加 rl_bandit_enabled/influence/feed_dir（默认关）。新增 tests\test_sp16_bandit.py（11 用例）。
- A-SP16.2 TLS 指纹隐身：新增 core\impersonate.py（curl_cffi 可选后端，impersonate浏览器指纹+ 超时 retry + 会话复用）；scanner.safe_request 通道排序 impersonate > http2 > aiohttp，缺依赖/失败自动降级；settings 加 http_impersonate/http_impersonate_browser（默认关）。新增 tests\test_sp16_impersonate.py。
- A-SP16.3 调用链上下文：新增 code\graph.py（tree-sitter 可选 AST 定义表，缺失自动降级纯 stdlib正则符号索引；同文件调用图 + BFS 入口可达性判定 reachable/unreachable/unknown；unknown 不写字段不参与判定，零新增误报）；static_audit 审计全量完成后统一 enrich，finding 增 abs_path + reachability 证据字段（settings.scan_callgraph 默认关）。新增 tests\test_sp16_graph.py（11 用例）。
- 回归：SP16 专项 3 文件 33 用例全过；全量回归仅 2 项已知环境抖动 （test_usage_ledger 模型调用失败，非本次改动引入）；清除了根目录残留 _tmp_poll/_tmp_verify（守卫 test_layout_guard 复过）。

## 13. R2-A 批次收口（2026-09-06，A 线代收原线在途改动，纯增量）
> 背景：浏览器 render 流 / Burp 流量流此前只做被动采集，未回注任务生成；漏洞报告缺来源溯源（无法区分 D3.5 挖参命中与实时采集命中）。本批补齐双源回注 + 溯源可视化，并桥接 SP15.2 参数池回灌缺口。纪律不变：全部开关默认关 / 短路零成本 / 异常全吞绝不影响主流程。

### R2-A S1 采集点全局回注（render / burp 两源 -> LiveIntake）
- modules/live_intake.py：新增进程级单例 feed_live() + pending/drain_pending 机制（无 emit 回调的同步采集上下文 -> 任务进 pending，由 orchestrator 本轮统一异步入队）；开关关/无实例立即短路返回 None。
- modules/recon.py：crawl_same_origin 浏览器渲染流（playwright 通道）解析 query 参数回注；
- ai/burp.py：_feed_live_from_history 逐条回注 Burp 历史流（非法 URL/脏数据跳过）；
- ai/v100/orchestrator.py：_feed_live_intake 前置 drain_pending 统一入队 + 登记全局单例。

### R2-A S2 漏洞来源溯源可视化
- core/report_generator.py：_source_badge/_source_label/_render_source_attribution_section，HTML 报告单条溯源徽标 + 全报告来源分布段，Markdown 报告单条溯源行 + 分布段；未知 source 兜底灰标，无来源不渲染。

### R2-A 桥接 backfill_param_mining
- ai/v100/phases/phases_recon.py：D3.5 参数池(param_candidates.jsonl) 回灌 brief[param_mining]（enable_param_mining 开关；坏行/缺字段过滤；池缺失优雅跳过；幂等合并交给 brief_param_mining）。

### 完成记录（2026-09-06，A 线代收）
- 测试：tests/test_live_intake.py +6（feed_live 短路/两源/emit 直抛/低分去重/重复注入面）、tests/test_sarif_attack_graph.py +7（badge/分布段/HTML/MD 渲染）、tests/test_param_pool_backfill.py +4（默认关/回灌/脏行/缺池）——17 例全绿；
- 全量回归：仅剩 2 例已知 usage_ledger 并发抖动（单跑通过）；unclosed session 警告来自既有 TestPocArtifacts 用例（PoC 产物链路），非本批引入，单列记录待后续清理；
- 本批含此前 SP16.1 orchestrator 的 bandit 接线（同文件混动，随本批落盘）。

## 14. SH17.1 阶段预算（per-phase wall-clock 超时，2026-09-06，A 线）
> 背景：真扫联调时 600s 顶层 CLI 超时被杀；任务级已有预算（executor 240s/任务）但挡不住任务多——30 任务 x 240s + 队列/AI 90s 链式调用让总时长可冲十几分钟，只能顶层一刀切（不知道卡在哪、该加多少）。用户提议：不给阶段整体极大放宽，而是每个阶段内对具体进程/子步骤独立设限——即补「阶段预算层」。

### 设计（默认值启用，逐项 env 可覆盖，<=0 不限制）
- settings：phase_timeout_{recon,taskgen,scan,chain_router,react_deep_dive,agent_coordinator,extras,verify,report}_s + phase_timeout_fallback_s 兜底；默认 recon 300 / taskgen 180 / scan 900 / chain_router 90 / react_deep_dive 180 / agent_coordinator 120 / extras 240 / verify 420 / report 120。
- orchestrator：__init__ 按 _STAGES 读取预算；_run_phase_timeboxed(name, coro) 用 asyncio.wait_for 包裹，超时只中断本阶段（phase_timeouts 记录 + log），跳过后继续后续阶段，不整扫报废；extras/verify 两处多分支块抽 _run_extras_block/_run_verify_block 统一受管。
- 报告：report["phase_timeouts"] 落盘实际命中的阶段超时清单（账本可查，与 _phase_timings 对齐）。

### 完成记录（2026-09-06）
- tests/test_phase_timeboxed.py 7 例全绿（默认配置/预算内执行/超时跳过/无预算透传/不污染后续阶段/run() 全 stage 包装完整性）；orchestrator 相邻测试 35 例全绿；
- 全量回归 0 新增；真扫验证见 §12 联调记录（真扫按阶段账本推断卡点，不再 600s 顶层猜）。

## 15. SP17 大批次（4 项能力补齐，2026-09-06，A 线 4 路并行）
> 并行模式：4 个后台 Agent 同时开工，文件级零重叠（每线独占文件+独立测试），主线程收口。

### 15.1 RL 反馈飞轮（SP17.1）
- bandit_report.py（新）：JSONL 反馈样本聚合报表（by_engine/top_combos，JSON+人读双出）；
- bandit_train.py（新）：真实样本训练轻量策略（baseline 判定 boost/penalty/hold，calibrated_influence 按样本量 1/2/3）；
- bandit.py：ContextualBandit.from_policy/load_policy（策略命中组合优先按 action 调权，未命中回退 Thompson，未加载零回归）；
- cli.py：bandit-report / bandit-train 两子命令；
- 测试 test_bandit_flywheel.py 9 例 + test_sp16_bandit.py 兼容；

### 15.2 调用链二期（SP17.2）
- graph.py：import_index（纯 stdlib 正则解析绝对/相对导入）、build_cross_graph（module.func 跨文件调用图，别名归一化）、entry_reachability/enrich_findings 新增 cross/use_cross 可选参数（缺省与旧版逐字一致）；
- static_audit.py：scan_callgraph 开启时 enrich_findings(use_cross=True)（主线程集成）；
- 测试 test_sp17_callgraph_cross.py 13 例 + test_sp16_graph.py 兼容；

### 15.3 TLS 指纹链（SP17.3）
- settings：http_impersonate_pool/rotate/http2 三配置（默认 rotate 关=SP16.2 单例路径零回归）；
- impersonate.py：ImpersonatePool（线程安全轮换池，命中保持 hit_streak_keep=3、失败切换）、get_impersonate_pool 单例、http2_fingerprint 指纹概要，scanner.py 免改；
- 测试 test_sp17_impersonate_pool.py + test_sp16_impersonate.py 14 例；

### 15.4 企业级报告（SP17.4）
- report_generator.py：build_distribution（type x severity 交叉统计+ranked_targets）、suggest_remediation（四级修复模板，已有 remediation 时 append 不覆盖）、enrich_report 注入 HTML/Markdown/SARIF 三路径（只增键不改既有键）；
- 测试 test_sp17_report.py 14 例 + 既有报告相关 123 例；

### 15.5 收口
- SP17 专项 78 例全绿（7 个测试文件：SP16 x 3 兼容 + SP17 x 4 新增）；ruff 新文件 14 项自动修复清零（存量错误不动）；
- 全量回归结果与提交见上（§12-§14 同栏记账表迁移至 git log）。

## 16. SP18 大批次（2026-09-06，A 线 6 路并行 + 主线程收口）
> 并行纪律：每线独占文件 + 独立测试；CLI 接线路主线程统一做（避免多线并发写 cli.py）；settings 预算应用主线程统一做。

### 16.1 商业化（SP18-1）
- core/archive.py（新）：build_scan_archive（归档报告 JSON/HTML/CSV + ARCHIVE.md 清单）、zip_archive（整体打包）、batch_targets（多目标批量规划，同 host 串行/异 host 并行、热点串行纪律）；
- cli：archive 子命令（--scan-id/--report/--out-dir/--zip）；
- 测试 test_sp18_archive.py 7 例。

### 16.2 数据飞轮（SP18-2）
- ai/v100/bandit_flywheel.py（新）：run_flywheel（多 feed 文件聚合 + min_new_samples 防抖，样本足才重训并写策略）；
- cli：flywheel 子命令；
- 测试 test_sp18_flywheel.py 5 例 + test_bandit_flywheel 兼容。

### 16.3 能力深化：编排可观测（SP18-3）
- orchestrator.py：chain_router/react_deep_dive/agent_coordinator 三协调阶段补 phase_timings 记账（启用才写，关闭不写假 0；墙钟 49% 未归因问题解除）；orchestration_ledger() 决策账本（耗时 + 路由/深潜/派发计数）；report["orchestration"] 只增键；
- 测试 test_sp18_orch_observability.py 5 例 + test_phase_timeboxed 兼容（12 例）。

### 16.4 报告导出补齐（SP17.4.3 认领项）
- report_generator.py：export_csv（UTF-8 BOM Excel 友好）、export_pdf（weasyprint→reportlab 双后端，未装优雅降级 None + warning）；
- 测试 test_sp17_export.py（37 passed 1 skipped，skip=依赖未装预期）。

### 16.5 模型链路根因修复
- 根因：provider_failover 模块级全局单例把熔断状态带进 pytest 会话——一次真实失败 3 次后 zhipu 熔断 OPEN，后续用例被直接跳过，终态 last_error=None 抛误导性“所有模型调用均失败: None”；
- 修复：ai/core.py 区分“真失败”vs“被熔断跳过”并给可操作指引（熔断清单/查 Key/网络/AI_MODE=0 逃生）；test_usage_ledger 用隔离熔断器 + 清黑名单 fixture + 新增熔断回归用例；.env.example 注释占位 Key 并提示 AI_MODE=0；
- 结果：test_usage_ledger 7 例全绿（原 2 红根治），c1/c2/c3 42 例无破坏。

### 16.6 阶段预算默认值校准
- 依据 3 份真扫账本（metrics_20260906_02/034630/034723）校准：recon 300→240 / taskgen 180→60 / scan 900→600 / verify 420→120 / report 120→60（中位数远低预算收紧，深扫 152 引擎 130s 仍有余量）；chain_router/react_deep_dive/agent_coordinator/extras 0 样本维持现状（现已被 16.3 补记账，下期可再校准）；

### 16.7 收口
- SP18 专项 33 例 + SP17 相关全部全绿；CLI 冒烟：bandit-report/flywheel/archive 输出正确；全量回归（见提交说明）；TASKLIST §16 增量记录。

## 17. SP19 深度链路实扫补全（2026-09-06，A 线 3 路并行，文件零交集）
> 前提：SP18 收口提交 6448fc7 后，盘出 deepsec 深度链路遗留 3 处真实 TODO 桩（sqlmap 结果解析 / POC 验证 / RCE 确认），其余 NotImplementedError 均为抽象基类方法非桩。

### 17.1 sqlmap 结果解析补全（SP19-1）
- sqlmap_wrapper.py：available databases 列表解析（内联逗号 + 多行 [*]/缩进记录，去重保序）；SQLMap JSON 完整解析（data[].value 抽 banner/current_db/current_user/databases/tables/columns/dump 前 5 行，兼兼容 {db:{tables:{tb:{entries}}}} 结构，坏 JSON/缺键优雅降级不抛错）；check_waf 关键词表识别 WAF 类型（cloudflare/akamai/modsecurity/f5/aws/imperva/barracuda/safedog/宝塔/阿里云/腾讯云/360，无命中回退含 WAF 行文本）；
- 测试 test_sp19_sqlmap_parse.py 19 例。

### 17.2 POC 通用验证逻辑（SP19-2）
- poc_generator.py：_generate_generic 按 vuln_type 分支生成 verify() 验证代码（sql 错误特征 / xss 反射回显 / rce 命令回显 / ssrf 云元数据特征 / unknown 探测兜底），POST 方法分支（requests.post data=params）；生成脚本均 compile 通过；
- 测试 test_sp19_poc_verify.py 7 例 + test_poc_generator 6 例回归。

### 17.3 exploit_chain RCE 确认（SP19-3）
- exploit_chain.py：_exploit_rce dangerous 模式每条命令成功判定（非空且无 not found/failed/error/timeout 标记），新增 rce_confirmed/commands_tried/commands_confirmed 键（只增键），evidence 只留有效回显，全败标注未确认；execute_command 异常兜底结构完整；清理 2 处方法内 TODO + L219 过时 TODO；
- 测试 test_sp19_rce_confirm.py 4 例 + danger_guard/attack_graph/skill_payload_bridge/sprint3 49 例回归。

### 17.4 收口
- SP19 专项 30 例全绿 + 相关回归 74 例全绿；新增行 emoji 红线复核通过（存量 emoji 未动）；TASKLIST §17 增量记录。

## 18. SP20 分布式模块测试补齐（2026-09-06，A 线 3 路并行，文件零交集）
> 前提：SP19 提交 72a9075 后全量 TODO 扫描仅剩 worker.py 1 处过时注释（_execute_node 已实现真实 DAG 执行）；盘出 distributed 模块（--distributed 已接线 master/worker/scan 三模式）零测试覆盖，补齐。

### 18.1 worker 线（SP20-1）
- worker.py：清理 execute_task 内过时 DAGNode 骨架注释（5 行注释 + 1 行死代码 task.get("params")），逻辑未动；
- 测试 test_sp20_worker.py 7 例（mock Redis 不连真库：pull_task 消费组/TTL 过期 ACK/空队列、execute_task 真实走 NODE_EXECUTORS[subgraph] 链路、未知类型 failed、report_result ACK+结果入队、get_stats）。

### 18.2 master 线（SP20-2）
- 测试 test_sp20_master.py 21 例：submit_task/submit_batch（xadd 序列化、缺 id 自动生成、ttl 默认 660）、register_worker/heartbeat/check_workers（alive/dead 划分）、get_result（轮询超时/命中/失败态）、handle_dead_worker（assigned 回收 + pending 重投递双分支）、start_monitor/stop、get_cluster_status（xlen 异常降级）；master.py 只读未改。

### 18.3 redis_backend 线（SP20-3）
- 修复真 bug：RedisContext 的 asyncio.Lock 不可重入，update/get_and_clear/get_all 在持锁中嵌套调用 get/set → Redis 路径必然死锁；改为持锁内直接操作 _redis（get/set/deserialize），语义等价；
- 测试 test_sp20_redis_backend.py 39 例（双路径：降级内存 fallback 11 例 + 降级锁定不重连 + Redis 路径序列化 12 例 + update 合并 4 例 + 单次失败降级 3 例 + 序列化 round-trip 8 例）。

### 18.4 收口
- SP20 专项 67 例全绿 + 全量回归通过（清理根目录遗留 _tmp_lock_check.py 后）；新增行 emoji 红线复核通过；TASKLIST §18 增量记录。

## 19. SP21 验证批次（2026-09-06，A 线 2 路并行验证 + B 侧合流勾选确认）
> 前提：SP20 提交 24d30ae 后必做任务清零，剩余仅验证类/合流确认，一次性并行收尾。

### 19.1 PDF/CSV 导出真实验证（SP21-1）
- 环境：装 reportlab 5.0.1（纯 Python 无系统库依赖）；卸载坏 weasyprint 69.0（Windows 缺 libgobject GTK 系统库，顶层 import 即 OSError，且 export_pdf 用 find_spec 探测造成假阳性——weasyprint 优先导致 reportlab 后端永远走不到，与 test_sp17 的真实 import 探测逻辑不一致，是 PDF 用例长期 skip 的根因）；
- 验证：export_pdf 真实生成 2347B %PDF magic 文件（reportlab 路径走通）；export_csv UTF-8 BOM 头 EF BB BF + csv.reader 读回表头/中文无损；
- 新增 tests/test_sp21_export_real.py（PDF skipif reportlab 不可用 + CSV 恒跑）；test_sp17_export 6 例从 skip 变全绿，共 8 passed。

### 19.2 CLI 全子命令冒烟（SP21-2）
- 11 个子命令实测（scan/setup/code/health/mcp/verify/tools/bandit-report/bandit-train/archive/flywheel）全部 --help 退出码 0；
- 离线端到端：mcp token 43 字符、bandit-report（8 样本/2 组合/引擎分布）、bandit-train（policy combos 生成，n<5 组合不进策略防过拟合）、flywheel（首跑 ran=true，二次同样本 ran=false 属防抖设计）、archive（ARCHIVE.md + zip 748B 双条目）、health 全绿；无 Traceback；
- 临时产物已清理。

### 19.3 B 侧合流勾选确认
- B 线 3 项（B-SP15.1/2/4 OOB 自证 + 挖掘器真扫自证 + recon_brief 回灌）已在 TASKLIST 勾选 [x]，对面交付；合流联调历史上已完成（见 §11.2 记录），本批次同步确认勾选状态。

### 19.4 收口
- 真扫联调按用户指示跳过（SP15-SP20 全部离线专项 + 全量回归已覆盖链路）；TASKLIST §19 增量记录。

### §19.5 SP21.2 动态补测任务宽限窗口（2026-09-06，A 线；B 侧 §11.3 观察项收口）
- 背景：B 侧真扫联调记录唯一未闭环环——param_mining 回灌补测任务 task_22 撞 attack 阶段固定墙钟预算（attack_node_budget=130s）被 fail_all_pending 误杀判败出队（调度预算观察项，修正归 A 线）。
- 根因：`_deadline_enforcer` 固定 sleep(attack_budget) 后无条件清空队列；动态补测任务（param_mining / live:*）在阶段中后期才入队，天然排在静态计划任务后，最易被墙钟砍掉。
- 修复（零回归，无受保护任务时行为与旧版完全一致）：
  - smart_queue.py：新增 `is_protected_task()`（source 前缀 param_mining / live:）；`fail_all_pending(reason, protect=True)` 保留受保护任务（pending+queue 均保留）；`protected_pending_count()`；
  - phases_executor.py：`_deadline_enforcer` 先 protect=True 清普通任务，存在受保护任务时给宽限窗口（attack_dynamic_grace_s 默认 45s，getattr 带默认不落 settings）再全清；`_run_one_task` 预算耗尽时受保护任务不直接判败，给 min(60, grace) 上限；
  - 新增 tests/test_sp21_deadline_grace.py 10 例（保护判定/保留/全清/零回归/宽限全流程），test_phase_timeboxed 9 例相邻回归全绿；ruff 新增文件 0 错误。
