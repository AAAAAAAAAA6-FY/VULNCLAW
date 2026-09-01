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
| A1.5 | 失败原因结构化沉淀：失败参数/类型/响应特征写入短期记忆，下轮 prompt 必带 | `ai/dispatcher.py` | P1 | memory 文件出现 failure\_class 字段 |
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
| D7.2 | benchmark 剧本化：已知漏洞清单 vs 扫描发现，输出检出率/误报率/耗时三角数据（scripts/benchmark.py 扩展） | `scripts/benchmark.py` | P0 | 每次大改动后出 benchmark 对比 |
| D7.3 | 引擎级回归：每个引擎配 1 正例+1 反例 fixture，CI 强制跑 | `tests/` | P1 | 新引擎必须带 fixture 才能合入 |
| D7.4 | 检出率红线：D 组改动合并前跑 benchmark，检出率不得低于基线（红线进 CI 门禁） | `.github/workflows/ci.yml` | P1 | CI 失败即阻断合并 |

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
| E3.1 | GitHub Action 模板：PR 触发非交互扫描（对标 Strix 一行接入） | `.github/workflows/pen.yml`（模板化） | P1 | B | 模板仓库/文档可复制即用 |
| E3.2 | 增量扫描：--diff 模式只测上次以来变化面（依赖 A3.2 目标画像） | `core/persistence.py`+`cli.py` | P1 | A | 二次扫描耗时显著下降 |
| E3.3 | PR 评论机器人：扫描结论以评论形式回贴 PR（含证据链接） | `scripts/` | P2 | B | PR 上出现漏洞评论 |
| E3.4 | 内置定时调度：平台级 cron（周期重扫+告警），不依赖外部 CI | `core/`+cli 子命令 | P2 | A | `vulnclaw schedule add` 生效 |

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
