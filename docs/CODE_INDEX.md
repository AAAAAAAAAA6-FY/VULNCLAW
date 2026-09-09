# 编号索引地图（CODE_INDEX）

> 由 `scripts/gen_code_index.py` 自动生成，**只索引不解释**。
> 表中「上下文」直接取代码里出现该编号的那一行原文（截断 140 字符），不做臆测。
> 未来写设计文档时，按此表逐个补「编号含义」。

共收录编号 **122** 个，累计引用 **611** 处。

| 编号 | 出现次数 | 首次出现（文件:行） | 上下文（原文截断） |
|---|---|---|---|
| `A01` | 11 | src/vulnclaw/ai/v100/phases/phases_report.py:47 | "lfi": ("CWE-22", "A01:2021 – Broken Access Control", [ |
| `A1` | 1 | src/vulnclaw/engines/web_engines.py:283 | """A1 XSS 浏览器执行验证：用 headless 加载 PoC，监听 alert/confirm/prompt 弹窗， |
| `A1.1` | 2 | src/vulnclaw/modules/vuln_scanner/oob_interactsh.py:20 | A1.1 收敛：统一委托 core/oob_channel.OOBChannel（provider=interactsh）， |
| `A1.2` | 10 | src/vulnclaw/ai/dispatcher.py:218 | A1.2: Plan-then-Act——分阶段计划（recon/assume/verify/exploit）与消费游标。 |
| `A1.3` | 13 | src/vulnclaw/ai/dispatcher.py:223 | A1.3: 反思循环——策略切换次数、强制切换标志、最近执行工具（换策略时避开）与近期工具序列（信息增益衰减） |
| `A1.4` | 9 | src/vulnclaw/ai/dispatcher.py:363 | """A1.4: 预期信息增益（0~1），确定性启发式，不依赖 LLM。 |
| `A1.5` | 5 | src/vulnclaw/ai/dispatcher.py:200 | A1.5: 失败原因结构化沉淀——失败参数/类型/响应特征写入台账，下轮 prompt 必带 |
| `A1.6` | 1 | src/vulnclaw/ai/dispatcher.py:1027 | A1.6: Human-in-the-loop——危险操作走 DangerGuard 审批 |
| `A2` | 4 | src/vulnclaw/ai/v100/phases/phases_executor.py:1149 | A2: 多 Agent 协作（角色化子 Agent + 共享黑板 + 竞争协作 + 冲突消解） |
| `A02` | 2 | src/vulnclaw/ai/v100/phases/phases_report.py:89 | "jwt": ("CWE-347", "A02:2021 – Cryptographic Failures", [ |
| `A2.1` | 4 | src/vulnclaw/ai/dispatcher.py:36 | A2.1: 角色化子 Agent 配置——窄 prompt + 窄工具集，替代单一大 prompt |
| `A2.2` | 5 | src/vulnclaw/ai/dispatcher.py:100 | """A2.2: 共享黑板——子 Agent 之间通过结构化 state 通信（端点/漏洞/证据）， |
| `A2.3` | 2 | src/vulnclaw/ai/v100/phases/phases_executor.py:868 | A2.3: 多 Agent 编排模式（角色化子 Agent + 共享黑板 + 竞争协作）优先 |
| `A2.4` | 6 | src/vulnclaw/ai/dispatcher.py:2156 | A2.4: 竞争协作（默认关）——exploit 高价值目标派 2 个不同策略子 Agent，取先确认者 |
| `A2.5` | 2 | src/vulnclaw/ai/v100/phases/phases_executor.py:1156 | A2.5: 结果合并与冲突消解——按证据强度规则（severity 权重 + 证据长度 + payload/AI 判定）取强去重。 |
| `A03` | 23 | src/vulnclaw/ai/v100/phases/phases_report.py:19 | "sqli": ("CWE-89", "A03:2021 – Injection", [ |
| `A3` | 2 | src/vulnclaw/engines/web_engines.py:2317 | 沙箱/黑名单多态绕过：属性名 hex 转义绕过 __globals__ 词过滤（A3 多态变形） |
| `A3.2` | 15 | src/vulnclaw/ai/v100/orchestrator.py:1327 | """A3.2: 目标画像持久化——recon brief → 指纹画像落库，下次增量只测变化面。 |
| `A3.3` | 3 | src/vulnclaw/ai/dispatcher.py:1454 | skills 是可执行测试套路（"这类目标该怎么打"），与 A3.3 模式库（"这个框架有什么 |
| `A3.4` | 1 | src/vulnclaw/ai/memory/lessons/lesson_store.py:6 | """A3.4 教训库：记录验证阶段误报根因，供下次同目标同类型验证时查询，减少重复误报。 |
| `A3.5` | 8 | src/vulnclaw/ai/core.py:1693 | A3.5: 隐私与存储边界——记忆只存授权目标 hash+host，payload/evidence 脱敏敏感值 |
| `A4` | 7 | src/vulnclaw/ai/dispatcher.py:1509 | ---------------- A4: 上下文管理 ---------------- |
| `A04` | 4 | src/vulnclaw/ai/v100/phases/phases_report.py:104 | "file_upload": ("CWE-434", "A04:2021 – Insecure Design", [ |
| `A4.1` | 4 | src/vulnclaw/ai/dispatcher.py:684 | 【目标层摘要（A4.1 资产/经验，非全量）】 |
| `A4.3` | 3 | src/vulnclaw/ai/dispatcher.py:1267 | A4.3: 工具输出裁剪（原始 stdout 千行只入日志，喂 LLM 用摘要） |
| `A4.4` | 31 | src/vulnclaw/ai/core.py:463 | A4.4 任务分层模型路由：按 task_type 选模型档位 |
| `A4.6` | 7 | src/vulnclaw/ai/v100/orchestrator.py:154 | P5-1: SQLite 断点续扫存储（A4.6 落地） |
| `A05` | 10 | src/vulnclaw/ai/v100/phases/phases_report.py:64 | "xxe": ("CWE-611", "A05:2021 – Security Misconfiguration", [ |
| `A5` | 3 | src/vulnclaw/engines/net_engines.py:1537 | """A5-2：字段建议泄漏（suggestions）——未知字段报错若回显 suggestions / Did you mean， |
| `A5.1` | 3 | src/vulnclaw/ai/tools.py:48 | """工具基类（A5.1 统一 Tool Schema）""" |
| `A5.2` | 6 | src/vulnclaw/ai/dispatcher.py:47 | A5.2: CLI 侦察工具（本机已注册才可见） |
| `A5.3` | 3 | src/vulnclaw/ai/tools.py:456 | A6.1 / A6.2 / A5.3: 原生 Agent 工具（浏览器 / 登录 / 受控沙箱） |
| `A5.4` | 4 | src/vulnclaw/ai/tools.py:198 | 危险参数黑名单（A5.4 参数级门禁雏形）在执行前拒绝并有审计日志。 |
| `A5.5` | 8 | src/vulnclaw/core/tool_registry.py:34 | A5.5: 工具失败替代链——主工具缺失/失败时附降级路径（信息性，不改变 success 语义） |
| `A5.6` | 5 | src/vulnclaw/ai/dispatcher.py:82 | A5.6: 扫描阶段 → AGENT_ROLES 角色映射（阶段化工具裁剪的查表基础） |
| `A6` | 3 | src/vulnclaw/engines/web_advanced_engines.py:382 | """落地验证（A6 核心补强）：注入后再次请求目标/常见 API 路径， |
| `A6.1` | 2 | src/vulnclaw/ai/tools.py:456 | A6.1 / A6.2 / A5.3: 原生 Agent 工具（浏览器 / 登录 / 受控沙箱） |
| `A6.2` | 3 | src/vulnclaw/ai/tools.py:456 | A6.1 / A6.2 / A5.3: 原生 Agent 工具（浏览器 / 登录 / 受控沙箱） |
| `A6.5` | 2 | src/vulnclaw/core/auth/human_in_the_loop.py:6 | """A6.5 2FA / 验证码人工接管占位。 |
| `A07` | 5 | src/vulnclaw/ai/v100/phases/phases_report.py:180 | "cred": ("CWE-1392", "A07:2021 – Identification and Authentication Failures", [ |
| `A7` | 3 | src/vulnclaw/engines/websocket_security.py:78 | A7 增强：明文 ws:// 检测（仅 HTTPS 站点对比 wss vs ws） |
| `A08` | 2 | src/vulnclaw/ai/v100/phases/phases_report.py:79 | "deserialization": ("CWE-502", "A08:2021 – Software and Data Integrity Failures", [ |
| `A8` | 2 | src/vulnclaw/ai/v100/phases/phases_taskgen.py:882 | A8：索引缺失（全新克隆 / 未构建 / 被 .gitignore 忽略未入库）→ 离线从内置 |
| `A8.2` | 4 | src/vulnclaw/ai/v100/phases/phases_executor.py:1297 | A8.2：命中 CVE 即生成 PoC / 复现命令（nuclei -id 即权威 PoC） |
| `A8.3` | 5 | src/vulnclaw/core/report_generator.py:138 | A8.3：漏报率回归基线（已知靶场命中率持续监控） |
| `A8.4` | 3 | src/vulnclaw/ai/v100/phases/phases_taskgen.py:903 | A8.4：情报源增量更新（NVD/ExploitDB/GitHub），仅当配置了相应环境变量才联网。 |
| `A9` | 2 | src/vulnclaw/engines/auth_engines.py:1092 | A9: JWT 伪造验证（alg=none / 弱密钥） —— 主动提交伪造 Token，验证服务端是否接受 |
| `A10` | 2 | src/vulnclaw/ai/v100/phases/phases_report.py:58 | "ssrf": ("CWE-918", "A10:2021 – SSRF", [ |
| `C1` | 2 | src/vulnclaw/ai/v100/orchestrator.py:1288 | """C1 成本核算：从 LLM 客户端单例的 TokenBudget 取累计成本（美元）。""" |
| `C1.4` | 14 | src/vulnclaw/core/report_generator.py:303 | C1.4: 渲染前先落盘 PoC 产物并标注 finding（异常隔离，绝不影响报告主流程） |
| `C2` | 4 | src/vulnclaw/core/static_audit.py:8 | """SP11-C1/C2 静态代码审计通道（DeepSec 融合，Apache-2.0 聚合调用）。 |
| `C2.2` | 1 | src/vulnclaw/deepsec/priv_esc_planner.py:9 | 权限提升路径规划（C2.2，受控）—— 低权 shell → 提权点枚举 → 逐步尝试。 |
| `C3` | 5 | src/vulnclaw/ai/v100/orchestrator.py:1297 | """C3: AI 成本预算熔断。扫描阶段累计成本超预算则降级为纯引擎模式（ai_mode=0），防失控。""" |
| `C4` | 1 | src/vulnclaw/ai/v100/orchestrator.py:889 | """C4-C10 三档分级：confirm / likely / suspicious。 |
| `C9` | 7 | src/vulnclaw/ai/v100/orchestrator.py:1193 | """SH17.1：verify 阶段主体（流式停 + 全量验证 + C9/C10 后处理）。""" |
| `C10` | 10 | src/vulnclaw/ai/v100/orchestrator.py:889 | """C4-C10 三档分级：confirm / likely / suspicious。 |
| `D1` | 7 | src/vulnclaw/ai/v100/phases/phases_executor.py:68 | f"   [D1] 粘滞剔除: {key[0]}/{key[2]} 累计失败 {n} 次，后续同键任务跳过" |
| `D1.1` | 4 | src/vulnclaw/ai/v100/phases/phases_executor.py:441 | """D1.1: 孤儿协程诊断——运行中且不属于 worker/guard/spy 的任务打 WARNING 定位。""" |
| `D1.2` | 2 | src/vulnclaw/ai/v100/phases/phases_executor.py:57 | """D1.2: 记录 (engine,target,param) 失败次数，达阈值写墓碑黑名单。""" |
| `D1.3` | 2 | src/vulnclaw/ai/v100/phases/phases_executor.py:409 | f"   🚨 [D1.3] 任务滞留超过 600s: {_stale[0][0]}（回查其 engine/param）" |
| `D2` | 9 | src/vulnclaw/ai/v100/phases/phases_executor.py:30 | """D2: 引擎任务目标域硬约束（fail-closed）。 |
| `D2.4` | 2 | src/vulnclaw/ai/v100/phases/phases_taskgen.py:404 | Z1.2（=D2.4）：情报驱动——指纹组件命中 CVE 索引 → 生成高危 CVE 专项任务（数据腿闭环） |
| `D3` | 11 | src/vulnclaw/ai/v100/phases/phases_recon.py:407 | D3: 将泄露的 SourceMap URL 上报为信息泄露类 finding。 |
| `D3.5` | 6 | src/vulnclaw/ai/v100/phases/phases_recon.py:22 | """SP15.2 合流桥接（A 侧）：B 侧 D3.5 挖掘结果从池文件回灌 brief["param_mining"]。 |
| `D3.6` | 1 | src/vulnclaw/modules/request_feed.py:92 | 供任务生成侧模板聚类复用（D3.6 前置工具）。 |
| `D4.1` | 2 | src/vulnclaw/modules/request_feed.py:9 | 请求级采集抽象（D4.1）与去重（D4.3） |
| `D4.2` | 4 | src/vulnclaw/ai/v100/orchestrator.py:1376 | """SP15.3 D4.2: recon 采集端点 -> 实时补测任务入队（开关默认关, 零行为回归）。 |
| `D4.3` | 2 | src/vulnclaw/modules/request_feed.py:9 | 请求级采集抽象（D4.1）与去重（D4.3） |
| `D4.5` | 2 | src/vulnclaw/modules/live_intake.py:13 | - 评分阈值 live_intake_min_score 控噪声预算（D4.5 acq_score）； |
| `D5` | 1 | src/vulnclaw/ai/v100/phases/phases_recon.py:214 | D5: URL 价值排序——带参数/API/敏感路径的端点优先进入扫描队列 |
| `E1` | 15 | src/vulnclaw/ai/v100/orchestrator.py:139 | E1: 增量扫描——记录已扫 (engine, target, param)，下次运行跳过 |
| `E1.1` | 3 | src/vulnclaw/core/attack_graph.py:10 | - E1.1  资产-漏洞-利用链统一图模型（networkx 起步，可换 neo4j） |
| `E1.2` | 3 | src/vulnclaw/core/attack_graph.py:11 | - E1.2  攻击路径计算：起点（外部面）-> 终点（RCE/数据）加权最短路径与概率 |
| `E1.3` | 3 | src/vulnclaw/ai/v100/phases/phases_report.py:452 | E1.3: 攻击图 + TOP 攻击路径（构建失败不阻塞主报告，降级为跳过） |
| `E1.4` | 8 | src/vulnclaw/core/attack_graph.py:12 | - E1.4  ExploitChain 复用同一图模型（from_chains / 构建接口） |
| `E2` | 2 | src/vulnclaw/config/settings.py:301 | E2: Nuclei 模板分档（full=全量 / balanced=中危以上 / fast=仅高危），与 nuclei_tags_from_stack 配合提速 |
| `E3` | 6 | src/vulnclaw/ai/v100/orchestrator.py:1234 | doubted = True  # E3: 业务逻辑单点且无差分证据 → 必须复核 |
| `E3.2` | 7 | src/vulnclaw/cli.py:282 | help="E3.2: 增量扫描——只测相对上次目标画像的变化面（复用 A3.2 画像，无基线自动全量建立）。", |
| `E3.3` | 1 | src/vulnclaw/modules/recon.py:1120 | E3.3: 纯 HTTP 兜底爬虫——零外部工具依赖（方案③） |
| `E4` | 4 | src/vulnclaw/ai/v100/orchestrator.py:136 | E4: 早停——参数已确认高危/严重漏洞则跳过剩余引擎（减少无效调用） |
| `E5` | 5 | src/vulnclaw/ai/v100/phases/phases_recon.py:388 | htttps://、tps://、data: 等畸形 scheme 直接跳过，不再进入 E5/请求层 |
| `E5.1` | 6 | src/vulnclaw/config/settings.py:50 | E5.1 scope 硬约束白名单（逗号分隔：example.com 匹配自身及子域；*.*.example.com 通配；10.0.0.0/8 CIDR；精确 IP） |
| `E5.2` | 2 | src/vulnclaw/core/danger_guard.py:37 | A5.4: 工具+危险参数注册表（工具级审批粒度，配合 E5.2 联动） |
| `E6` | 1 | src/vulnclaw/config/settings.py:313 | E6: 分布式分片（无 Redis 走 fakeredis 模拟） |
| `E402` | 8 | src/vulnclaw/bootstrap.py:16 | from vulnclaw.paths import TOOLS_HOME  # noqa: E402 |
| `E914` | 2 | src/vulnclaw/engines/auxiliary_engines.py:389 | hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest() |
| `E74856` | 3 | src/vulnclaw/core/report_generator.py:23 | "Critical": ("#E74856", "🔴 严重"), |
| `SP17.4.3` | 5 | src/vulnclaw/core/report_generator.py:1524 | SP17.4.3: 商业交付导出 - CSV / PDF 双格式（A 线） |
| `SP1` | 3 | src/vulnclaw/core/sandbox_runner.py:8 | """SP1 无 Docker 自动降级沙箱链：进程级隔离执行 PoC/利用脚本。 |
| `SP2` | 4 | src/vulnclaw/core/dedupe.py:8 | """SP2 确定性去重前置：指纹去重 + 语义疑似分组。 |
| `SP3` | 7 | src/vulnclaw/core/coverage.py:8 | """SP3 机器事实覆盖账本：asset x engine x status -> coverage.json（审计口径）。 |
| `SP4` | 2 | src/vulnclaw/core/report_generator.py:1346 | SP4: E1 攻击图 -> SARIF 2.1.0 run.graphs + run.graphTraversals |
| `SP5` | 3 | src/vulnclaw/ai/core.py:71 | SP5: 连续处于降级态的每次超限调用都累计 streak（恢复后归零）， |
| `SP6` | 6 | src/vulnclaw/core/knowledge.py:82 | SP6: payload 桥种子——exploit_chain 可直接引用（三腿沉淀·静态定义腿） |
| `SP7` | 3 | src/vulnclaw/core/mcp_server.py:1284 | SP7: 逐引擎 OpenAPI 式入参 schema（常驻主链路） |
| `SP8` | 13 | src/vulnclaw/ai/core.py:400 | usage_site: Optional[str] = None,  # SP8: 成本台账调用点标签（provider×site 成本表维度） |
| `SP10` | 6 | src/vulnclaw/ai/v100/phases/phases_report.py:484 | SP10: finding 生命周期台账 + 对比分组（失败不阻塞主报告） |
| `SP10.3` | 2 | src/vulnclaw/core/finding_lifecycle.py:227 | 报告分组（SP10.3 治理台账视角） |
| `SP11` | 2 | src/vulnclaw/core/static_audit.py:8 | """SP11-C1/C2 静态代码审计通道（DeepSec 融合，Apache-2.0 聚合调用）。 |
| `SP14` | 1 | src/vulnclaw/modules/recon.py:1813 | 入池格式（SP14 接口约定，消费方 = A 线 request_feed / 参数池 / 任务生成）: |
| `SP14.1` | 4 | src/vulnclaw/config/settings.py:404 | ---- D3.5 参数挖掘（SP14.1，A 线；探测/消费两侧各自独立开关）---- |
| `SP14.2` | 1 | src/vulnclaw/modules/request_feed.py:18 | 设计约束（SP14.2 验收）： |
| `SP14.3` | 8 | src/vulnclaw/core/oob_channel.py:200 | channel: str = ""       # SP14.3-B：解析出的通道 provider（interactsh/dnslog），随证据链传递 |
| `SP15` | 3 | src/vulnclaw/core/oob_channel.py:479 | SP15-B 自证口径：任何回查异常（含超时/网络抖动）一律返回空，绝不抛错 |
| `SP15.1` | 1 | src/vulnclaw/engines/base.py:99 | """SP15.1 合流适配：OOB 证据查询的双接口统一入口。 |
| `SP15.2` | 3 | src/vulnclaw/ai/v100/phases/phases_recon.py:22 | """SP15.2 合流桥接（A 侧）：B 侧 D3.5 挖掘结果从池文件回灌 brief["param_mining"]。 |
| `SP15.3` | 8 | src/vulnclaw/ai/v100/orchestrator.py:1376 | """SP15.3 D4.2: recon 采集端点 -> 实时补测任务入队（开关默认关, 零行为回归）。 |
| `SP15.4` | 1 | src/vulnclaw/modules/recon.py:1989 | SP15-B / B-SP15.4: recon_brief 回灌（字段与 A 侧消费完全一致） |
| `SP15.5` | 3 | src/vulnclaw/config/settings.py:409 | ---- D4.2 采集→任务实时生成（SP15.3/SP15.5，A 线；默认开，含预算软截止保护）---- |
| `SP16.1` | 8 | src/vulnclaw/ai/v100/bandit.py:8 | SP16.1 上下文多臂老虎机（轻量在线 RL 决策层） |
| `SP16.2` | 5 | src/vulnclaw/config/settings.py:417 | ---- SP16.2 TLS 指纹伪装（A 线；curl_cffi 可选后端，默认开，缺库自动降级 aiohttp）---- |
| `SP16.3` | 6 | src/vulnclaw/code/graph.py:7 | SP16.3 / SP17.2 调用链上下文（轻量符号索引 + 跨文件 import 展开） |
| `SP17.1` | 8 | src/vulnclaw/ai/v100/bandit.py:22 | - SP17.1 可选策略加载：ContextualBandit.from_policy / load_policy 加载 |
| `SP17.2` | 5 | src/vulnclaw/code/graph.py:7 | SP16.3 / SP17.2 调用链上下文（轻量符号索引 + 跨文件 import 展开） |
| `SP17.3` | 3 | src/vulnclaw/config/settings.py:420 | ---- SP17.3 TLS 指纹链（A 线；基于 SP16.2，把"单指纹"升级为"指纹链"；池默认非空+轮换默认开，仅 http2 编排位保持关闭）---- |
| `SP17.4` | 7 | src/vulnclaw/core/report_generator.py:381 | SP17.4 企业级报告增强（A 线）： |
| `SP18` | 9 | src/vulnclaw/ai/v100/bandit_flywheel.py:8 | SP18 数据飞轮：批处理入口——聚合最新反馈样本、重训策略、写新策略、给变更摘要。 |
| `SP19` | 1 | src/vulnclaw/deepsec/poc_generator.py:329 | SP19: 按漏洞类型生成 verify() 验证判断逻辑（生成代码字符串，不实际执行） |
| `SP21.2` | 8 | src/vulnclaw/ai/v100/phases/phases_executor.py:246 | （SP21.2：动态补测任务 protected 保留宽限窗口），已产出的 finding 已进 StreamVerify 队列。 |
| `SP22` | 2 | src/vulnclaw/ai/v100/orchestrator.py:1438 | SP22 变更：不再套用"远程 Agent 实际攻击"审批键 remote_deep_penetrate |
| `SP24` | 1 | src/vulnclaw/config/settings.py:191 | ========== SP24: 通用硬编码参数 env 化（超时/重试/批大小，原散落各模块的字面量统一收口） ========== |
| `SP27` | 16 | src/vulnclaw/ai/v100/phases/phases_executor.py:555 | SP27: 指令消费——排除项过滤 + 重点(target)增强（--instruction 的 Focus/Out of scope） |

## 使用说明

- 重跑：`python scripts/gen_code_index.py`（幂等，覆盖重写本文件）。
- 新增编号时无需手工登记，脚本自动收录。
- 含义解释请补在对应设计文档中，不要改本表（本表只做索引）。
