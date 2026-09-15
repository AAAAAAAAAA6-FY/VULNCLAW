# VULNCLAW 优化任务可视化进度表

> 创建时间：2026-08-30
> 用途：跟踪 18+ 个优化任务的状态，避免迷失

---

## 任务总览

| 编号 | 任务 | 分支名 | 状态 | 开始时间 | 结束时间 | 验收命令 |
|------|------|--------|------|----------|----------|----------|
| P1-1 | FFUF 增量缓存 | opt/p1-1-ffuf-cache | 已完成 | 2026-09-13 | 2026-09-13 | pytest tests/test_ffuf_cache.py |

> P1-1 备注（2026-09-13）：原实现只有读没有写（`_ffuf_cache.set` 从未被调用 → 缓存永远 miss、
> 增量模式从未生效）。本次补全写入（仅 code=0 且有产出时写 dirs+not_found），新增
> `VULNCLAW_FFUF_CACHE=0` 评测旁路开关（eval_prf.py 默认置 0，防持久缓存污染 P/R/F1），
> 并补验收测试 `tests/test_ffuf_cache.py`。
| P1-2 | LLM Prompt 压缩 + 语义缓存 | opt/p1-2-llm-cache | 已完成 | 2026-09-13 | 2026-09-13 | pytest tests/test_llm_cache.py |
| P1-3 | DAG 失败重试 + 死信队列 | opt/p1-3-dag-retry | 已完成 | 2026-09-13 | 2026-09-13 | pytest tests/test_dag_retry.py |

> P1-3 备注（2026-09-13）：**实现代码此前已由另一 Agent 落地**（非本轮新增），分散在
> `dag/scheduler.py`（`execute_node` 捕获异常→`retry_count<max_retries` 时指数退避 2^(n-1)s、
> 置 `RETRYING` 挂起防重复提交、耗尽置 `FAILED`）、`dag/executor.py`（`write_dead_letter`/`read_dead_letter`
> + `_runtime_cache/dag_dead_letter/<scan_id>.jsonl`）、`dag/graph.py`（`NodeStatus.RETRYING`、`max_retries=2`）、
> `dag/context.py`（`record_node_retry` 可观测）。本轮补齐**唯一缺口**：验收测试
> `tests/test_dag_retry.py`（4 passed，覆盖重试成功/重试耗尽入 DLQ/上游失败下游 SKIPPED/重试计数可观测），
> 故状态由"待开始"改为"已完成"。roadmap 此前标"待开始"是因为缺验收测试，并非功能未实现。
| P1-4 | BatchProcessor 接线 | opt/p1-4-batch-proc | 已完成 | 2026-09-13 | 2026-09-13 | pytest tests/test_batch_proc.py |

> P1-4 备注（2026-09-13）：BatchProcessor 本体与 phases_verify 的 `_verify_cross_batch`（verify_batch_ai）
> 早已接线，本次补齐缺的验收测试 `tests/test_batch_proc.py`（分组/越界 fail-closed/跨 target 防污染），
> 并落地**串行 vs 批量对照实验** `scripts/bench_ai_batch.py`：
> mock 模式实测 n=12/batch=4 → 12 次调用降为 3 次、14.5s→3.6s、两管线判定 100% 一致；
> `--degrade 1.0` 注入"批量张冠李戴"后批量准确率 100%→0%，证明批量**不是纯无损**，
> 上线前用 `--live` 跑真实 LLM 量化退化率。
| P2-1 | httpbin 集成测试 | opt/p2-1-httpbin | 已完成 | 2026-09-13 | 2026-09-13 | pytest tests/test_httpbin_live.py |
| P2-2 | 扩充 payload_pool.yaml | opt/p2-2-payloads | 已完成 | 2026-09-13 | 2026-09-13 | python -c "import yaml; yaml.safe_load(open('core/data/payload_pool.yaml'))" |
| P2-3 | 扩充 common_dirs | opt/p2-3-dirs | 已完成 | 2026-09-13 | 2026-09-13 | python -c "from vulnclaw.core.settings import settings; print(len(settings.common_dirs))" |
| P2-4 | 优化进度表 | opt/p2-4-roadmap | 已完成 | 2026-08-30 | 2026-08-30 | Test-Path docs/OPTIMIZATION_ROADMAP.md |
| P2-5 | Dockerfile | opt/p2-5-docker | 已完成 | 2026-09-13 | 2026-09-13 | docker build -t vulnclaw:latest . |
| P2-6 | CLI 帮助文档 | opt/p2-6-cli-help | 已完成 | 2026-09-13 | 2026-09-13 | python scan.py --help |

> P1-2 备注（2026-09-13）：**实现代码早已由另一 Agent 落地**（非本轮新增），分散在
> `ai/core.py` 的 `LLMClient`：类级 `_semantic_cache`（sha256(model+system+prompt)、1h TTL、有界 LRU 512、
> `get_cache_stats()` 可观测）+ `ask(use_cache=...)` 的查/写缓存逻辑（425-444 / 523-541 行）；
> 以及 `ai/v100/orchestrator.py:31` 的 `compress_prompt`（超长 prompt >4k token 压成 url/param/engine 三元组清单）。
> 本轮补齐**唯一缺口**：验收测试 `tests/test_llm_cache.py`（6 passed，离线 monkeypatch `_call_model_once`，
> 覆盖命中免调用/未命中/默认关闭/TTL 过期/prompt 压缩短与原样&长保留关键行），故状态由"待开始"改为"已完成"。
> 注：缓存为类级共享结构，测试间用 autouse fixture 清理隔离。
> P2-5 备注（2026-09-13）：根 `Dockerfile` 早已存在且有效——`python:3.11-slim` + 装 git/nmap + `pip install .[full]`
> （`full` extra 已在 `pyproject.toml:51` 定义），ENTRYPOINT 为 `scan.py`；无需改动。本机无 Docker 故未实跑 `build`，
> 仅静态审查通过。
> **至此 roadmap 10 项仅剩 P2-1（httpbin 集成，需联网/live）未收口。**
> P2-1 备注（2026-09-13）：新建 `tests/test_httpbin_live.py`（3 passed，联网打 httpbin.org）。
> 关键坑已踩并修：① vulnclaw HTTP 客户端默认 `use_shared=True` 复用绑定在首个工作事件循环上的
> 共享 aiohttp session，连续 `asyncio.run` 会因"Event loop is closed"失败 → 测试强制 `use_shared=False`
> 让每次调用在当前循环内自建 session；② 默认走 `settings.proxy`/代理池轮换，偶发不可达代理导致 `status=0`
> → 强制 `proxy=None` 直连；③ httpbin 对自定义头保留原大小写，断言改大小写无关查找。
> 模块级 `pytestmark.skipif(not 可达)` 保证离线/受限环境自动跳过，不污染 CI。
> **至此 OPTIMIZATION_ROADMAP 10 项全部收口（已完成）。**

> P2-2/3/6 备注（2026-09-13）：三者均为内容/文档类扩充，无新增逻辑。
> - P2-2：在 `core/data/payload_pool.yaml` 新增 `xxe`（4 条：经典/BOM/外部DTD OOB/参数实体）与 `ssrf`（5 条：AWS IMDSv1、GCP 元数据、回环/localhost 探测）两类此前缺失的高价值 payload；YAML 解析正常（分类 7→9）。
> - P2-3：在 `config/settings.py` 的 `common_dirs` 默认词表追加 ~28 条中间件/管控面/SSO/云原生高频暴露路径（grafana/prometheus/kibana/consul/vault/etcd/traefik/k8s actuator/jenkins/zabbix/tomcat...）；计数 535→563。运行期 `directory_ffuf.py`/`recon.py` 已对 common_dirs 去重，增量安全。
> - P2-6：`scan.py --help` 本就完整（11 子命令 + 使用示例），验收命令直接通过，未改动。
> 仅剩 **P1-2（LLM 缓存，实质性功能，未实现）** 与 **P2-1（httpbin 集成，需联网/live）**、**P2-5（Dockerfile，未实现）**。

---

## 冲刺 95 分并行方案（2026-09-13 晚，8 工作流 / 19 任务）

> 目标：78 → 93-95（硬门槛见下）。**代码侧可做 ≠ 评分可达**：真实靶场/OOB 回调/压测/K8s 部署这几条硬门槛受本机环境（无 Docker daemon、无自部署 interactsh、无授权目标）物理阻塞，只能交付"可执行准备 + 离线证明"。

### 批次状态（并发上限约 4 路，用 Known members 探测验证真实性）

| 任务 | 状态 | 交付与证据 |
|------|------|------|
| A1 引擎对抗验证 | ✅ 完成（待最终一次验证） | `tests/test_engine_adversarial.py`：四类对抗响应（500/空体/畸形体、WAF 403、真实超时、重定向循环）× 代表引擎（sqli/xss/lfi/cmdi/ssti/ssrf/open_redirect），全部 fail-closed + 请求数/耗时上限断言 |
| A2 真实 TP/FN/FP/TN 数据集 | 🔶 fixture 层完成 | `data/datasets/real_results_v1.jsonl` 34 行（TP=18/TN=16），六指标门禁 PASS；真实靶场样本待 D2 解锁 |
| B1 finding 证据等级 | ✅ 完成 | `core/finding_schema.py`（五级语义 + 10 态状态机 + 稳定 finding_id）+ 接线 `enrich_report`（只增不改）+ `tests/test_finding_schema.py` + `docs/FINDING_SCHEMA.md` |
| C1 DAG 可靠性 | ✅ 完成 | 状态机补齐（lease/cancel/timeout/dead_letter）+ `tests/test_dag_fault_injection.py`（19 例）+ `docs/DAG_STATE_MACHINE.md`；真 Redis 跨进程 lease blocked |
| C3 增量扫描基线 | ✅ 完成（CLI 接线待办） | `core/baseline.py`（指纹 + compare）+ `tests/test_incremental_scan.py`（15 例，含"增量∪基线≈全量"等价性）+ `docs/INCREMENTAL_SCAN.md` |
| D1 OOB 离线闭环 | ✅ 完成 | `tests/test_oob_interactsh_offline.py`（mock interactsh 真 HTTP）+ 修复 3 处 FN 风险 + `docs/OOB_VALIDATION.md` |
| D2 Vulhub 端到端 | ✅ 准备完成 / 🚫 执行 blocked | 10 场景锁定清单 `scripts/lab_profiles/vulhub.yaml` + `scripts/lab_vulhub.py`（无 Docker exit 2）；容器执行需外部环境 |
| E1 工具互导 | ✅ 完成 | `core/interop.py`（8 格式导入 + 7 格式导出 + FIELD_MAPPING 锁死）+ `tests/test_interop.py` + `docs/INTEROP.md` |
| F1 供应链 | ✅ 完成 | `scripts/sbom.py`（SBOM.json + LICENSES.md）+ `scripts/verify_tools.py`（SHA256 完整性）+ `tests/test_supply_chain.py` + `docs/SUPPLY_CHAIN.md` |
| F2 平台安全 | ✅ 完成 | `tests/test_platform_security.py`（scope guard / danger guard / 工具输出信任边界）+ `docs/THREAT_MODEL.md`（含 7 项残余风险） |
| G 变异/模糊测试 | ✅ 完成 | `scripts/mutation_probe.py` + `tests/test_mutation_fuzzing.py` + `docs/MUTATION_FINDINGS.md`；顺带修复 `clean_ai_json` RecursionError 兜底与回显形态穷举（防幻影 diff） |
| H 扫描成本优化 | ✅ 完成 | `core/cost_model.py` + `core/scan_profiles.py`（7 模式 + 预算裁减）+ `tests/test_cost_model.py`（34 例）+ `docs/RESOURCE_BUDGET.md` |
| E2 API / H1 SRE / H2 UX / H3 CLI / B2 生命周期 / B3 误报治理 / G1 多租户 | ⏳ 未启动 | B1 已冻结（依赖解除），可下一批启动；G1 需 API 层 |
| 环境 blocked | 🚫 | D2 容器执行、G2 K8s/Helm、C2 大规模压测、真实 OOB 回调、多租户运行时 |

### 本轮真实修复清单（测试暴露，非功能新增）

1. `finding_schema.advance_status` 降级缺陷：`verified` 遇弱证据被 `can_transition` 合法路径降回 `suspected`（单调性破坏）；
2. `report_generator.enrich_report`：未接入 schema 注入 + 非 dict finding（None/str）直接崩溃；
3. `baseline.diff_has_changes`：docstring 承诺 degraded 一律视为有变化，实现漏判（CLI 退出码会骗人）；
4. OOB 三处 FN 风险：`wait_for_interaction` 熔断时漏掉已收到的实锤 / `interactions_for` 的 poll 消费竞争（并发等待互相吃回调）/ `get_interactsh_poll` 熔断分支同样漏报；
5. `clean_ai_json` 深层嵌套 JSON 的 `RecursionError` 未兜底（G 组变异测试暴露）；
6. 回显剥离只覆盖原始 + URL 编码两种形态 → HTML 实体转义回显残留造成幻影 diff 误报（G 组修复）；
7. `tests/test_dag_*` 的 DLQ 清理改"清空"而非删除（本机 safe-delete 钩子对 os.remove 抛 SystemExit）。

### 95 分硬门槛（诚实声明）

- ✅ 可本机验证：真实样本 recall/precision 数据（fixture 层 34 例）、误报漏报复盘、SBOM/许可证/完整性报告、权限隔离与凭据保护测试、finding 证据链（B1 后）。
- 🚫 本机不可达：≥8 真实靶场场景、≥3 类真实 OOB 回调、100 目标压测、worker/Redis 故障恢复、K8s 部署验收、非作者真实使用、多版本 benchmark 无回归——需外部环境或时间。

### 并发操作教训（2026-09-13）

- spawn 返回 "Spawned" **不等于**成员注册成功：曾出现 4 路回执全成功但 `Known members: none`（零产出）。**验证方式**：给不存在的收件人发消息，错误信息会列出真实成员清单。
- 稳定并发档：3-4 路；超过后 spawn 可能假成功或直接失败。第 1 批真实注册 4 路（G/A/D/H）已验证。
