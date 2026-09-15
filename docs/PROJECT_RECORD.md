# VULNCLAW 项目统一记录

> 唯一项目状态记录入口。最后整理：2026-09-13。
> 其他 AI 先读本文，再读代码、测试和正式用户文档。

## 1. 当前事实

| 项目 | 当前值 | 事实来源 |
|---|---:|---|
| 静态引擎定义 | 80 | `scripts/engine_registry_check.py` |
| 运行时发现 | 82 | `scanner.get_engine_inventory()` |
| 运行时启用 | 80 | `src/vulnclaw/core/scanner.py` |
| 抽象类 | 2 | 运行时健康检查 |
| 普通加载失败 | 0 | 运行时健康检查 |
| 离线 fixture | 28 | `tests/fixtures/benchmark_baseline.json` |
| fixture TP/FN/FP/TN | 15/0/0/13 | `tests/fixtures/benchmark_baseline.json` |
| fixture 检出率/误报率 | 1.0/0.0 | `scripts/benchmark.py` |
| fixture evidence rate | 约 0.54 | `scripts/benchmark.py` |
| fixture reproduction rate | 0 | fixture 无 OOB/exploit 信号；统计已接五档规范字段（G4） |
| 测试函数 | 1755 | `scripts/test_coverage_audit.py` |
| 未被测试文件提及的引擎 | 39 | 最近一次覆盖审计快照 |

fixture 覆盖：反序列化、SSRF、暴露面、GraphQL/API Security、JWT、XXE、IDOR 候选、XSS、LFI、文件上传、SSTI、NoSQL。

## 2. 已完成

### 检测与请求链路

- 本地目标绕过不兼容的 HTTP/2/impersonation 路径。
- 反序列化保持 fail-closed，区分被动 `scan()` 与主动错误签名 `check()`。
- 增加运行时引擎 inventory，并接入报告和健康检查。
- 修复 fixture runner 的 GET/POST mock 清理和测试顺序污染。

### Benchmark 与 CI

- `scripts/benchmark.py` 支持 fixture/eval 两种模式。
- 支持 recall、precision、detection rate、false rate 门禁。
- 支持 evidence、reproduction、request count、elapsed time 指标。
- `.github/workflows/ci.yml` 已接入 eval 与 fixture 两类门禁。
- 最近完整 pytest 已通过；benchmark 定向回归 22 passed。

### 引擎与覆盖统计

- 静态引擎解析支持多级继承、类型标注和模块常量。
- 运行时数量统一为 discovered=82、enabled=80、abstract=2、failed=0。
- 已有离线正反例不代表真实互联网泛化能力。

## 3. 架构摘要

项目采用 `src/` 布局，核心链路为：

```text
scan.py
  -> vulnclaw CLI
  -> scanner / engine registry
  -> reconnaissance
  -> deterministic engines
  -> verification gateway / exploit verification
  -> orchestration / reporting / audit
```

主要边界：

- `src/vulnclaw/core/`：扫描器、工具注册、配置、治理、报告基础设施。
- `src/vulnclaw/engines/`：漏洞检测引擎。
- `src/vulnclaw/ai/`：编排、任务生成、验证和报告阶段。
- `src/vulnclaw/dag/`：任务图、重试和死信队列。
- `tests/`：单元、集成、靶场和 fixture 基准。
- `scripts/`：基准、靶场、审计和辅助命令。

## 4. 路线图状态

### 已完成或已有实现

- FFUF 增量缓存。
- BatchProcessor 验收测试。
- DAG retry/dead-letter 实现与验收测试。
- 引擎事实源、fixture benchmark、CI 门禁。
- payload pool 与 common_dirs 的部分扩充。

### 仍待完成

- httpbin 集成测试。
- Docker 构建与部署验收。
- 完整 CLI/生产部署文档。
- 真实多账号 IDOR/BOLA。
- SSRF/Fastjson/Log4Shell 的 HTTP/LDAP 外带验证（当前网络公共 oast 被墙，需自部署 `OOB_INTERACTSH_SERVER`；DNS 型外带已验证闭环，见 2026-09-13 记录）。
- Vulhub 真实靶场 E2E（2026-09-13 记录：本机无 WSL 发行版、Docker daemon 起不来，5 场景 revision 已锁定待 Docker 就绪重放）。
- evidence/reproduction 在真实扫描报告中的完整接线。
- 39 个未充分覆盖引擎的真实正反例。

## 4b. 2026-09-13 真实环境验证记录

### 并行组 A：真实 OOB/interactsh（本机实测）

- `tests/test_oob_channel.py` 30 passed。
- 公共 interactsh（oast.pro/live/site/online/fun/me）本机 TLS 握手被断（GFW RST，rc=1），注册失败；当前可用通道为 dnslog.cn（DNS）。
- SSRF（`http://<tok>.dnslog.cn/t`）、Fastjson（Inet4Address 反向解析）、Log4Shell（`jndi:dns://<tok>.dnslog.cn/a`）三类 DNS 型外带真实触发回调并闭环；HTTP/LDAP 未验证。
- 超时（6s→0 条）、interactsh 两败熔断 300s→降级 dnslog、目标级 6 连 miss 熔断，均实测。
- 证据链：`finding["oob_evidence"]`{ts,channel,token,detail,curl} 且 JSON/HTML/SARIF 接入；真实回调落盘 `_runtime_cache/metrics/oob_interactions.jsonl`。
- 配置建议：`OOB_INTERACTSH_SERVER=https://oob.example.com`（仅 origin、可信 TLS），写入 `.env` 后自动追加 `-server`。

### 并行组 B：Vulhub 真实靶场（本机阻塞记录）

- 本机无 WSL Linux 发行版（`wsl -l` 为空），Docker Desktop 能起 UI 但 backend/daemon npipe 始终不可用；`lab_preflight.py` exit 2 如实阻塞。未执行任何 E2E，无 fixture 冒充。
- Vulhub master 已锁定 `aeaf65793f147f29bd50841ef77f4e9cad07ecc7`（2026-09-13，源码在 `%TEMP%\vulhub`）。
- 场景清单（revision 固定后待重放）：weblogic/ssrf（image `vulhub/weblogic:10.3.6.0-2017` 端口 7001）、fastjson/1.2.47-rce（`vulhub/fastjson:1.2.45` 端口 8090 与在线 lab 冲突需改端口）、log4j CVE-2021-44228（`vulhub/solr:8.11.0` 端口 8983/5005）、struts2 s2-045（`vulhub/struts2:2.3.30` 端口 8080）、shiro CVE-2016-4437（`vulhub/shiro:1.2.4` 端口 8080）。启动/清理均为 `docker compose up -d` / `docker compose down`。
- CI 边界：全部 workflow 无 job 启动 Docker/Vulhub，fixture 门禁维持。
- 附带真实 E2E：127.0.0.1:8090 扫描（`_runtime_cache/reports/report_http___127_0_0_1_8090_20260913_111702.json`）96 findings（verified 96、cross_confirmed 6、0 FP）、total_engine_calls 686、elapsed 735s；88 项含 evidence+reproduction_steps+curl，但 `reproduced`(bool)=0；OOB `collaborator_domain=wf03km.dnslog.cn` 已配但本次 0 回调（miss_streak=6）。

### 并行组 C：真实报告体量评估（331 findings / 1.85MB，2026-09-13）

- 实测：HTML full 419KB / summary 381KB / compact 381KB；Markdown 三档均 12KB；生成耗时 <12ms。
- 硬编码问题（已修复，见下）：HTML 正文 `vulns[:50]` 将 max_findings 钳到 50；Markdown 主循环硬编码 30 条且忽略 detail/max_findings/max_evidence；summary 与 compact 处理无差别、产物完全一致。
- 字段保全：HTML 三档保留 severity/URL/parameter/evidence；MD 三档丢 parameter；summary/compact 白名单剔除 `payload`（curl 退化丢注入载荷）及 `ai_verdict/verdict/cwe/owasp/oob_evidence`（存在即丢）；MD 各档不渲染 reproduction。
- 默认参数：max-findings=50 对 331 条约留 15% 作展示上限合理但需与参数贯通；max-evidence-chars=5000 对真实数据（max 344、P99≈95）从不触发，建议降至 ~500 抑制极端长证据。
- 裁剪建议：max_findings 贯通 + 按严重性优先裁剪（排序已存在）+ max-evidence ~500 + JSON 分页可选；HTML 已用 `<details>` 折叠。

### 报告裁剪硬编码修复（2026-09-13，`core/report_generator.py`）

- HTML 正文 `vulns[:50]`→遍历 compact_report 已裁剪的展示集，full 全量渲染（`max_findings=200` 实测渲染 331 条）；底部"仅显示前 50"改为读 `reporting.hidden_count` 动态提示。
- HTML/Markdown evidence 截断改用参数 `max_evidence` 而非常量 5000。
- Markdown 主循环 `vulns[:30]`→按 `detail` 语义：full 全量、summary/compact 按 `max_findings`。
- compact_report：compact 白名单在 summary 基础上收窄（去掉 remediation/title 等扩展字段，仅留最小识别集），summary/compact 产物不再相同。
- 白名单字段保全（后续补齐）：summary/compact 白名单追加 `payload`/`oob_evidence`/`ai_verdict`/`verdict`/`cwe`/`owasp`——payload 供 curl/复现输出、oob_evidence 为带外回调实锤、判定字段为分类依据，避免裁剪后丢关键证据；compact 仅保留最小识别集 + payload/oob_evidence。三档均实测保留两项，summary/compact 仍有差异。
- 回归验证（331-finding 真实报告）：HTML full 331 条/summary 50/compact 50；MD full 331/summary 50/compact 50；summary vs compact 字段集已分歧；报告相关测试 71 项全绿。

## 工作流 1（真实 OOB/Vulhub）核查（2026-09-13）

- 已闭环（代码就位）：双 provider（interactsh 7 协议主 + dnslog DNS 备），3 层熔断（通道级 300s / interactsh 连败 2 次降级 / 目标级连续 6 次零回调跳过）；OOB 调用链：SSRF `net_engines.py:235/438`、Fastjson `framework_zero_day_engines.py:309`、Log4Shell `:222`，均走 `_run_oob_scan`→`OOBChannel`。
- 已闭环（锁定）:Vulhub revision `aeaf6579…ecc7` 与 `%TEMP%\vulhub` 快照目录名 + REVISION.txt 三处一致；weblogic-ssrf、fastjson/1.2.47、log4j solr:8.11.0、s2-045、shiro 5 个 compose 齐。
- 待资源缺口（未新建文件）：`oob_interactions.jsonl`(552 行) 全为确定性/测试数据，无真实回调证据；缺本地回环 OOB 监听器；`OOB_INTERACTSH_SERVER` 未配置（读 `os.environ`，默认空→公共 oast 被墙）；HTTP/LDAP 通道未实验证；vulhub.yaml 场景未行级 pin。
- 建议行动（依权限）：① 本地回环 listener 验证 HTTP/LDAP 通道（监听 53/1389 需管理员）→ ② 公网 VPS 自部署 interactsh 并填 `.env` → ③ WSL2+Docker 后重放 5 场景。

### 工作流 1 补缺完成（2026-09-15，仅改现有文件）

- 本地回环 OOB 闭环落地（HTTP+LDAP/TCP 双通道）：
  - `core/oob_channel.py`：新增 `LocalLDAPListener`（JNDI 盲打 TCP 回连监听，累积读取捕获第二包 search DN 中的 token）、`local_oob_ldap_base()`、`local_oob_token_seen()`、`wait_local_oob()`、`local_oob_channel()`；`enable_local_oob()` 幂等启动 HTTP+LDAP 双监听共享 hits 文件；`maybe_enable_local_oob_for_target()` 仅私网/本机目标启用。
  - 引擎接入：`engines/net_engines.py` `_test_ssrf_oob` 本地回环分支（`SSRF-OOB本地回环确认`）；`engines/framework_zero_day_engines.py` `_run_oob_scan` 本地回环分支（Log4Shell/Fastjson/Struts2 共用，JNDI ldap/rmi 载荷改写为本地监听地址，DNS 型载荷本地跳过，产出 `…(本地回环实锤)`）；`ai/v100/phases/phases_verify.py` `_poll_collaborator_callback` 增加本地 pending 闭环检查。
  - 实测通过（LOOPBACK_E2E PASS）：HTTP 回连命中、LDAP 回连（token 在第二包）命中、SSRF 引擎本地分支返回确认、框架引擎本地分支返回 `oob_evidence{ts,channel,token,detail}`（channel=ldap）；OOB/SSRF/framework 相关单测 66+89 项全绿。
  - 数据飞轮核查：`_runtime_cache/growth/feedback.jsonl` 989 条 finding 指纹已完整覆盖 `_runtime_cache/reports` 全部 131 份报告（唯一指纹 989 全覆盖，幂等跳过 14716 条）——此前已点火，无需新增导入。
- 仍缺（需外部资源）：公网 VPS 自部署 interactsh 并填 `.env`（`OOB_INTERACTSH_SERVER`）；WSL2+Docker 重放 vulhub 5 场景。

### 数据飞轮：读取端闭环接入扫描主链路（2026-09-15，方案3，仅改现有文件）

- 目标：方向2 读取端（误报抑制 + 历史 payload 供给）真正闭环进主链路，开关默认 `False` 零影响。
- 开关：`config/settings.py` `enable_growth_feedback`（`ENABLE_GROWTH_FEEDBACK`，默认 False）。
- 桥接层：`growth/bridges.py` 新增 `maybe_suppressed_signatures()`（查询通道）、`suppress_findings()`（过滤通道，dict/list 双形态）、`_active_signatures()`（mtime 缓存防高频重扫）；抑制 key 与 `feedback_ledger.suppressed_signatures()` 同口径（`<vuln_type>|<归一化参数>`）。
- 引擎双端接入：
  - `core/scanner.py` `run_engine`：返回 findings 前过滤强误报指纹。
  - `ai/v100/phases/phases_executor.py` `_execute_engine_check`：引擎命中排队进 verify 前过滤（含 task 侧 param 补位，命中即 pass；不计 hit）。
- 写盘兜底：`runners/scan_runner.py` 报告 `json_path` 落盘前再滤一遍（覆盖规则/直连/脚本等非引擎源），抑制数记入 `report["growth_stats_suppressed"]`。
- 供给端闭环：`phases_taskgen.py` 任务生成时注入历史 payload（前置已就位）；`phases_verify.py` 技术验证前 finding 无 payload 时用账本推荐 payload 补位验证（`growth_payload_source=ledger_recommend`）。
- 回归：`test_feedback_ledger.py` 13 项 + OOB/engine 相关单测 155 项全绿；bridges 冒烟验证通过（单条命中/混合列表/开关关闭原样放行）。

### 覆盖补齐：跳过引擎回滚 + 深度断言 + IDOR 多账号（2026-09-15，仅新建 fixture/e2e 脚本）

- 回滚 D 任务"跳过 4 个环境驱动型引擎"的决定并补齐 yaml（fixture 是数据集原料，`rebuild_dataset.py` 不驱动引擎，离线数据集口径下可完整表达正反例）：
  - `tests/fixtures/engines/symbolic_logic.yaml`（`SymbolicLogicEngine`，正例 `quantity_overflow_solvable` evidence `约束求解证明目标可满足`，2 反例 fail-closed）。
  - `tests/fixtures/engines/idor_dual_session.yaml`（`DualSessionOracleEngine`，正例 `cross_account_private_leak` evidence `双会话差分证实`，1 反例 403 fail-closed）。
  - `tests/fixtures/engines/tls_security.yaml`（`TlsSecurityEngine`，正例 `legacy_protocol_and_rc4` evidence `服务端仍可与以下已废弃协议完成握手`，TLSv1.3+AEAD / 纯 HTTP 2 反例）。
  - `tests/fixtures/engines/dns_security.yaml`（`DnsSecurityEngine`，正例 SPF missing / DMARC p=none / DNSSEC 未启用，1 反例完整安全配置）。
- E 深度断言：ssti/7 正例补 `evidence_contains`+`reproduction`，cmdi/ldap 修正 reproduction 缩进。
- IDOR/BOLA 多账号：新建 `scripts/idor_multirole_e2e.py` + `tests/test_idor_multirole_e2e.py`（6 用例）；修复 `orchestrator.py` `build_multi_role_sessions` 用 `extra_headers` 注入 Authorization（修 aiohttp 构造后写 headers 失效 bug）。
- 验证：`rebuild_dataset.py` 337 rows（TP=181 TN=156，较 326 上升）、`dataset_metrics.py` recall=1.0 precision=1.0 reproduction_rate=1.0、`test_coverage_audit.py` ENGINES=80 GAP=0 DEPTH=75、`test_engine_fixtures.py` 21 + `test_dataset_metrics.py` 17 全绿。

### 新引擎三连：CSS Exfiltration / OAuth redirect_uri 绕过 / DNS Rebinding（2026-09-15，并行交付）

- P1 `CssExfiltrationEngine`（`name="css_exfiltration"`，web_advanced_engines.py 追加）：参数级 check() 注入唯一 12 位 token 进 style 属性/`url(`/`<style>` 块，必须 token 反射且落在 CSS 值上下文才报，普通文本回显不报（fail-closed）；scan() 目标级被动返回空。fixture `css_exfiltration.yaml` 正反例 + `tests/test_css_exfiltration.py`（aiohttp TestServer 靶场 2 用例）。
- P2 OAuthEngine 扩展（auth_engines.py）：`REDIRECT_URI_PAYLOADS` 追加 13 条绕过变体（@混淆/编码双重编码/白名单后缀附加/换行截断/路径穿越/非 http scheme）；新增 `_classify_redirect_uri()` 打类型标签；重写 `test_redirect_uri_hijack` 为结构化判定（以 authorize 端点 netloc 为基准 host，授权码被发往非授权域才报，Location 反射仅兜底 Low），全量 payload 遍历替代 [:5]。oauth.yaml 追加正反例 + `tests/test_oauth_redirect_bypass.py` 3 用例。
- P3 `DnsRebindingEngine`（`name="dns_rebinding"`，net_engines.py 追加）：TOCTOU 两轮解析（间隔 min(ttl,2)s，`asyncio.to_thread` 包解析）IP 集合不一致→High；单查询混合网段→Medium；仅低 TTL 无其它信号不报（fail-closed）；私网目标/解析失败/无 dnspython 均跳过返回 []。fixture `dns_rebinding.yaml` + `tests/test_dns_rebinding.py` 8 用例（TOCTOU 翻转/混合网段/稳定不报/异常不报）。
- 验证：三组新测试 13 全绿；回归 `test_engines_core`+`test_engine_fixtures`+`test_dataset_metrics` 136 passed；`rebuild_dataset.py` 353 rows（TP=191 TN=162）；`dataset_metrics.py` recall=1.0 precision=1.0 reproduction_rate=1.0；`test_coverage_audit.py` ENGINES=83（+3 新引擎）GAP=0 DEPTH=78。

### fixture 补实与 gadget 指纹库（2026-09-15，四任务并行）

- 任务2 `weak_credential` fixture 3→6：补 `weak_credential_iis_admin_staff`（Basic admin/P@ssw0rd 正例）、`weak_credential_default_device`（设备默认口令表单 302 正例）、`weak_credential_lockout_protected`（429 防爆破反例）。
- 任务3 `csrf` fixture 2→5：补 `form_without_token_get_state_change`（GET 状态变更无 token 正例）、`form_with_hidden_anti_csrf`（authenticity_token 反例）、`page_no_forms`（静态页反例）。注意：引擎 `TOKEN_NAME_RE.match()` 锚定起始，`_token`/`X-CSRF-Token` 不被识别，fixture 用引擎真实识别的 `authenticity_token`。
- 任务4 `business_logic` fixture 3→6：补 `business_price_bypass_coupon`（价格绕过/优惠券 abuse 正例，evidence 贴合 `_check_coupon_abuse`：折扣被接受含折扣信息）、`business_skip_payment_step`（状态参数改 paid 正例，贴合 `_check_status_manipulation`）、`business_valid_discount`（正常折扣反例）。
- 任务5 deserialization gadget 指纹（deserialization.py + payload_pool.yaml）：新增 `JAVA_GADGET_FINGERPRINTS` 16 条（URLDNS、CC1-7、CommonsBeanutils1、Jdk7u21、JRMPClient/JRMPListener、JdbcRowSet、Groovy1、Spring），接入 `_passive_check`（desc=`ysoserial {gadget} 链特征`）与 `_detect_stack` java 判定；payload_pool `deserialization.java` 追加 URLDNS 真实 base64、CC1/JRMPClient/JdbcRowSet `__gadget:` 标记 4 条。亲测 InvokerTransformer 串命中。
- 验证：`rebuild_dataset.py` 381 rows（TP=213 TN=168）、`dataset_metrics.py` recall=1.0 precision=1.0 reproduction_rate=1.0 门禁 PASS、回归 136 passed 无破坏。

### 注册补位与深度覆盖归零（2026-09-15，三线并行）

- 任务1 任务池注册：`phases_taskgen.py` global_engines 显式加入 `css_exfiltration`、`dns_rebinding`（此前仅有 __init__.py 导出 + P0-3 兜底，显式化消除 warning）；`__init__.py` 两新引擎此前已含。
- 任务3 prototype_pollution fixture 2→5：补 `prototype_lodash_gadget_upgrade`（正例，`X-Powered-By: Lodash` 指纹 → 已验证(gadget链路)）、`prototype_json_body_marker`（正例，JSON 体 json_payloads 分支落地验证）、`prototype_gadget_not_upgraded`（反例，无 marker 不报）。确认：`_detect_gadget_fingerprint` 只扫 resp[2] headers（Server/X-Powered-By），不扫 body。
- 任务5 深度覆盖 6 缺口补 fixture（DEPTH 78→84）：confluence_exposure/nacos_exposure/solr_exposure（scan 型，evidence `产品 JSON 特征命中`）、log4shell（check 型，`${sys:java.version}` 字面量消失＋解析值，evidence `JNDI`）、metamorphic（tamper 差分，evidence `响应 HTTP `）、sequence_chain（乱序直达末步，evidence `业务成功信号`）。各 yaml 1 正例 + 2 反例。
- 验证：`rebuild_dataset.py` 402 rows（TP=221 TN=181）、`test_coverage_audit.py` ENGINES=83 GAP=0 DEPTH=84、门禁 recall=1.0 precision=1.0 reproduction_rate=1.0 PASS、回归 136 passed。

## 工作流 6（部署/压测）补缺（2026-09-13）

- 已就绪：docker-compose 3 服务（redis:7-alpine 带 healthcheck / master / worker replicas:2，数据走 `_runtime_cache` 文件）；`/health` 与 `/metrics`（Prometheus text 4 组 gauge）实测可用；本机负载 100 并发：QPS≈291.5、p50 3.0ms / p95 4.5ms / p99 6.3ms。
- 本轮修复（仅改现有文件）：
  - `dashboard/server.py` 新增 `/ready`（readiness）：Redis 未就绪返回 503 + reason；`/health` 保留为 liveness（进程活即 200）。实测：无 Redis 时 `/health`=200、`/ready`=503。
  - `docker-compose.yaml` 给 master/worker 补 healthcheck（redis-py ping 探活，interval 15s / start_period 30s）；redis 原 healthcheck 不变。
- 仍缺（需新建，未授权）：`scripts/*_load_test.py` 压测脚本 + 入口 bat；`deploy/` 目录（容器编排/Prometheus 采集告警）。
- 验证：compose YAML 语法通过、`test_deployment_static.py` + `test_sprint4.py` 31 项全绿。

## 工作流 8（安全/供应链）核查与补缺（2026-09-13）

- 磁盘实测修正：先前"缺凭据脱敏/压缩炸弹/出站白名单/SSRF/插件签名"录音全部误报——均已实现：
  - 平台级 SSRF/DNS-rebinding：`core/http_client.py` `check_ssrf()`（SSRF_GUARD=1 启用、首次解析 IP 重解析一致性、`ssrf_allow_private` 白名单网段）。
  - 压缩炸弹防护：`http_client.py` 解压后最终字节数上限校验（gzip/deflate/br）。
  - 出站白名单：`settings.egress_allowlist` 解析 + 校验。
  - 插件签名：`core/plugin_market.py` SHA256 fail-closed（`plugin_signatures.json`）。
  - 日志凭据脱敏：`core/logger.py` redact_secrets（fail-open）+ `core/utils.py`。
  - 结构化日志：`logger.py` JSON formatter（STRUCTURED_LOG=1，{ts,level,name,trace_id,message}）+ thread-local trace 上下文。
  - P50/P95/P99 扫描器指标：`core_modules/metrics.py` Summary quantiles=(0.5,0.9,0.95,0.99,0.999) 带降级 + Histogram(engine 耗时) + 成功率/OOB/队列/worker/死信计数。
- 真缺口（本轮修）：扫描器指标（9090 端口，`--metrics-port`/`enable_metrics`）与 dashboard `/metrics`（仅 4 组集群 gauge）两套孤立 → `/metrics` 末端融合转储扫描器 registry（`generate_latest`，异常静默降级，空 registry 跳过）。实测：`/metrics` 同时输出集群 gauge + `scanner_*`（含 latency summary/engine histogram），无 Redis 时 200 正常。
- 仍缺（需新建/外部）：`deploy/` + Prometheus 采集告警配置；扫描器与 dashboard 异地部署时的指标汇聚（需 pushgateway 或共享 registry）。
- 验证：dashboard /metrics 实测含 `scanner_response_latency_seconds` summary；`test_platform_security.py`+`test_deployment_static.py`+`test_sprint4.py` 98 项全绿。

### 工作流7 生态/API 接线（2026-09-13，并行交付）

- `cli.py` 新增 `interop` 子命令（formats / import / export）：`interop import <fmt> <file|-> [--export <fmt>]` 与 `interop export <fmt> <file|->`，stdout 只输出数据供管道、人读摘要走 stderr，文件缺失/未知格式退出码 2；已加入 214 行子命令白名单（否则被兼容模式转发）。
- `dashboard/server.py` 新增 `POST /api/webhook/ingest` 入站 webhook：`_auth_ok` 鉴权、payload 超 5MiB → 413、未知格式 → 400；经 `interop.import_any` 解析 + `to_native_findings` 追加落盘 `_runtime_cache/webhook/feed.jsonl`（写失败静默降级）；返回 `{accepted, skipped, finding_count, ref}`（ref=秒级时间戳+内容哈希）。
- 新建 `src/vulnclaw/client.py` SDK：`DashboardClient`（httpx.AsyncClient 薄封装，token 自动带 `X-Dashboard-Token`；`build_request` 可离线断言）+ `build_payload` 包装 `export_any`。
- OpenAPI：FastAPI `openapi_tags`/`description` 已补齐（webhook body 结构入 description），`/openapi.json` 自动可用。
- 测试：`test_interop.py` + 新建 `test_interop_api.py` → 62 passed（离线、零网络）。

### 工作流8 复核补充（2026-09-13，承接"工作流 8（安全/供应链）核查与补缺"节，本会话并行复核）

- 代码与上节实现一致、无重复定义（http_client 单一 `check_ssrf`/`check_egress`/`_read_response_body`；metrics.py 的第二个 Summary 为旧版无 quantiles 的 try/except 降级分支，非重复注册）。
- 复核测试：`test_platform_security.py` + `test_tool_output_guard.py` 95 passed, 2 skipped（既有网络插件测试）；layout/plugin/scope/supply 回归 EXIT=0。
- 清理残留：`config/settings.py.bak`、根目录 `_tmp_engine_list.py`/`_tmp_out.txt`/`_tmp_pin_check.py`、`scripts/__pycache__`；`test_layout_guard.py` 白名单登记 `SBOM.json`（sbom.py 默认产物）。
- 默认关闭项：`EGRESS_ALLOWLIST`/`SSRF_GUARD`/`SSRF_ALLOW_PRIVATE`（即出站白名单与平台级 SSRF/DNS-rebinding 均为 opt-in，不改变现有扫描行为）。

### 工作流11 跨版本回归实验室（2026-09-13，`tests/test_version_regression_matrix.py`）

- 目标：对"版本判定类"引擎建立 易受/修复/边界 三档断言矩阵（TP/FN 门禁 + FP 门禁 + 区间端点 off-by-one 防护），版本区间逻辑回归时即时拦截。
- 载体：复刻 `test_engines_core.py` 的 lab 模式——内存 aiohttp app（单服务按路径返回不同版本指纹）+ TestServer + 真实引擎调用，零 Docker/网络依赖，任意环境确定性回归。
- 实测矩阵：Apache CVE-2021-41773（易受 2.4.49 / 边界 2.4.50 / 修复 2.4.52）、Nginx CVE-2021-23017（1.18.0 / 1.21.0）、PHP CVE-2019-11043（7.1.28 / 7.4.30）、Jetty CVE-2021-28164（9.4.36 / 9.4.45）、jQuery CVE-2020-11022/23（易受 3.5.0 / 边界 3.4.1 / 修复 3.6.0）、无版本指纹（Server: cloudflare）不得误报。
- 扩展框架（A6 阶段补足）：ASP.NET CVE（4.8 ∈ 区间检出 / 4.8.1 不检出）、OpenSSL CVE（1.0.1 检出 / 3.0.0 不检出）、Django 框架指纹（Info 级识别）、Express 指纹。
- 命中的真实引擎：`engines/logic_leak_engines_2.py` `JsLibraryCveEngine`（jQuery 区间 `(1,0,0)-(3,5,0)`）与 `BackendComponentFingerprintEngine`（`BACKEND_RULES` 含 Apache 2.4.49/50）。
- 验证：`test_version_regression_matrix.py` 18 项全绿（A0~D 六组：后端组件易受/修复/边界 + 前端 jQuery 三档 + 安全端点 FP 门禁）；叠加 `test_engines_core.py` 共 44 项全绿无回归（仅 aiohttp 弃用告警）。

### 评审整改波次0：T01/T02/T04/T07（2026-09-15，分支 opt/deepseek-review-v2）

- T01 git 纪律：全部非 thirdparty 变更按主题分 9 个语义化提交（docs/src/tests/scripts/ai/T15 第1批/编排器清理/T15 测试/T06 vulhub_lab/T14 master 修复），提交信息 UTF-8（历史有 GBK 乱码，用临时文件 `-F` 规避，用完即删）；thirdparty 遗留（gitlink 无 submodule 映射 + 数据字典）用户指定单独处理不动。最终非 thirdparty 状态清零。
- T02 lint 门禁：`pyproject.toml` 新增 `[tool.ruff.lint] select = ["E4","E7","E9","F"]` + tests/scan.py per-file-ignores；存量 957 处 BLE001（盲 except）登记为技术债务（T15 迁移），不在本地全量开启；CI（`.github/workflows/ci.yml`）新增 "New blind-except gate" 步骤——对 PR 变更的 .py 文件 `ruff check --no-config --select BLE001` 强制零新增裸 except，绕开配置白名单。
- T04 依赖可复现：dev 依赖补版本下限（ruff>=0.16.0 / mypy>=1.10.0 / pre-commit>=3.7.0 / pytest>=8.2.0 / pytest-cov>=5.0.0 / pytest-asyncio>=0.23.0）；lock 文件生成到 `_runtime_cache/requirements-lock.txt`（68 行，运行时产物不入库，遵守不新建仓库文件规则）。
- T07 引擎能力边界：10 个高危引擎 docstring 追加三段式声明（can_detect / cannot_detect / 前置条件，2026-09-15 评审补录）：SSRFEngine、Log4ShellEngine、FastjsonDeserializationEngine、CMDIEngine、SSTIEngine、IDOREngine、OAuthEngine、WeakCredentialEngine、DeserializationEngine、BusinessLogicEngine。
- 连带收尾：补提交 T15 审计函数测试（audit_suppressed 落盘/读取 5 用例）、T06 `scripts/vulhub_lab.py`（WSL2+Vulhub 靶场驱动，--check/--list/--up/--down/--endpoints/--status，T08 矩阵用）、T14 master 状态回源 Redis 合并修复（重启后残缺状态不覆写）+ 专项测试 test_sp20_master.py + 主链路冒烟门禁（orchestrator 可导入/无 Markdown 表格残留，补 E2E 门禁不覆盖 orchestrator 的盲区）。
- 验证：`test_engines_core`+`test_engine_inventory`+`test_core_imports`+`test_sp20_master`+`test_p3_batch2` 193 passed；ruff 配置可解析；git log 9 提交落盘。

## 5. 评分与技术判断

当前综合评分约 78/100：

- 架构与编排：8.4/10
- 检测可信度：约 7.4/10
- 引擎覆盖：约 7.6/10
- 工程交付：约 7.8/10
- 生产成熟度：约 6.6/10

优势：验证网关、危险操作控制、OOB 设计、业务状态链、插件化、审计与 CI 质量门禁。

短板：真实样本规模、真实复现数据、生态、外部靶场验证、部分引擎覆盖和生产部署成熟度。

## 6. AI 交接规则

1. 先读本文，再读 `README.md` 和相关代码/测试。
2. 数字以可重复命令和运行时代码为准，不以旧文档宣传数字为准。
3. fixture 的 100% 不得解释为生产覆盖率。
4. 不为提高指标而保留已知不稳定或误报的 fixture。
5. 修改代码后同步修改测试；事实变化时更新本文。
6. `.trae/` 与 `.codebuddy/` 是工具私有目录，不要物理合并；它们都指向本文。

## 7. 正式文档

- [README](../README.md)：项目介绍和使用说明。
- [quickstart](quickstart.md)：快速开始。
- [CHANGELOG](../CHANGELOG.md)：版本变更。
- [CONTRIBUTING](../CONTRIBUTING.md)：贡献规范。
- [SECURITY](../SECURITY.md)：安全政策。

旧的重复状态/快照记录已合并到本文；详细实现以当前代码和测试为准，历史差异以 Git 历史为准。
