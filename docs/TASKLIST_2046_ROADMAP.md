# TASKLIST · 2046 路线图执行清单（P0 / P1）

> 来源：四份 AI 评审融合（2026-09-14）+ 三路并行侦察（精确到行号）。
> 执行原则：**最小改动 / 每项可独立验证 / 遵守"无用功清单"**。
> 三线并行：**A 线 = 数据飞轮与攻击图 / B 线 = 门禁与安全 / C 线 = 智能层**。

---

## A 线（数据飞轮 + 攻击图）

### A1 [P0] 飞轮点火 —— 进行中
**现状事实（已侦察）**
- 开关 `enable_growth_feedback` / `enable_growth_ingest` / `enable_growth_ingest_llm` 默认 **False**（`src/vulnclaw/growth/bridges.py:23-25`）；`config/settings.py` **未声明**这三个字段（`_flag()` 走 `getattr` 动态读，`bridges.py:28-33`）。
- 接线点：`maybe_ingest_cves()` → `runners/scan_runner.py:1201-1202`；`maybe_absorb_scan(report)` → `scan_runner.py:2682-2683`。
- **飞轮从未点火**：`_runtime_cache/growth/` 只有 `coverage_gaps.jsonl`，**不存在 `feedback.jsonl`**。
- **断链 ①（bug）**：`distill_data.py:26` `_DEFAULT_LEDGER = .../feedback_ledger.jsonl`，而生产者 `FeedbackLedger` 写的是 `feedback.jsonl`（`feedback_ledger.py:35-39`）→ 消费者永远读不到。
- **断链 ②（bug）**：`bridges.adaptive_payloads()`（`bridges.py:87-93`）**无任何调用点**（注释声称"供 exploit_chain/taskgen 复用"，实际未接线）。
- **陷阱 ③**：`absorb_finding` 的 verdict 兜底（`feedback_ledger.py:120-130`）`confidence in (1,"high") → confirm`；报告里 `confidence` 可能是中文"高"→ **被判成 miss（弱证据）**。
- **燃料**：`_runtime_cache/reports/` **360 份**历史报告 + `_runtime_cache/datasets/real_results_v1.jsonl` **34 行**。

**改动清单**
1. 修断链 ①：统一账本文件名（消费者指向生产者实际写入的 `feedback.jsonl`）。
2. 修陷阱 ③：verdict 兼容中文 confidence（"高/中/低" → high/medium/low）。
3. 写**存量导入**入口（幂等）：把 `_runtime_cache/reports/*` 灌入 `feedback_ledger`（复用 `absorb_scan`），支持 CLI/开关触发。
4. 点火：开关生效路径收口（默认值策略见"风险"）。

**验收**：导入后 `feedback.jsonl` 行数 > 0；`distill_data.export_training_data()` 能产出 > 0 条；重复执行不产生重复行（幂等）。
**风险**：①重复导入（需按 finding 指纹去重）；②报告格式与 `absorb_scan` 入参不兼容（需适配层）；③**默认开=改变既有扫描行为**——建议先以"显式开关 + 文档"点火，默认值变更单独批次评审。

### A2 [P1] 攻击图数据化
**现状**：`core/attack_graph.py` 的 `_CASCADE_RULES` 为 8 条手写常量；边概率硬映射，未由真实数据校准。
**改动**：①`prob` 从 `feedback_ledger` 的真实命中率校准；②从 CVE 数据自动补边（前置类型→后置利用）。
**验收**：攻击图 JSON 中每条边的 prob 可溯源到 ledger 统计。

---

## B 线（门禁 + 安全）

### B1 [P0] 端点级 P/R 门禁进 CI —— 进行中
**现状事实（已侦察）**
- `scripts/eval_prf.py` 退出码：`0`=全清（零 FN+零 FP+零 ERR+无抖动端点）、`1`=存在 FN/FP/ERR/抖动、`2`=靶机不可用、`3`=外部目标未授权（`eval_prf.py:785-787` 等）。
- **没有 `--min-f1` / `--min-recall` 参数**（`__main__` 参数表 `:794-812`）。
- `local_lab` 由 `_ensure_lab()`（`:132-146`）**自动拉起**（12s 轮询）；整轮预计 1–3 分钟。
- `.github/workflows/ci.yml`：`test` job（`:14-71`）矩阵 py3.11/3.12、`pytest ... --cov`、**无 timeout-minutes**；已有 3 个"脚本退出码作门禁"的现成范式（`:42-50 / 52-56 / 58-66`）。
- `regression.yml`：单 job、`timeout-minutes: 30`、ruff + pytest。

**改动清单**
1. `eval_prf.py` 新增 `--min-f1`（可选，缺省=沿用"全清"严格口径）。
2. `ci.yml` 新增独立 job `endpoint-prf-gate`：`timeout-minutes: 15`、装依赖、`python scripts/eval_prf.py --min-f1 0.95`，退出码即门禁。

**验收**：本地 `python scripts/eval_prf.py --min-f1 0.9` 返回 0；CI 上该 job 绿。
**风险**：CI 环境无 local_lab 依赖问题（纯 stdlib + aiohttp，已覆盖）；端口冲突（CI 干净环境无虞）。

### B2 [P0] Dashboard fail-closed
**现状**：`dashboard/server.py:118-122 _auth_ok()` 无 `DASHBOARD_TOKEN` 时**全部放行**；默认绑定回环（注释明示）；bind 位置在 `uvicorn.run(...)`（行号待补）。
**改动**：①无 token 且绑定 host 非回环 → **拒绝启动**（fail-closed）；②启动时若未配置 token，**打印一次性随机 token**。
**验收**：`host=0.0.0.0` 且无 token → 拒启并报错；`127.0.0.1` → 放行 + 警告。

### B3 [P1] Cookie 加密落盘
**现状**：`_runtime_cache/cookies/*.json` **明文**（现有 7 个）；读写点集中在 `core/utils.py`（`_get_cookie_file_path` / `_atomic_write_json` / `extract_target_cookies`）与 `runners/scan_runner.py:seed_cookie_for_domain`。
**改动**：①写入加密、读取解密（Windows DPAPI / 跨平台密钥文件二选一）；②旧明文首读时自动迁移（加密重写后清除明文）。
**验收**：新写入文件非明文；旧文件自动迁移；cookie 注入链路（`get_shared_session`）行为不变。

---

## C 线（智能层）

### C1 [P1] LLM 语义确认层（成立理由 + curl PoC） —— 进行中
**现状事实（已侦察）**
- `phases_verify.py:231-315 _verify_cross_batch()` **已带结构化 schema** `[{"index","confirmed","confidence","reason"}]`（最接近目标的现有实现，缺证据引用/curl）。
- `phases_verify.py:772-921 _verify_cross()`：prompt（`:789-803`）只问"是/否/证据不足"；投票解析 `:890 is_vuln = "是" in result`（**改 JSON 后必须同步修改**）。
- `ai/core.py:389-402 ask(..., force_json=False)`；`:479-480` `force_json` 会追加"只输出合法 JSON"系统指令。
- 结构化 JSON 解析器：`safe_extract_json`（`phases_verify.py:288` 已 import）。
- curl 生成**已存在**：`orchestrator.py:1152-1179 _build_curl_command` + `:1180-1188 _enrich_finding_repro`（写 `curl_command`/`reproduction`）。
- severity 分档锚点：`phases_verify.py:17-25 _severity_verify_plan()`（Medium+ 已走 2 模型 + HTTP 验证）。

**改动清单**
1. `_verify_cross()` prompt 升级为结构化 schema：`{confirmed, confidence, reason, evidence_ref[], curl_poc}`；`client.ask(..., force_json=True)`。
2. 解析走 `safe_extract_json`，**解析失败 fail-closed**（维持原 boolean 结论，不得凭空 confirmed）。
3. 投票逻辑同步改为解析 `confirmed` 字段。
4. 写入 finding：`ai_reason` / `evidence_ref` / `curl_command`（与报告侧 `report_generator.py:80` 消费口径对齐）。

**验收**：对 local_lab 跑一轮，Medium+ finding 带 `ai_reason` + `curl_command`；未配置 AI 时零影响（降级保持）。
**风险**：投票逻辑不同步会全 False；LLM 成本需走 `usage_site="verify:semantic"` 计量。

### C2 [P1] 自动登录（解锁 IDOR multi-session）
**现状事实（已侦察）**
- `core/auth/instruction_auth.py` **已有完整降级链**：`try_instruction_login()`（`:236-282`）、`_http_form_login()`（`:111-187`，HTMLParser 抓表单 + httpx POST）、`_save_cookie()`（`:60-71`，原子写）、`_register_role_sessions()`（`:211-229`，**多身份会话已实现**）。
- `core/auth/auto_login.py`：`auto_login_and_get_cookie()`（`:22-73`）用 Playwright `page.fill`，但**选择器硬编码** `#username/#password/#login-btn`（`:26-28`）。
**改动**：①选择器改为可配置（`.env`/参数）；②登录成功后对接 `seed_cookie_for_domain` 落盘；③接入扫描主流程（凭据存在时自动尝试）。
**验收**：对一个真实登录靶场（或本地构造表单页）自动登录并落 cookie；IDOR oracle 能读到属主标记。

### C3 [P1] 本地 OOB 回环（打通 reproduced）
**现状（部分待补）**：`core/oob_channel.py` 7 协议构造已实现（`_OOB_PROTOCOLS`、`protocol_callback`）；`settings.oob_base_url`/`oob_hits_file` 消费于 `core/vulnspec/runner.py:_probe_oob`；无"本地监听"provider 分支。
**改动**：新增 local provider（本机 HTTP listener → 按 `hits_file` 行格式写命中）→ `reproduced` 从恒 0 变真实数。
**验收**：对 local_lab 的 OOB 声明确认一次真实回调闭环。

### C4 [P1] 先验驱动调度
**现状**：`ai/v100/phases/phases_taskgen.py` 生成任务（引擎/参数/优先级字段待补行号）；`modules/live_intake.py` 提供 `feed_live`。
**改动**：侦察/被动数据 → LLM 排序"最可能出洞的点" → 写回任务优先级字段。
**验收**：任务序列出现按先验的排序变化（可复现）。

---

## ⛔ 无用功清单（四份评审共识，禁止投入）

- ❌ 加第 81~100 个引擎（覆盖已饱和，质量才是瓶颈）
- ❌ 加测试数量 / fixture（2,295 已够，缺的是 P/R 门禁）
- ❌ 再碰 Docker/Vulhub（环境墙；`local_lab` 是等价且更强的证据）
- ❌ 换 neo4j、prompt 措辞优化、UI 美化
- ❌ 把 19 类安全防护逐项默认开（只改 dashboard 这一个暴露面）

## 进度总表

| ID | 任务 | 线 | 优先级 | 状态 |
|---|---|---|---|---|
| A1 | 飞轮点火（含 2 处断链修复） | A | P0 | 进行中 |
| A2 | 攻击图数据化 | A | P1 | 待办 |
| B1 | 端点级 P/R 门禁进 CI | B | P0 | 进行中 |
| B2 | Dashboard fail-closed | B | P0 | 待办 |
| B3 | Cookie 加密落盘 | B | P1 | 待办 |
| C1 | LLM 语义确认层 | C | P1 | 进行中 |
| C2 | 自动登录 | C | P1 | 待办 |
| C3 | 本地 OOB 回环 | C | P1 | 待办 |
| C4 | 先验驱动调度 | C | P1 | 待办 |
