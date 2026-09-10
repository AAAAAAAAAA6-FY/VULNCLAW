# MAPPING_13_FINAL.md — VULNCLAW × PentAGI 能力映射 最终账（13 点，第三轮重核）

> 对接方：PentAGI ｜ 本方：VULNCLAW（pentest_platform）
> 落定日期：2026-09-10 ｜ 核验方式：基于仓库代码逐条取证（非声明）
> 定义基座：用户 2026-09-10 提供《13 映射点最终账（VULNCLAW 对账修正版）》——含 13 点逐点真定义与初步判定，本文件据此重核。

## 重要修订说明（第三轮）
- 本文件前两轮（重建版 / 定稿版）对 ②③ ④ ⑥ ⑦ ⑧ ⑪ 七点采用**推断定义**（按 VULNCLAW 护城河维度臆测编号↔能力映射），因当时误判"原始清单不可得"。
- 用户 2026-09-10 补回《VULNCLAW 对账修正版》真定义基座后，上述 7 点的真实编号↔定义与推断**大量不符**，已按真定义重核，结论有实质变化：
  - ④ 推断=去重收口 → 真定义=**ToolCallFixer**（工具输出防注入/调用降级）→ ✅ 已落
  - ⑥ 推断=记忆/学习 → 真定义=**事件模型→UI 批次** → ⏸ 挂起（UI 批次未落）
  - ⑦ 推断=状态总线/可观测 → 真定义=**Assistant 控制面** → ⏳ 待办（无证据）
  - ⑧ 推断=危险护栏/合规 → 真定义=**记忆分层** → ✅ 已落
  - ⑪ 推断=多 Agent 编排 → 真定义=**多租户** → ⏳ 待办（无 tenant 实现）
  - ③ 推断=验证利用层 → 真定义=**RepeatingDetector**（①子件）→ ✅ 已落
  - ② 真清单未列此编号（原 13 点②定义待确认）
- ⑬ 由"已落"修正为"🟡 部分已落"（缺按 agent 维度细分）。
- 注：VULNCLAW 确有"危险护栏/合规""状态总线/可观测""多 Agent 编排""验证利用层""去重收口"等实现，但它们**不对应**上述编号（属额外护城河，非 PentAGI 映射点）。

## 核验结论速览
- **已落（有代码+测试）**：① ③ ④ ⑧ ⑨ ⑩
- **部分已落**：⑬（缺按 agent 维度分流）
- **部分覆盖**：⑤（两级同族回退，非完整多源链）
- **挂起**：⑥（事件模型→UI 批次，UI 批次未落）
- **待办**：⑦（Assistant 控制面）⑪（多租户）
- **存疑**：⑫（ImageChooser，疑似平台自身组件混入）
- **待确认**：②（真清单未列此编号）
- 账实不符已更正：⑩（原账"待企业层"→已落）、⑬（原账"待办"→部分已落）

---

## 账务明细（按真定义逐点）

### 一、已落（有代码 + 有测试）
**① 监督三件套** — ExecutionMonitorDetector / HardLimit / RepeatingDetector
- `ai/dispatcher.py::_monitor_tool_usage`；`tests/test_s1_deep_react.py` 4 例专门断言（本次补齐）
- 状态：✅ 已落

**③ RepeatingDetector** — 连续同工具→强制换策略
- 同上（①子件，独立断言）
- 状态：✅ 已落

**④ ToolCallFixer** — 工具输出防注入 / 调用降级
- `core/tool_output_guard.sanitize_tool_result`（:119）+ `run_tool` 降级链；专项 62 例
- 状态：✅ 已落

**⑧ 记忆分层** — 短期(agent内) + 长期(VectorMemory) + 降级
- `dispatcher` short_term + `ai/core.py:1848` VectorMemory + `_MemoryFallback` + `core_modules/sqlite_persistence.py`；`tests/test_memory_feedback.py`
- 状态：✅ 已落（分层边界测试待补）

**⑨ 滚动压缩** — bounded history + 纪要保留
- `ai/dispatcher.py::_compress_history`；`tests/test_budget_wiring.py`
- 状态：✅ 已落（原评"已覆盖"偏保守，升为已落）

**⑩ 证据链 receipt** — 哈希链 + HMAC 防篡改回执
- `core/audit_receipt.py` + `verification_gateway`/`tool_governance` 接线 + CLI `--receipt` + `tests/test_verification_gateway.py:139` 篡改检测
- 状态：✅ 已落（**原账"待企业层"账实不符**）

### 二、部分已落
**⑬ 多 provider 分流** — 按档位(tier)分流
- `ai/v100/provider_balancer.get_client_for_tier`（:208）/ `get_tier_client`（:358），已接线 cost_router/SP23/js_triage
- 状态：🟡 部分已落（**原账"待办"账实不符**；缺"按 agent"维度细分）

### 三、部分覆盖（精度修正）
**⑤ intel.lookup 回退链**
- `modules/intelligence/shodan_client.py` Shodan→Censys 两级回退；`mcp_server._tool_intel_lookup`（:1221）调用之；无凭据路径有测试
- 状态：🟡 部分覆盖（**原账 D1.4 完整多源链 → 实为两级同族回退**）

### 四、挂起
**⑥ 事件模型→UI 批次**
- Dashboard（`dashboard/server.py` ScanEvent 10 类）+ LiveIntake 存在，UI 批次未落
- 状态：⏸ 挂起（公允）

### 五、待办（属实处）
**⑦ Assistant 控制面** — 全库无证据 → ⏳ 待办属实
**⑪ 多租户** — 全库无 tenant/multi_tenant 实现 → ⏳ 待办属实

### 六、存疑
**⑫ ImageChooser** — 全库无对应物 → ❓ 存疑（疑似平台自身组件混入，待 PentAGI 给定义与归属）

### 七、待确认
**②** — 用户提供的《VULNCLAW 对账修正版》未列此编号；原 13 点②定义待确认（可能已合并/删除）。

---

## 待 PentAGI 对质 5 条
1. **⑩ 账实不符**：receipt 已强落地（哈希链+HMAC+CLI+篡改检测测试），请更新账为已落。
2. **⑬ 账实不符**：tier 分流已存在并接线；若你要的是"按 agent 维度分流"，请给出新增点。
3. **① 测试缺口已补**：监督三件套现已有 4 例独立断言（RepeatingDetector / ExecutionMonitorDetector / HardLimit / UnknownTool）。
4. **⑫ 存疑**：VULNCLAW 无对应物，请给出定义与归属。
5. **⑤ 精度**：实为两级回退（Shodan→Censys），非完整多源链，建议标注"部分覆盖"。

## 代码取证记录（2026-09-10，第三轮）
- `ai/dispatcher.py`（`_monitor_tool_usage` / `_compress_history`）
- `tests/test_s1_deep_react.py`（监督三件套 4 例断言）
- `core/tool_output_guard.py:119`（`sanitize_tool_result`）
- `ai/core.py:1848` VectorMemory + `_MemoryFallback` + `core_modules/sqlite_persistence.py` + `tests/test_memory_feedback.py`
- `core/audit_receipt.py` + `verification_gateway`/`tool_governance` + `cli.py:473,477` + `tests/test_verification_gateway.py:139,153`
- `ai/v100/provider_balancer.py:208,358`（`get_client_for_tier` / `get_tier_client`）
- `modules/intelligence/shodan_client.py` + `core/mcp_server.py:1221`（intel 回退链）
- `dashboard/server.py`（ScanEvent 10 类）+ LiveIntake（事件模型→UI 批次挂起）

## 结算口径（第三轮重核）
已落 6（① ③ ④ ⑧ ⑨ ⑩） + 部分已落 1（⑬） + 部分覆盖 1（⑤） + 挂起 1（⑥） + 待办 2（⑦ ⑪） + 存疑 1（⑫） + 待确认 1（②）
- 前两轮"系统性低估"定性不成立；现按真定义，VULNCLAW 在 ① ③ ④ ⑧ ⑨ ⑩ 已落、⑬ 部分已落，无低估。
- ⑥ ⑦ ⑪ 由前两轮"已落"修正为挂起/待办（前轮编号↔定义臆测所致，非代码回退）。
- 本对账为最终交付物（②待用户确认原 13 点编号；⑫待 PentAGI 给定义）。
