# Finding 证据等级 schema v1（FINDING SCHEMA）

> B1 交付。实现：`src/vulnclaw/core/finding_schema.py`（附加视图，零破坏迁移）。
> 验收：`tests/test_finding_schema.py`（含报告链路零回归断言）。
> 报告接线：`report_generator.enrich_report()` → `apply_schema_inplace()`（纯新增键）。

## 1. 存在意义

扫描链路上"这条 finding 到底是被**规则命中**了、还是被**验证**了、还是被**复现**了"此前
在多处各自解读（引擎布尔字段 / 渲染层徽标 / `verification_method` 字符串 / `ai_verdict`
中文串），口径漂移会让报告与评分把**规则命中**当成**验证结论**。本 schema 把口径收敛为一处。

## 2. 字段定义

```json
{
  "finding_id": "f1-<16hex>",
  "schema_version": 1,
  "detection": {
    "rule_match": true,
    "response_evidence": true,
    "verification": false,
    "reproduction": false,
    "oob_confirmed": false
  },
  "confidence": "medium",
  "status": "suspected",
  "evidence_items": [{"kind": "...", "source": "...", "detail": "..."}],
  "verification": {"verified": false, "method": "", "signals": [], "evidence": ""},
  "reproduction": {"reproduced": false, "signals": [], "payload": "", "parameter": ""},
  "oob": {"confirmed": false, "signals": [], "channel": "", "token": "", "observed_at": "", "raw": ""}
}
```

**五级语义铁律（各级独立赋值，禁止跨级推断）**：

| 级别 | 含义 | 只读取的原生信号（示例） |
|---|---|---|
| `rule_match` | 本地规则/特征命中 | `rule_hit`/`rule_id`/`signature_id`/`verification_method=local_rule` |
| `response_evidence` | 响应侧存在可展示证据文本 | `evidence`/`proof`/`response_preview` |
| `verification` | 验证层/外部工具背书 | `exploited`/`burp_verified`/`cross_confirmed`/`verdict=confirmed`/`ai_verdict` 含"真实漏洞" |
| `reproduction` | 独立重打/重放确认 | `exploit_reproduced`/`revalidated`/`blind_repro=confirmed` |
| `oob_confirmed` | 带外回调实锤 | `oob_confirmed`/`oob_evidence`/`verification_method` 含 oob |

- `rule_match=True` **绝不**自动推出 `verification=True`；
- `reproduction` 刻意**不**按 `verification_method` 文本判定（`burp_replay_diff` 同时是验证
  信号，按 "replay" 文本匹配会变成跨级推断）；
- 各级只读"属于自己那一级"的信号表，互不污染。

## 3. 10 态状态机

```text
candidate → suspected → verified → reproduced → oob_confirmed     （检测等级单调推进）
                    ↘ false_positive / accepted / fixed / reopened / closed   （治理态，人工权威）
```

- `advance_status`：**只升不降**——`verified` 遇弱证据保持 `verified`（`can_transition`
  允许的"合法降级"只适用于人工迁移，不适用于检测等级自动推进）；
- 治理态（false_positive/accepted/fixed/closed）一旦写入即为权威，不再被检测等级覆盖；
- `reopened` 可由治理态回退进入（重新追踪）。

## 4. finding_id（稳定身份）

`sha256(url|method|type|parameter)`（长度前缀 + 不可见分隔符拼接，前 16 hex，前缀 `f1-`）：

- 同输入 → 同 ID（跨进程、跨扫描、与 dict 键序无关）；
- 参数顺序 / URL query 顺序 / 尾斜杠 / 大小写差异 → 同 ID；
- 无任何身份字段或非 dict → 空串（fail-closed）。

用途：跨扫描关联（C3 基线比较）、多工具结果归并（E1 互导）、生命周期追踪（B2/B3）。

## 5. 迁移策略（只增不改）

- `to_schema_v1(finding)` 返回**新 dict**：既有键值一字不改，只新增 schema 键；
- 报告链路用 `apply_schema_inplace(finding)`：**就地**补写 `SCHEMA_ADDITIVE_KEYS`
  （`finding_id`/`schema_version`/`detection`/`status`/`verification`/`reproduction`/
  `oob`/`evidence_items`），**不含** `confidence`/`evidence` 两个既有渲染字段 →
  HTML/Markdown/SARIF/CSV 渲染逐字节不变；
- 幂等：对已归一化结果重复调用输出不变；
- 坏输入（非 dict）→ fail-closed 为 candidate。

## 6. 格式映射（哪些格式展示哪些字段）

| 格式 | 展示 schema 字段 | 说明 |
|---|---|---|
| JSON | 全字段 | 机读主源 |
| HTML/Markdown | status 徽标、confidence、evidence_items 前 N 条 | 渲染色带 + 证据摘要 |
| SARIF | `properties.vulnclaw.{finding_id, detection, status}` | 消费方可据此过滤"已复现"等 |
| CSV | finding_id + status 列 | 台账导入导出 |

## 7. 现状差距（如实记录，留给 B2/B3）

1. 渲染层（G 组徽标口径）存在跨级推断：`verified = rule_hit or oob or ...`、
   `reproduced = oob or exploit_*`——与本 schema 的语义口径**刻意分歧**；
   schema 不采信这些派生字段，两套口径暂并存（B3 误报治理时收敛）；
2. `ai_verdict` 中文串判定（含"真实漏洞"→ verification）是弱结构化信号，
   依赖词表稳定性；B2 生命周期引入结构化状态后应逐步弱化文本判定；
3. 现有代码多处把"规则命中"直接呈现为"已确认"（报告文本层），属展示面问题，
   本轮未做破坏性修改。

## 8. 复现

```powershell
python -m pytest tests/test_finding_schema.py tests/test_sp17_report.py tests/test_sp17_export.py -q --disable-warnings
```
