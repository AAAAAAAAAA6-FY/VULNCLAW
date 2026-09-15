# 工具互导（INTEROP）

> E1 交付。实现：`src/vulnclaw/core/interop.py`（纯函数、离线、确定性）。
> 验收：`tests/test_interop.py`（20+ 例，含映射表完整性锁死与 round-trip 保真）。

## 1. 支持格式矩阵

| 格式 | 导入 | 导出 | 原始报文 | 备注 |
|---|:---:|:---:|:---:|---|
| VULNCLAW JSON | ✅ | ✅ | ✅ | 原生口径，无损 |
| JSONL | ✅ | ✅ | ✅ | 通用行式交换 |
| Nuclei JSONL | ✅ | ✅ | ✅ | `template-id`/`info.*`/`matched-at` |
| Burp XML | ✅ | ✅ | ✅ | base64 请求/响应自动解码 |
| ZAP JSON | ✅ | — | ❌ | 报告不携带原始报文 |
| SARIF 2.1.0 | ✅ | ✅ | ❌ | ruleId/level/locations |
| CSV | ✅ | ✅ | ❌ | 列式摘要 |
| 原始 HTTP 请求 | ✅ | — | ✅(仅请求) | 解析 method/host/path/header/cookie |

统一分派：`import_any(text, fmt)` / `export_any(findings, fmt)` / `supported_formats()`。

## 2. 统一模型（`UnifiedFinding`，17 字段）

```text
source scanner rule_id title finding_id severity confidence url method
parameter request response evidence verification reproduction oob raw
```

- `severity`：critical/high/medium/low/info 或 `""`（**不可识别一律留空**，不降级为 info）；
- `confidence`：high/medium/low 或 `""`；
- `finding_id`：自带优先，缺失时按 `finding_schema.compute_finding_id` 口径计算（跨格式一致身份，→ 多工具结果可归并）；
- `raw`：原始条目存档（不参与往返）。

归一化口径（跨工具对齐的关键）：

| 外部取值 | 统一档位 |
|---|---|
| Burp `High`/`Medium`/`Low`/`Information` | high/medium/low/info |
| Burp `Certain`/`Firm`/`Tentative` | high/medium/low |
| ZAP `riskcode` 4/3/2/1/0 | critical/high/medium/low/info |
| ZAP `riskdesc` `"High (High)"` | 取主级别 → high |
| SARIF `level` error/warning/note | high/medium/low |
| 数字 0-4（通用） | 0=info … 4=critical |

## 3. 字段映射表

`FIELD_MAPPING`（代码内）是**唯一事实源**，覆盖 8 种格式 × 17 个统一字段，
每个字段标注取值来源（`const:` 固定值 / `derive:` 推导 / `n/a` 无来源 / `ext.` 扩展位）。
测试 `TestFieldMapping::test_every_format_covers_every_unified_field` 锁死
"每格式键集合 == UNIFIED_FIELDS"，**杜绝新增字段时漏映射**。

## 4. round-trip 保真机制（扩展位）

外部格式不承载 `verification`/`reproduction`/`oob`/`finding_id` 等字段。为让
"导出 → 再导入"严格一致，导出器写入**带命名空间的扩展位**：

| 格式 | 扩展位落点 |
|---|---|
| Nuclei JSONL | 顶层 `vulnclaw` 键（+ `method`/`parameter` 顶层键） |
| Burp XML | `<vulnclaw-extension>` 子元素 |
| SARIF | `properties.vulnclaw` |
| CSV | 独立列 |

导入器**优先读扩展位**，缺失时回退外部格式原生字段（即第三方真实产物路径）。
`severity`/`evidence` 也在扩展位内——外部格式对它们有展示默认值（Nuclei severity 必填
`info`、SARIF message 不可为空），不落扩展位会在往返中被"默认值化"。

## 5. 用法

```python
from vulnclaw.core.interop import import_nuclei_jsonl, export_sarif, to_native_findings

res = import_nuclei_jsonl(open("nuclei.jsonl", encoding="utf-8").read())
print(len(res), "条；跳过", res.skipped, res.errors[:3])
sarif_text = export_sarif(res)                    # 交给消费方
native = to_native_findings(res)                  # 喂 report_generator["vulnerabilities"]
```

## 6. 已知限制（如实）

1. **不做行为等价的完整解析**：只保证 finding 级互导（严重度/位置/证据/身份），
   不重建扫描上下文；
2. ZAP JSON / CSV / SARIF 不含原始报文 → `request`/`response` 恒空（`n/a`，绝不编造）；
3. `raw_http` 只吃请求侧（无响应结论）→ `evidence`/`severity` 恒空；
4. 统一模型不含 `payload` → `to_native()` 刻意不写 `payload` 键（避免伪造复现信息）；
5. 跨工具**去重与冲突解释**（同一漏洞被多工具报告时的合并策略）尚未实现——
   当前仅通过 `finding_id` 提供归并所需的稳定身份。
