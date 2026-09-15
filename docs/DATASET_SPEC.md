# DATASET_SPEC — 真实结果数据集格式与指标口径（v1）

> 版本化数据集：文件名含版本号（如 `_runtime_cache/datasets/real_results_v1.jsonl`）。
> schema 语义变更时升级新文件（v2），不原地改旧文件语义。
> 配套脚本：`scripts/dataset_metrics.py`（统计 + 门禁）。

## 1. 格式

JSONL：每行一个 JSON 对象，UTF-8，无 BOM。空行跳过。

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | string | 是 | 记录唯一标识，建议 `<engine>:<case_id>` |
| `target` | string | 是 | 目标 URL |
| `vulnerability` | string | 是 | 引擎名 / 漏洞类型 |
| `category` | string | 是 | 枚举，见下表 |
| `expected` | string | 是 | 期望结果（建议 `detect` / `no_detect`） |
| `actual` | string | 是 | 实际观察（建议 `detected` / `not_detected`） |
| `evidence` | string | 是 | 证据文本；**非空（strip 后）即视为有证据** |
| `reproduction` | string | 否 | 复现步骤/记录；**缺失或空 = 未提供**，指标计 0，脚本必须容忍缺失 |
| `environment` | string | 是 | 运行环境标识，如 `local-offline` |
| `timestamp` | string | 是 | UTC ISO8601（如 `2026-09-13T08:00:00Z`） |

坏行处置：JSON 解析失败、非对象、缺 `id`/`category`、或 `category` 不在枚举内的行 → 计入 `unknown` 并打印告警（stderr），不进入任何指标分母。

## 2. category 枚举与计数归属

| category | 含义 | 计数 |
| --- | --- | --- |
| `true_positive_verified` | 真实漏洞正例（已验证） | TP |
| `false_negative` | 有漏洞但漏报 | FN |
| `false_positive` | 误报 | FP |
| `true_negative_safe` | 安全反例（验证干净） | TN |
| `environment_error` | 环境异常（目标不可达/工具崩溃等） | **排除，单独计数** |
| `unknown` | 未验证 | **排除，单独计数** |

**铁律**：
1. `environment_error` 与 `unknown` **不得计入任何 TP/TN/FP/FN 分母**，只单独计数报告。
2. "未验证"（unknown / 坏行 / 缺字段）**绝不能当 TN**——把没测过的当干净会系统性低估误报率。

## 3. 指标定义（写死进 spec 与代码）

- `recall = TP / (TP + FN)`
- `precision = TP / (TP + FP)`
- `fp_rate = FP / (FP + TN)`
- `fn_rate = FN / (TP + FN)`
- `evidence_rate` = 有非空 `evidence` 的 TP 数 / TP 总数
- `reproduction_rate` = 有非空 `reproduction` 的 TP 数 / TP 总数（**仅报告，不设门禁**；当前为 0）

分母为 0 时该指标记 `None`（输出 `NA`）；对非零门禁阈值视为**不通过**（缺失数据不能凑达标，与 `scripts/benchmark.py` 的 `_meets_quality_gate` 同口径）。

## 4. 门禁（CLI）

```
python scripts/dataset_metrics.py --dataset _runtime_cache/datasets/real_results_v1.jsonl \
  [--min-recall R] [--max-false-rate F] [--min-evidence-rate E] [--min-precision P]
```

- `recall >= min_recall` 且 `fp_rate <= max_false_rate` 且 `evidence_rate >= min_evidence_rate`（及可选 precision）全部满足 → exit 0，否则 **exit 2**。
- 数据集文件缺失 / 完全无法解析 → exit 2。
- 输出：统计 JSON（一行）+ 人类可读摘要；`environment_error` / `unknown` 计数与各指标并列报告。

## 5. 种子数据约定（v1）

- 来源：`tests/fixtures/engines/*.yaml` 现有正反例（离线 mock，可重复）。
- 映射：`expect: positive` → `true_positive_verified`；`expect: negative` → `true_negative_safe`。
- `environment = "local-offline"`；`timestamp` 为生成时刻 UTC ISO8601。
- `reproduction` 字段刻意缺失（种子数据未做复现验证），用于锁定脚本对缺失字段的容忍。
