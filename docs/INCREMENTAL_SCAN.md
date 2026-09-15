# 增量扫描与基线比较（INCREMENTAL SCAN）

> C3 交付。实现：`src/vulnclaw/core/baseline.py`（指纹 + 比较，纯函数 + 最小 IO）。
> 验收：`tests/test_incremental_scan.py`（15 例）+ `tests/test_sp26_report_diff.py` 零回归。

## 1. 指纹口径（fingerprint_scan）

一次扫描归一为**确定性指纹**（同输入同输出，字段全排序）：

| 字段 | 内容 | 用途 |
|---|---|---|
| `assets` | 主机集合（target + subdomains + 各 URL host） | 资产变化 |
| `routes` | 路径集合 | 路由变化 |
| `params` | path → 参数名集合 | 参数变化 |
| `responses` | URL → {status, 长度, 内容 hash 前 8} | 响应变化 |
| `engines` | finding type → 条数 | 引擎结果变化 |
| `findings` | finding_id → {status, severity, type, url} | 发现级状态与严重度 |

fail-closed：非 dict 输入 → `ValueError`（不猜测输入形态）；缺失字段按空集合处理，**不编造**。

## 2. 比较语义（compare_with_baseline）

| 桶 | 判定 |
|---|---|
| `added` | 本次有、基线无（且状态非 reopened） |
| `unchanged` | 两侧同状态同严重度 |
| `changed` | 状态或严重度变化（附 status_from/to、severity_from/to） |
| `fixed` | 基线活跃、本次消失 → **修复候选** |
| `removed` | 基线已处置（治理态）、本次消失 → 不再追踪 |
| `reopened` | 基线已处置、本次又活跃；或本次状态即 reopened |
| `surface.*` | 资产/路由/参数/响应/引擎的 added/removed/changed/unchanged |

降级（fail-closed，均为 `degraded=true`）：

- `current` 不可解析 → 空 diff + `reason`（**不产出任何判定**）；
- `baseline` 不可解析 → current 全量计入 `added`（**宁多报不漏报**）；
- `diff_has_changes(degraded)` → **恒为 true**（无法判定不得静默当"无变化"，否则退出码骗人）。

## 3. 增量 ∪ 基线 ≈ 全量（正确用法）

`fixed` 的判定前提是"本次**扫过**该范围"。因此**部分扫描直接 compare 会把未扫范围的既有
finding 误判为 fixed**（已知陷阱，`tests/test_incremental_scan.py::test_partial_scan_must_be_merged_before_compare`
已固化该语义）。正确用法：

```text
基线（A+B）
  ├─ 未重扫部分：沿用基线 finding
  └─ 重扫部分  ：用本次结果替换
        ↓
      merged 视图  ──compare──▶ 与"全量重扫"对基线的结论完全一致
```

`test_merged_incremental_equals_full_rescan` 对此做了逐桶（added/fixed/unchanged/changed/
removed/reopened）等价断言。

## 4. 保存与加载 / CLI

```python
from vulnclaw.core.baseline import save_baseline, load_baseline, compare_with_baseline
path = save_baseline(scan_report, "")          # 缺省落 _runtime_cache/baselines/<target>.json
diff = compare_with_baseline(current_report, load_baseline(path))
```

CLI（建议接线，`scan.py` 由 C3 成员落地）：

```powershell
python scan.py baseline-diff --baseline _runtime_cache/baselines/app.example.json --current report.json --json
# 退出码：0=无变化；2=有变化（或 degraded）
```

## 5. 限制（如实）

- 指纹中的 `responses` 摘要只保留 hash 前 8 位——用于"内容是否变化"，不用于内容取证；
- 未实现跨主机/跨项目的基线聚合（单 target 一文件）；
- 响应摘要的采集依赖 finding 载荷（`response`/`length`/`body` 字段存在时才有值）。
