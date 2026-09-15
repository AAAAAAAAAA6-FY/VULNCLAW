# 扫描资源预算与模式（RESOURCE BUDGET）

> 由 H 组（扫描成本优化）落地：`src/vulnclaw/core/cost_model.py` + `src/vulnclaw/core/scan_profiles.py`。
> 全部为纯函数/纯数据，无网络、无时钟，可离线审计。

## 1. 成本模型

`core/cost_model.py` 把"一轮扫描要发多少请求、花多少时间、产物多大"变成确定性估算：

| 函数 | 估算对象 | 单位 |
|---|---|---|
| `estimate_request_cost(engine, payload_count)` | 单引擎 × 单目标 | 请求数 / 秒 |
| `estimate_scan_cost(engines, targets, concurrency)` | 整轮扫描 | 请求数 / 秒 |
| `estimate_oob_polling_cost(tokens, interval, timeout)` | OOB 盲打等待 | 通道请求数 / 秒 |
| `estimate_report_cost(finding_count, detail)` | 报告产物 | 字节 / 秒 |
| `risk_benefit_ratio(severity, exposure, confidence)` | 风险收益比 | 0~10 |

口径要点：

- 1 成本单位 = 100 请求（请求类）或 200 KB（报告类），两类不可跨类比较；
- 每引擎的请求画像在 `ENGINE_COST_PROFILES` 显式登记（覆盖 80 引擎中的主要引擎，
  未登记走 `DEFAULT_ENGINE_COST = 1 请求/payload + 2 基线`）；
- 并发只摊薄墙钟（理想线性下界），不改变请求总数——真实耗时还会叠加限速/退避/AI 验证；
- 非法输入一律 `ValueError`/`TypeError`，**绝不静默取默认**（防止把参数写错伪装成低成本）。

## 2. 扫描模式（scan_profiles）

| 模式 | 引擎集 | payload 深度 | 并发 | 请求预算 | 报告 detail | 适用场景 |
|---|---|---:|---:|---:|---|---|
| `fast` | P0（10 引擎） | 4 | 10 | 2,000 | summary | 快速摸底 |
| `standard` | P0 + P1（29 引擎） | 8 | 5 | 20,000 | full | 默认推荐 |
| `deep` | P0 + P1 | 16 | 3 | 不限 | full | 尽量穷尽 |
| `low-noise` | 8 个高价值验证型 | 2 | 2 | 400 | summary | 生产窗口/低打扰 |
| `oob` | 盲打类（ssrf/xxe/log4shell/fastjson） | 6 | 3 | 1,500 | full | 带外专项 |
| `api` | API/鉴权/组件（12 引擎） | 6 | 5 | 4,000 | full | 接口专项 |
| `budget` | P0 + P1 | 4 | 5 | 1,000 | summary | 预算受限 |

引擎优先级（预算裁减的"先丢谁"事实源）：`PRIORITY_P0`（2）> `PRIORITY_P1`（1）> 未登记（0）。

## 3. 超限降级策略（apply_budget）

```python
from vulnclaw.core.scan_profiles import get_profile, apply_budget

result = apply_budget(get_profile("standard"), budget_requests=100)
result.dropped          # ('security_headers', 'info_leak', ...)  被裁引擎（顺序确定）
result.dropped_estimate # 被裁引擎原请求数合计
result.estimate.requests# 裁减后残余请求数
result.reason           # 人读原因；到最小集仍有超出时明确标注
```

规则（确定性、可解释、fail-closed）：

1. 裁减顺序固定：**低优先级 → 高成本 → 名称字典序**；
2. 循环裁减直到请求数进入预算，或只剩 1 个引擎（最小可用集不裁空，
   此时 `reason` 标注"已到最小集，无法继续裁减"）；
3. 绝不静默降级：被裁项全部随结果返回；
4. `budget_requests=0` 语义 = 不限。

## 4. 与 benchmark 请求计数对接

`scripts/benchmark.py` 的 `EVAL_REQUESTS` / `FIXTURE_REQUESTS` 是**实测**请求数，
`cost_model` 的估算是**先验**画像；两者可用于对账：估算偏差大 = 引擎画像需修正
（改 `ENGINE_COST_PROFILES` 即改口径，测试 `tests/test_cost_model.py` 锁数值）。

## 5. CLI 接线建议（尚未落地，供后续接入）

```text
scan.py scan -t <target> --profile fast            # 选用模式
scan.py scan -t <target> --profile standard --budget 5000   # 预算覆盖
```

接线方式：`scan_main.py` 参数解析后调用 `get_profile()` + `apply_budget()`，
把 `result.profile.engines`/`payload_depth`/`concurrency`/`report_detail` 传给扫描管线，
并在启动日志打印 `result.reason`（有裁减时）与 `result.estimate.as_dict()`。

> 遗留：CLI 接线与 `--profile/--budget` 参数尚未实现（H 组按边界约定只交付 core 模块）。
