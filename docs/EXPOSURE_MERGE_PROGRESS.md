# 引擎合并推广进度（exposure 规则引擎）

> 关联：v2 任务卡「引擎治理」的批量合并推广。通用引擎 `engines/exposure_fingerprint_engine.py`
> + 规则 `core/data/exposure_rules.yaml`。

## 设计铁律（沿用原实现，不可破坏）
1. 先产品指纹、后漏洞特征 —— 指纹未命中直接跳过，普通站点不误报。
2. 全部只读探测（GET），无 OOB、无破坏性载荷。
3. `finding.type` 取 `title`（与原引擎逐字一致），保证验证链/去重/报告零回归。

## 合并进度

| 中间件 | 状态 | 规则 id | 原引擎位置 |
| --- | --- | --- | --- |
| Nacos | ✅ 已合并 | nacos_exposure | NacosExposureEngine |
| Apache Solr | ✅ 已合并 | solr_exposure（cores 即漏洞面） | SolrExposureEngine |
| Atlassian Confluence | ✅ 已合并 | confluence_exposure（AppLinks 降级） | ConfluenceExposureEngine |
| Prometheus | ✅ 本轮合并 | prometheus_exposure | PrometheusMetricsExposureEngine（logic_leak_engines_2.py:346） |
| container_platform | ➖ 不适用 | — | ContainerSecurityEngine 检测容器配置风险特征（docker.sock/特权容器），骨架不同于「指纹+probe」，保留原引擎 |
| 框架 0day 族 | ⏳ 计划 | — | Fastjson/Struts2/Shiro 等各自独立利用逻辑，待评估是否同骨架 |
| HTTP 逻辑族 | ⏳ 计划 | — | 待评估 |

## 收益
- 新增中间件**只需加 YAML 一条规则**，无需写 Python（社区可贡献）。
- 规则天然可配 fixture，顺带解决 G.1 benchmark（离线可重复评估）。

## 旧引擎处置
合并后旧引擎**保留双跑**，待 `finding` 语义一致验证通过后下线（避免回归）。
