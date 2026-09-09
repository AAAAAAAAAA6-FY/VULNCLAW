# 整改清单与验证结果

日期：2026-09-09 · 靶场：local_lab（127.0.0.1:8090，真值 10 端点 + 1 负样本）
基准：整改前（2026-09-07 同靶场报告）**检出率 0.0%（TP=0/FN=10，报告仅 1 条 finding）**

---

## 一、真扫暴露的问题与修复

| 编号 | 问题 | 根因 | 修复 | 文件 |
|---|---|---|---|---|
| K | 任务卡死 → worker 永久空转 | `stale=300s` 任务使 `pending` 恒非空 → `is_drained()` 永远 False → sentinel 不广播 | watchdog 强制回收 >300s 滞留任务（`complete_task(success=False)` + 清 `_task_pick_ts`） | `phases_executor.py` |
| L | StreamVerify 整批验证丢失 | 绑定后 `self._probe_before_ai(v)` 偶发把 `v` 当 self，报 `missing 'vuln'` | 改为模块函数显式传参 `_probe_before_ai(self, v)` | `phases_verify.py` |
| M | nuclei 时间黑洞 | 每端点 300s 超时、exit=-1、0 结果，仍逐端点重试（extras 预算 1704s） | 单端点超时封顶 120s + 连续疑似超时 3 次熔断剩余目标 | `cve_nuclei.py` |
| N | OOB 熔断误判 | `_poll_*` 内部吞异常返回空 → 被当成"目标没回连"累加 miss → 误判"外发封禁" | 新增 `_last_poll_error`；轮询故障不计入目标级 miss | `oob_channel.py` |
| O | interactsh 注册永远失败 | 实跑 `-h` 确认该 client **不支持 `-sf`/`-nf`**（传之打印 usage 并 exit 1），只能降级明文 dnslog | 去掉 `-sf`/`-nf`；因无 `-sf` 无法"重启续会话"，改为**常驻子进程 JSONL 流式订阅**（atexit + `aclose()` 兜底，不泄漏） | `oob_channel.py` |
| P | 孤儿协程泄漏 217 个 | A2.4 竞争协作中 `t.cancel()` **之后没有 await**，任务停在 cancelling 持续堆积 | `cancel()` 后补 `await asyncio.gather(*pending, return_exceptions=True)` | `phases_executor.py` |
| Q | interactsh 每次白等 8s | 国内连不上 oast 公共服务器，注册必超时，但每次仍先试 interactsh | 通道级快速熔断：连续失败 2 次即熔断 300s，期间直走 dnslog | `oob_channel.py` |

### 已由作者自行修复（本轮核对确认）
- smart_queue：`total_added` 守恒、`_completed_tasks` 改保序 dict、`_param_task_map` 清理、`pending_count` 去重
- 封板窗口：`_MinObserve=1.0` 双条件（原 400ms 会误杀延迟入队的动态补测任务）

---

## 二、验证结果（2026-09-09 13:59，报告 `report_http___127_0_0_1_8090_20260909_135902.json`）

| 指标 | 整改前 | 整改后 | 目标 | 结论 |
|---|---|---|---|---|
| 检出率 | 0.0% (TP 0/10) | **100% (TP 10/10)** | ≥80% | 达标 |
| 误报率 | — | **0%**（负样本 `/safe` 未出现） | ≤5% | 达标 |

命中端点：`/xss`、`/sqli`、`/ssti`、`/nosql`、`/ldap`、`/deser`、`/upload`、`/.env`、`/cors`、`/redirect`（全部 10 个）

---

## 三、遗留与下一步

1. **interactsh 在国内不可用**：oast 公共服务器超时，实际仍走明文 `dnslog.cn`。
   → 建议配置自部署服务 `OOB_INTERACTSH_SERVER`，否则 OOB 证据走明文通道有被 MITM 伪造的风险。
2. **报告体量过大**：单次扫描报告约 3.8 万行。虽负样本为 0，但 finding 数量仍需收敛（成本与可读性）。
3. **孤儿协程**：审计 P（A2.4 竞争协作 `cancel()` 后补 `await`）已修。本次真扫 D1.1 仍报
   70 → 435 → 92 个，但**位置已变为 `phases_executor.py:762`**（`_execute_engine_bundle`
   的 `_run_one` 子任务），且**随任务量先涨后落、最终收敛**——属正常并发波动，非无界泄漏
   （整改前是单调堆积到 217 且不回落）。彻底清零需给 bundle 的 `gather` 加超时/取消保护，列为观察项。
4. **高难度靶场**：当前仅基础靶场（10 端点）。WAF 过滤 SQLi、时间盲注、属性注入 XSS、双重编码穿越、JWT、IDOR 等场景尚未覆盖。

---

## 四、建议的长期方向（与本轮整改无关，供参考）

- 引擎广度属"弱模型代偿资产"，会随模型变强而贬值；应持续加码**验证层、合规层、知识资产、成本分层**。
- `verification_gateway` 具备"消费任意扫描器 SARIF 输出 → 去伪 → 防篡改凭证链"的能力，是可独立于扫描器存在的**质检/出证服务**，建议作为第一等产品推进（定位为"AI 扫描结果的质检层"，把上游 agent 变成输入而非对手）。
