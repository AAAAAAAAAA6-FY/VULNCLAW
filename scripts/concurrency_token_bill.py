#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""J.1 并发 token 账单（静态量化视图，来自代码审查快照）。

清单 v2 组 J：评审关注「LLM 调用失败率/Tool 失败率」但无量化成本视图。本脚本从代码审查
提取各并发控制点（asyncio.Semaphore 上限）与成本路由站点（cost_router 的
pre_screen_candidates max_tokens=400），输出「若满并发，单轮理论最大 token 消耗」账单。

说明：
  - 并发上限为代码审查快照（值取自 src/vulnclaw 下 asyncio.Semaphore(N) 调用点）；
    若后续调整并发，请同步本表。
  - 真实运行时账单应使用 UsageLedger 的 site 维度（filter:prescreen / verify:cross /
    verify:batch），本脚本给的是「理论上限」参考。
  - token 单位为相对值（非真实价格）；prescreen 用 cost_router 实测 max_tokens=400，
    其余路径按 2000 粗估单次调用。

用法：python scripts/concurrency_token_bill.py
"""
from __future__ import annotations

import sys

# (并发控制点, 上限, 单次调用 max_tokens 粗估)
CONCURRENCY_POINTS = [
    ("orchestrator.execute_semaphore", 7, 2000),
    ("phases_verify.verification_semaphore", 4, 2000),
    ("directory_ffuf.run_ffuf_async", 20, 200),
    ("recon.passive_crawl(get_safe_concurrency or 16)", 16, 2000),
    ("net_engines.DNS_CONCURRENCY", 10, 500),
    ("cve_nuclei.sem", 4, 2000),
    ("ai_core._semaphore", 2, 2000),
    ("bundle_engine_semaphore", 2, 2000),
    ("burp.concurrency(max 16)", 16, 2000),
]

PRESCREEN_MAX_TOKENS = 400  # cost_router.pre_screen_candidates max_tokens（实测）


def main() -> int:
    print("| 并发控制点 | 上限 | 单次 max_tokens | 理论 token/轮(相对) |")
    print("|---|---|---|---|")
    total = 0
    for name, cc, mt in CONCURRENCY_POINTS:
        rel = cc * mt
        total += rel
        print(f"| {name} | {cc} | {mt} | {rel} |")
    print(f"PRESCREEN_MAX_TOKENS={PRESCREEN_MAX_TOKENS}")
    print(f"TOTAL_RELATIVE_TOKENS_PER_ROUND={total}")
    print("说明：相对单位（非真实价格）；prescreen 用 cost_router 实测 400，其余按 2000 粗估。"
          "真实成本用 UsageLedger site 维度（filter:prescreen/verify:cross/verify:batch）。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
