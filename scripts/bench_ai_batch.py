#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""P1-4：AI 判定批量化对照实验（串行 vs 批量）。

为什么需要这个实验：
  批量判定把 N 次 LLM 调用压成 ceil(N/batch) 次，理论收益 = 调用数/耗时同步下降；
  但批量 prompt 可能让模型"张冠李戴"（判定质量下降）——这不是纯粹的无损优化。
  本脚本用同一组带**隐藏真值**的候选漏洞，分别走串行与批量两条管线，量出：
    1) API 调用次数与墙钟耗时（收益）
    2) 两管线判定结果 vs 真值的准确率（质量）
    3) 两管线判定结果互相的一致率（稳定性）

两层模式：
  mock（默认）：确定性 Mock 判定官——按证据标记（reflect=true / probe 失败）判定，
    与"具体是不是第 i 条"无关，因此能纯粹验证管线本身（分组/解析/index 映射）不出错；
    --degrade p 可注入"批量张冠李戴"概率，演示质量风险。
  --live：用真实 LLM（get_llm_client().ask）跑同一对照，消耗真实 token。

用法：
    python scripts/bench_ai_batch.py                     # mock 全离线
    python scripts/bench_ai_batch.py -n 16 --batch 4 --degrade 0.2
    python scripts/bench_ai_batch.py --live              # 真实 LLM（花钱）
"""
import argparse
import asyncio
import json
import re
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

# ============================================================
# 合成数据：隐藏真值的漏洞候选
# ============================================================

def build_items(n: int) -> List[Dict]:
    """生成 n 个候选：偶数序号 = 真漏洞（reflect 证据），奇数序号 = 误报（probe 失败）。

    真值嵌在证据文本里（内容式，非位置式），Mock 判定官据此判定——
    串行/批量两种 prompt 下判定依据完全相同，管线正确性才可被纯粹度量。
    """
    items = []
    for i in range(n):
        truth = (i % 2 == 0)
        if truth:
            evidence = (
                f"载荷注入后响应包含回显标记 uniq-{i}；"
                f"probe 观测: ok=true, reflect=true, marker=uniq-{i}"
            )
        else:
            evidence = (
                f"响应无差异，特征词未出现；"
                f"probe 观测: ok=false, reason=timeout"
            )
        items.append({
            "index": i,
            "type": "sqli" if i % 4 == 0 else "xss",
            "url": f"http://127.0.0.1:8090/item{i}?q=1",
            "param": "q",
            "payload": f"' OR 1=1--",
            "evidence": evidence,
            "truth": truth,
        })
    return items


RULES = (
    "【裁决规则】\n"
    "1. 反射/回显类漏洞：只有载荷回显（reflect=true）或明确响应差分才可 confirm；\n"
    "2. 无客观证据或 probe 缺失/失败（ok=false）：必须判 confirmed=false 且 confidence=low（证据不足）；\n"
    "3. 绝不猜测，宁可证据不足。\n"
)


def item_block(i: int, item: Dict) -> str:
    return (
        f"[{i}] type={item['type']} | url={item['url']} | param={item['param']} | "
        f"payload={item['payload']}\n"
        f"    证据包: {item['evidence']}"
    )


def build_batch_prompt(items: List[Dict]) -> str:
    """与 phases_verify._verify_cross_batch 同构的批量 prompt。"""
    lines = [item_block(i, it) for i, it in enumerate(items)]
    return (
        "你是 Web 漏洞证据型验证官。以下是同一 URL 与参数上多个检测引擎给出的漏洞候选，"
        "每候选附【证据包】。请逐条独立裁决，不受同组其他条目影响。\n\n"
        + RULES
        + "\n".join(lines)
        + "\n\n只输出 JSON 数组，不要任何解释性文字，格式：\n"
        '[{"index": 0, "confirmed": true, "confidence": "high", "reason": "证据式理由"}]\n'
        "confidence 只能是 high / medium / low。"
    )


# ============================================================
# 判定官：Mock（确定性内容式）与 Live（真实 LLM）
# ============================================================

class MockJudge:
    """内容式确定性判定 + 可注入的'批量张冠李戴'模拟。

    - 从 prompt 文本里按证据标记推导每条结论（与条目顺序无关）；
    - batch 模式下以 degrade_p 概率把结论错位一档（模拟批量导致的质量退化），
      用于演示"批量不是纯无损"——真实模型的退化率要用 --live 实测。
    """

    def __init__(self, latency_s: float = 1.2, degrade_p: float = 0.0):
        self.latency_s = latency_s
        self.degrade_p = degrade_p
        self.calls = 0

    def _verdict(self, text: str) -> bool:
        # 内容式判定：回显命中 → true；probe 失败 → false（与 _verify_cross_batch 规则一致）
        return "reflect=true" in text and "ok=false" not in text

    async def ask(self, prompt: str) -> str:
        self.calls += 1
        if self.latency_s > 0:
            await asyncio.sleep(self.latency_s)
        blocks = re.findall(r"\[(\d+)\].*?\n    证据包: ([^\n]+)", prompt, re.DOTALL)
        verdicts = {int(idx): self._verdict(ev) for idx, ev in blocks}
        if len(verdicts) > 1 and self.degrade_p > 0 and (hash(prompt) % 100) / 100 < self.degrade_p:
            # 模拟"张冠李戴"：全部结论错位一位（确定性，可复现）
            keys = sorted(verdicts)
            shifted = {k: verdicts[keys[(keys.index(k) + 1) % len(keys)]] for k in keys}
            verdicts = shifted
        if len(verdicts) == 1:
            k = next(iter(verdicts))
            return json.dumps([{"index": k, "confirmed": verdicts[k],
                                "confidence": "high" if verdicts[k] else "low",
                                "reason": "mock"}], ensure_ascii=False)
        return json.dumps(
            [{"index": k, "confirmed": v, "confidence": "high" if v else "low", "reason": "mock"}
             for k, v in sorted(verdicts.items())],
            ensure_ascii=False,
        )


class LiveJudge:
    """真实 LLM 判定（消耗 token）。接口对齐 ai.core.LLMClient.ask。"""

    def __init__(self, task_type: str = "verify"):
        from vulnclaw.ai.core import get_llm_client
        self._client = get_llm_client(force_new=False)
        self.task_type = task_type
        self.calls = 0

    async def ask(self, prompt: str) -> str:
        self.calls += 1
        return await self._client.ask(
            prompt,
            system="只输出 JSON，不要 Markdown 代码块。",
            temperature=0.1,
            max_tokens=1500,
            task_type=self.task_type,
        )


# ============================================================
# 两条管线
# ============================================================

def _parse_verdicts(raw: str, n: int) -> List[Optional[bool]]:
    """把 LLM 响应解析成 [bool|None]*n（None=缺失，按 fail-closed 记 False 统计）。"""
    m = re.search(r"\[.*\]", raw, re.DOTALL) or re.search(r"\{.*\}", raw, re.DOTALL)
    if not m:
        return [None] * n
    try:
        data = json.loads(m.group())
    except json.JSONDecodeError:
        return [None] * n
    out: Dict[int, bool] = {}
    for j, item in enumerate(data if isinstance(data, list) else [data]):
        idx = item.get("index", j if isinstance(data, list) else 0)
        if isinstance(idx, int) and 0 <= idx < n:
            out[idx] = bool(item.get("confirmed", False))
    return [out.get(i) for i in range(n)]


async def run_serial(items: List[Dict], judge) -> List[Optional[bool]]:
    results = []
    for it in items:
        raw = await judge.ask(build_batch_prompt([it]))
        results.extend(_parse_verdicts(raw, 1))
    return results


async def run_batch(items: List[Dict], judge, batch_size: int) -> List[Optional[bool]]:
    results: List[Optional[bool]] = []
    for i in range(0, len(items), batch_size):
        group = items[i:i + batch_size]
        raw = await judge.ask(build_batch_prompt(group))
        results.extend(_parse_verdicts(raw, len(group)))
    return results


def _accuracy(verdicts: List[Optional[bool]], items: List[Dict]) -> float:
    ok = sum(1 for v, it in zip(verdicts, items) if v is not None and v == it["truth"])
    return ok / len(items) if items else 0.0


def _consistency(a: List[Optional[bool]], b: List[Optional[bool]]) -> float:
    same = sum(1 for x, y in zip(a, b) if x is not None and x == y)
    return same / len(a) if a else 0.0


async def experiment(n: int, batch_size: int, judge, latency_s: float) -> Dict:
    items = build_items(n)
    t0 = time.perf_counter()
    serial_v = await run_serial(items, judge)
    t_serial = time.perf_counter() - t0
    serial_calls = judge.calls

    t0 = time.perf_counter()
    batch_v = await run_batch(items, judge, batch_size)
    t_batch = time.perf_counter() - t0
    batch_calls = judge.calls - serial_calls

    return {
        "n": n,
        "batch_size": batch_size,
        "serial": {"calls": serial_calls, "time_s": round(t_serial, 2),
                   "accuracy": _accuracy(serial_v, items)},
        "batch": {"calls": batch_calls, "time_s": round(t_batch, 2),
                  "accuracy": _accuracy(batch_v, items)},
        "consistency": _consistency(serial_v, batch_v),
        "calls_saved": serial_calls - batch_calls,
        "latency_s": latency_s,
    }


def report(res: Dict, mode: str) -> None:
    print(f"\n===== P1-4 串行 vs 批量 对照实验（{mode} 模式）=====")
    print(f"候选数 n={res['n']}  batch={res['batch_size']}  模拟单次时延={res['latency_s']}s")
    print(f"{'管线':<8}{'API调用':>8}{'耗时(s)':>10}{'判真值准确率':>14}")
    for name in ("serial", "batch"):
        r = res[name]
        print(f"{name:<8}{r['calls']:>8}{r['time_s']:>10}{r['accuracy']:>14.0%}")
    print(f"两管线判定一致率: {res['consistency']:.0%}   调用节省: {res['calls_saved']} 次")
    if res["batch"]["accuracy"] < res["serial"]["accuracy"]:
        print("⚠️ 批量准确率下降 → 批量化属'中风险优化'，上线前必须用 --live 实测退化率")


async def main_async() -> None:
    ap = argparse.ArgumentParser(description="P1-4 AI 判定批量化对照实验")
    ap.add_argument("-n", type=int, default=12, help="候选漏洞数")
    ap.add_argument("--batch", type=int, default=4, help="批量大小")
    ap.add_argument("--latency", type=float, default=1.2, help="mock 模式模拟单次 LLM 时延(s)")
    ap.add_argument("--degrade", type=float, default=0.0,
                    help="mock 模式注入'批量张冠李戴'概率 0~1（演示质量风险）")
    ap.add_argument("--live", action="store_true", help="用真实 LLM 跑（消耗 token）")
    args = ap.parse_args()

    if args.live:
        judge = LiveJudge()
        res = await experiment(args.n, args.batch, judge, latency_s=0.0)
        report(res, "live")
    else:
        judge = MockJudge(latency_s=args.latency, degrade_p=args.degrade)
        res = await experiment(args.n, args.batch, judge, latency_s=args.latency)
        report(res, "mock")


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
