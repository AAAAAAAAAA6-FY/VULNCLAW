# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/bandit_train.py
"""
SP17.1 RL 反馈飞轮：用真实 JSONL 样本训练轻量决策策略。

输出策略文件（bandit_policy.json）：
  {
    "version": 1,
    "trained_at": ...,
    "samples": N,
    "rate_threshold": 0.12,          # 组合命中率低于该值的推荐降权
    "calibrated_influence": 2,       # 依据样本量校准后的影响幅度建议
    "combos": {key: {"n":N,"hit_rate":r,"action":"boost|penalty|hold"}},
    "engine_rates": {engine: hit_rate}
  }

消费：ContextualBandit 可选加载策略（替代纯 Thompson）——见 bandit.py
      ContextualBandit.from_policy(policy_path)（SP17.1 接线）。

训练方法（零新依赖、可解释、防过拟合）：
1. 每个组合 hit_rate，最低样本数 min_samples=5 才参与判定；
2. 全局基线 = 全部组合加权平均命中率；rate > 1.5x 基线 => boost，
   rate < 0.5x 基线 => penalty，其余 hold；
3. calibrated_influence：样本量 < 50 时保守取 1（数据不够不敢动大），
   50-199 -> 2，>=200 -> 3（有量才加大肌肉记忆）。

纪律：纯 stdlib；坏行跳过；样本不足仍出策略（全 hold + 提示）；无 emoji。
"""
import argparse
import json
import time
from pathlib import Path

from vulnclaw.ai.v100.bandit_report import load_feed

MIN_SAMPLES_COMBO = 5
MAX_COMBOS_IN_POLICY = 500


def train(rows: list[dict]) -> dict:
    """基于真实样本训练策略（保守、可解释）。"""
    total = len(rows)
    if not total:
        return {
            "version": 1,
            "trained_at": round(time.time(), 3),
            "samples": 0,
            "note": "no sample yet，策略为空（保持 Thompson 默认）",
            "combos": {},
            "engine_rates": {},
        }
    hits_total = sum(1 for r in rows if bool(r.get("hit")))
    baseline = hits_total / total

    # 引擎级别命中率
    from collections import defaultdict
    eng_stat: dict[str, list[int]] = defaultdict(list)
    for r in rows:
        parts = str(r.get("key") or "").split("|")
        eng = parts[2] if len(parts) > 2 else ""
        eng_stat[eng].append(1 if bool(r.get("hit")) else 0)
    engine_rates = {
        k: round(sum(v) / len(v), 3) for k, v in sorted(eng_stat.items())
    }

    # 组合级别判定
    from collections import defaultdict as _dd
    combo_hit: _dd = _dd(int)
    combo_n: _dd = _dd(int)
    for r in rows:
        key = str(r.get("key") or "")
        combo_hit[key] += 1 if bool(r.get("hit")) else 0
        combo_n[key] += 1
    combos: dict[str, dict] = {}
    for key, n in combo_n.items():
        if n < MIN_SAMPLES_COMBO:
            continue  # 样本不足不参与，防过拟合
        rate = combo_hit[key] / n
        if baseline > 0:
            ratio = rate / baseline
            if ratio >= 1.5:
                action = "boost"
            elif ratio <= 0.5:
                action = "penalty"
            else:
                action = "hold"
        else:
            action = "boost" if rate > 0 else "hold"
        combos[key] = {"n": n, "hit_rate": round(rate, 3), "action": action}
        if len(combos) >= MAX_COMBOS_IN_POLICY:
            break

    # 样本量的校准影响幅度
    if total < 50:
        calibrated = 1
    elif total < 200:
        calibrated = 2
    else:
        calibrated = 3

    return {
        "version": 1,
        "trained_at": round(time.time(), 3),
        "samples": total,
        "baseline_hit_rate": round(baseline, 4),
        "rate_threshold": round(max(0.05, baseline * 0.5), 4),
        "calibrated_influence": calibrated,
        "engine_rates": engine_rates,
        "combos": combos,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RL 反馈飞轮：训练轻量策略")
    ap.add_argument("--feed", required=True, help="bandit_feedback.jsonl 路径")
    ap.add_argument("--out", default="bandit_policy.json", help="策略输出路径")
    args = ap.parse_args(argv)

    rows = load_feed(args.feed)
    policy = train(rows)
    Path(args.out).write_text(
        json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    boosts = sum(1 for c in policy["combos"].values() if c["action"] == "boost")
    penalties = sum(1 for c in policy["combos"].values() if c["action"] == "penalty")
    print(
        f"policy written: {args.out} (samples={policy['samples']} "
        f"combos={len(policy['combos'])} boost={boosts} penalty={penalties})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())