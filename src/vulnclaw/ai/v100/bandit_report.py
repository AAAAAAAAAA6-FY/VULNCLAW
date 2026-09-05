# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/bandit_report.py
"""
SP17.1 RL 反馈飞轮：反馈样本聚合报表（JSON + 人读文本双出）。

输入：bandit_feedback.jsonl（ContextualBandit._write_feed 落盘格式）
  {"ts":..., "key":"target|param|engine", "hit":true|false, "hits":N, "fails":N}
输出：
  JSON：{generated_at, total_samples, combos, by_engine, by_param_hash, top_combos}
  文本：控制台人读汇总（高产出 / 高沉默 / 引擎分布）

纪律：纯 stdlib；坏行跳过；空输入仍出空报表（不报错）；无 emoji。
"""
import argparse
import json
import time
from collections import Counter
from pathlib import Path


def load_feed(path: str) -> list[dict]:
    """读取 JSONL 反馈样本（坏行静默跳过）。"""
    rows = []
    p = Path(path)
    if not p.exists():
        return rows
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    rows.append(obj)
            except (ValueError, TypeError):
                continue
    return rows


def aggregate(rows: list[dict]) -> dict:
    """聚合为报表 dict。"""
    combos: dict[str, dict] = {}
    by_engine: Counter = Counter()
    for r in rows:
        key = str(r.get("key") or "")
        hit = bool(r.get("hit"))
        h = int(r.get("hits") or 0)
        fl = int(r.get("fails") or 0)
        parts = key.split("|")
        engine = parts[2] if len(parts) > 2 else ""
        by_engine[engine] += 1
        st = combos.setdefault(key, {"hits": 0, "fails": 0})
        st["hits"] += int(hit)
        st["fails"] += int(not hit)
        # 兼容旧格式（无逐条 hit 字段）：用 hits/fails 总数字段取 max 兜底
        st["hits"] = max(st["hits"], h)
        st["fails"] = max(st["fails"], fl)
    top = []
    for k, st in combos.items():
        n = st["hits"] + st["fails"]
        if not n:
            continue
        top.append({
            "key": k,
            "hits": st["hits"],
            "fails": st["fails"],
            "hit_rate": round(st["hits"] / n, 3),
        })
    top.sort(key=lambda x: (x["hits"], x["hit_rate"]), reverse=True)
    return {
        "generated_at": round(time.time(), 3),
        "total_samples": len(rows),
        "total_combos": len(combos),
        "by_engine": dict(by_engine.most_common()),
        "top_combos": top[:50],
    }


def render_text(agg: dict) -> str:
    """人读文本渲染（控制台）。"""
    lines = []
    lines.append("RL 反馈飞轮报表")
    lines.append(f"样本总数: {agg['total_samples']}  组合数: {agg['total_combos']}")
    if agg["by_engine"]:
        lines.append("引擎分布:")
        for eng, cnt in agg["by_engine"].items():
            lines.append(f"  {eng or '(空)'}: {cnt}")
    lines.append("Top 组合 (按命中数):")
    for c in agg["top_combos"][:15]:
        lines.append(
            f"  hits={c['hits']} fails={c['fails']} rate={c['hit_rate']:.3f}  {c['key']}"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RL 反馈飞轮报表")
    ap.add_argument("--feed", required=True, help="bandit_feedback.jsonl 路径")
    ap.add_argument("--out", default="", help="可选：JSON 报表输出路径（默认 stdout）")
    args = ap.parse_args(argv)

    rows = load_feed(args.feed)
    agg = aggregate(rows)
    print(render_text(agg))
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            json.dumps(agg, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())