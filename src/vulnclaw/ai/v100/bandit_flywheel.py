# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/bandit_flywheel.py
"""
SP18 数据飞轮：批处理入口——聚合最新反馈样本、重训策略、写新策略、给变更摘要。

把 SP17.1 的"样本 -> 策略 -> 生效"从手动变成可持续闭环：
  run_flywheel(feed_dir, policy_out, min_new_samples=10) -> dict 摘要
- 扫描 feed_dir 下所有 bandit_feedback*.jsonl（可能多个文件，按文件聚合）；
- 简单增量统计：全量重算 total_samples，以 policy_out 已存在时的
  samples 为"上次处理后基线"，差值即新增样本量（防抖依据）；
- 新增样本 < min_new_samples 时不重训（防抖），返回 ran=False；
- 足够则复用 bandit_train.train 训练并写 policy_out，返回 ran=True 摘要。

消费方：外部定时/手动调用（主线程收口统一接线），不接 CLI、不碰 settings.py。
纪律：纯 stdlib；只读复用 bandit_report.load_feed / bandit_train.train；
坏行静默跳过；空 feed 不出错；无 emoji。
"""
import json
from pathlib import Path

from vulnclaw.ai.v100.bandit_report import load_feed
from vulnclaw.ai.v100.bandit_train import train

FEED_GLOB = "bandit_feedback*.jsonl"


def _load_policy_meta(policy_out: str) -> int:
    """读回已有策略的样本数（上次处理后基线）；不存在/损坏返回 0。"""
    p = Path(policy_out)
    if not p.exists():
        return 0
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return int(data.get("samples") or 0)
    except (ValueError, TypeError, OSError):
        return 0


def run_flywheel(feed_dir: str, policy_out: str, min_new_samples: int = 10) -> dict:
    """数据飞轮批处理：聚合样本 -> 防抖判定 -> 重训写策略 -> 变更摘要。

    feed_dir：反馈样本目录（含 bandit_feedback*.jsonl，多个文件按名聚合）；
    policy_out：策略输出路径（bandit_policy.json）；
    min_new_samples：新增样本下限，低于则不重训（防抖）。

    返回：
      ran=False -> {"ran", "reason", "total_samples", "prev_samples",
                    "new_samples", "combos", "policy_path"}
      ran=True  -> {"ran", "samples", "combos", "boost", "penalty",
                    "policy_path", "baseline_hit_rate", "total_samples",
                    "prev_samples", "new_samples"}
    """
    feed_dir = str(feed_dir or "")
    policy_out = str(policy_out or "")
    if not feed_dir:
        return {
            "ran": False,
            "reason": "no_feed_dir",
            "total_samples": 0,
            "prev_samples": 0,
            "new_samples": 0,
            "combos": 0,
            "policy_path": policy_out,
        }

    rows: list[dict] = []
    for fp in sorted(Path(feed_dir).glob(FEED_GLOB)):
        rows.extend(load_feed(str(fp)))
    total = len(rows)
    prev = _load_policy_meta(policy_out)
    new_samples = max(0, total - prev)
    combos_total = len({str(r.get("key") or "") for r in rows})

    base = {
        "total_samples": total,
        "prev_samples": prev,
        "new_samples": new_samples,
        "combos": combos_total,
        "policy_path": policy_out,
    }
    if new_samples < min_new_samples:
        return {"ran": False, "reason": "insufficient_new_samples", **base}

    policy = train(rows)
    out = Path(policy_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(policy, ensure_ascii=False, indent=2), encoding="utf-8")
    boosts = sum(1 for c in policy["combos"].values() if c["action"] == "boost")
    penalties = sum(1 for c in policy["combos"].values() if c["action"] == "penalty")
    return {
        "ran": True,
        "samples": policy["samples"],
        "combos": len(policy["combos"]),
        "boost": boosts,
        "penalty": penalties,
        "policy_path": policy_out,
        "baseline_hit_rate": policy.get("baseline_hit_rate", 0.0),
        **base,
    }


__all__ = ["run_flywheel"]