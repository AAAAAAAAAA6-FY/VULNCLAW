# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""SP18（A 线）数据飞轮 单元测试。

覆盖（全部离线，不触网不调 AI）：
a) 样本足够：ran=True 且策略文件生成、摘要字段齐全（含 combos/boost/penalty/
   baseline_hit_rate/samples），判定与 bandit_train.train 一致；
b) 样本不足（写 3 行但 min_new_samples=10）：ran=False 且不写 policy；
c) 空 feed_dir：不抛错、返回 ran=False；
d) 与 bandit_train.train 判定一致：boost/penalty 数>0 时摘要如实。
"""
import json

from vulnclaw.ai.v100 import bandit_train
from vulnclaw.ai.v100.bandit_flywheel import run_flywheel


def _write_feed(feed_dir, lines, name="bandit_feedback.jsonl"):
    p = feed_dir / name
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.writelines(ln if ln.endswith("\n") else ln + "\n" for ln in lines)
    return p


def _rows_boost_penalty():
    """返回含 boost（多 hit 组合）与 penalty（全静默组合）的样本行。"""
    lines = []
    for _ in range(7):   # sqli 组合 10 行：7 hit -> boost
        lines.append(json.dumps({"key": "h|p|sqli", "hit": True}))
    for _ in range(3):
        lines.append(json.dumps({"key": "h|p|sqli", "hit": False}))
    for _ in range(10):  # xss 组合 10 行：0 hit -> penalty
        lines.append(json.dumps({"key": "h|p|xss", "hit": False}))
    assert len(lines) == 20
    return lines


def test_flywheel_trains_and_writes_policy(tmp_path):
    feed_dir = tmp_path / "feed"
    policy = tmp_path / "bandit_policy.json"
    _write_feed(feed_dir, _rows_boost_penalty())
    summary = run_flywheel(str(feed_dir), str(policy), min_new_samples=10)

    assert summary["ran"] is True
    assert policy.exists()  # 策略文件已生成
    # 摘要字段齐全
    for k in ("samples", "combos", "boost", "penalty", "policy_path",
              "baseline_hit_rate", "total_samples", "prev_samples", "new_samples"):
        assert k in summary
    assert summary["samples"] == 20
    assert summary["total_samples"] == 20
    assert summary["new_samples"] == 20
    assert summary["prev_samples"] == 0
    # 与 bandit_train.train 判定一致（boost/penalty 数如实）
    loaded = json.loads(policy.read_text(encoding="utf-8"))
    boost = sum(1 for c in loaded["combos"].values() if c["action"] == "boost")
    penalty = sum(1 for c in loaded["combos"].values() if c["action"] == "penalty")
    assert summary["boost"] == boost == 1
    assert summary["penalty"] == penalty == 1
    assert loaded["combos"]["h|p|sqli"]["action"] == "boost"
    assert loaded["combos"]["h|p|xss"]["action"] == "penalty"


def test_flywheel_skips_when_not_enough_new_samples(tmp_path):
    feed_dir = tmp_path / "feed"
    policy = tmp_path / "bandit_policy.json"
    # 仅 3 行，低于 min_new_samples=10
    _write_feed(feed_dir, [
        json.dumps({"key": "h|p|sqli", "hit": True}),
        json.dumps({"key": "h|p|sqli", "hit": True}),
        json.dumps({"key": "h|p|xss", "hit": False}),
    ])
    summary = run_flywheel(str(feed_dir), str(policy), min_new_samples=10)

    assert summary["ran"] is False
    assert summary["reason"] == "insufficient_new_samples"
    assert not policy.exists()  # 未写策略
    assert summary["total_samples"] == 3
    assert summary["new_samples"] == 3


def test_flywheel_empty_feed_dir_no_error(tmp_path):
    feed_dir = tmp_path / "empty_feed"
    feed_dir.mkdir(parents=True, exist_ok=True)
    policy = tmp_path / "bandit_policy.json"
    summary = run_flywheel(str(feed_dir), str(policy), min_new_samples=10)

    assert summary["ran"] is False
    assert summary["total_samples"] == 0
    assert not policy.exists()


def test_flywheel_matches_bandit_train_judgement(tmp_path):
    feed_dir = tmp_path / "feed"
    policy = tmp_path / "bandit_policy.json"
    lines = _rows_boost_penalty()
    _write_feed(feed_dir, lines)

    summary = run_flywheel(str(feed_dir), str(policy), min_new_samples=10)
    rows = [json.loads(x) for x in lines]
    expected = bandit_train.train(rows)  # 复用判定

    assert summary["ran"] is True
    assert summary["samples"] == expected["samples"]
    assert summary["combos"] == len(expected["combos"])
    assert summary["boost"] == sum(1 for c in expected["combos"].values()
                                   if c["action"] == "boost")
    assert summary["penalty"] == sum(1 for c in expected["combos"].values()
                                     if c["action"] == "penalty")
    assert summary["baseline_hit_rate"] == expected["baseline_hit_rate"]


def test_flywheel_aggregates_multiple_feed_files(tmp_path):
    feed_dir = tmp_path / "feed_multi"
    policy = tmp_path / "bandit_policy.json"
    lines = _rows_boost_penalty()  # 20 行
    _write_feed(feed_dir, lines[:10], name="bandit_feedback_a.jsonl")
    _write_feed(feed_dir, lines[10:], name="bandit_feedback_b.jsonl")
    summary = run_flywheel(str(feed_dir), str(policy), min_new_samples=10)

    assert summary["ran"] is True
    assert summary["total_samples"] == 20
    assert summary["samples"] == 20
    assert policy.exists()