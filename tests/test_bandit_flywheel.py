# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""SP17.1（A 线）RL 反馈飞轮收尾 单元测试。

覆盖（全部离线，不触网不调 AI）：
a) bandit_report：混合好坏行 feed 的聚合正确（total_samples / combo / 引擎）、
   坏行静默跳过、空文件不出错；
b) bandit_train：20 行 / 2 组合（其一 hits 多）训练出合理 baseline 与
   boost/penalty 判定，策略 JSON 可写回读；
c) bandit.py 策略加载：加载策略后 adjust() 在命中组合按 action 调整且 clamp
   于 [1,10]；未加载策略时回退纯 Thompson（monkeypatch betavariate 校验是否调用）。
"""
import json
import random

from vulnclaw.ai.v100 import bandit_report, bandit_train
from vulnclaw.ai.v100.bandit import ContextualBandit, bandit_key

# ---------- a) bandit_report ----------

def _write_feed(path, lines):
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(ln if ln.endswith("\n") else ln + "\n" for ln in lines)
    return path


def test_report_aggregates_mixed_feed(tmp_path):
    feed = tmp_path / "feed.jsonl"
    _write_feed(feed, [
        json.dumps({"key": "t|p|sqli", "hit": True, "hits": 1, "fails": 0}),
        "this is not valid json",
        json.dumps({"key": "t|p|sqli", "hit": False, "hits": 0, "fails": 1}),
        "[1, 2, 3]",  # 合法 JSON 但不是 dict -> 坏行
        "  ",  # 空白行
        json.dumps({"key": "t|q|xss", "hit": True, "hits": 1, "fails": 0}),
    ])
    rows = bandit_report.load_feed(str(feed))
    agg = bandit_report.aggregate(rows)
    assert agg["total_samples"] == 3          # 只有 3 条 dict 行
    assert agg["total_combos"] == 2
    combo = {c["key"]: c for c in agg["top_combos"]}
    assert combo["t|p|sqli"]["hits"] == 1
    assert combo["t|p|sqli"]["fails"] == 1
    assert combo["t|q|xss"]["hits"] == 1
    assert combo["t|q|xss"]["fails"] == 0
    assert agg["by_engine"].get("sqli") == 2
    assert agg["by_engine"].get("xss") == 1


def test_report_empty_file_no_error(tmp_path):
    feed = tmp_path / "empty.jsonl"
    feed.write_text("", encoding="utf-8")
    rows = bandit_report.load_feed(str(feed))
    agg = bandit_report.aggregate(rows)
    assert agg["total_samples"] == 0
    assert agg["total_combos"] == 0
    assert agg["top_combos"] == []


def test_report_missing_file_returns_empty(tmp_path):
    rows = bandit_report.load_feed(str(tmp_path / "nope.jsonl"))
    assert rows == []


# ---------- b) bandit_train ----------

def test_train_judges_combos_and_writes_policy(tmp_path):
    # 20 行、2 组合：其一 hits 多（boost），另一全沉默（penalty）
    rows = []
    for _ in range(7):
        rows.append({"key": "h|p|sqli", "hit": True})   # 7 hits
    for _ in range(3):
        rows.append({"key": "h|p|sqli", "hit": False})
    for _ in range(10):
        rows.append({"key": "h|p|xss", "hit": False})   # 0 hits
    assert len(rows) == 20
    policy = bandit_train.train(rows)
    assert policy["samples"] == 20
    assert policy["baseline_hit_rate"] == 0.35   # 7/20
    assert policy["calibrated_influence"] == 1   # <50 保守
    combos = policy["combos"]
    assert combos["h|p|sqli"]["action"] == "boost"    # 0.7/0.35 = 2.0 >= 1.5
    assert combos["h|p|sqli"]["n"] == 10
    assert combos["h|p|xss"]["action"] == "penalty"   # 0.0 <= 0.5x baseline

    # 策略 JSON 可写读
    out = tmp_path / "bandit_policy.json"
    out.write_text(json.dumps(policy, ensure_ascii=False), encoding="utf-8")
    loaded = json.loads(out.read_text(encoding="utf-8"))
    assert loaded["combos"] == combos
    assert loaded["samples"] == 20


def test_train_empty_returns_empty_policy():
    policy = bandit_train.train([])
    assert policy["samples"] == 0
    assert policy["combos"] == {}


# ---------- c) bandit.py 策略加载 ----------

def _write_policy(tmp_path, combos, calibrated=3):
    p = tmp_path / "bandit_policy.json"
    p.write_text(json.dumps({
        "version": 1,
        "calibrated_influence": calibrated,
        "combos": combos,
    }, ensure_ascii=False), encoding="utf-8")
    return p


def test_from_policy_adjusts_by_action_and_clamps(tmp_path):
    pol = _write_policy(tmp_path, {
        "t|p|sqli": {"n": 10, "hit_rate": 0.9, "action": "boost"},
        "t|p|xss": {"n": 10, "hit_rate": 0.1, "action": "penalty"},
        "t|p|xxe": {"n": 10, "hit_rate": 0.5, "action": "hold"},
    }, calibrated=3)
    b = ContextualBandit.from_policy(str(pol))
    assert b.adjust(5, "t|p|sqli") == 8     # +3
    assert b.adjust(5, "t|p|xss") == 2      # -3
    assert b.adjust(5, "t|p|xxe") == 5      # hold
    assert b.adjust(9, "t|p|sqli") == 10    # clamp 上
    assert b.adjust(1, "t|p|xss") == 1      # clamp 下
    # 全部落在 [1, 10]
    for base in (1, 3, 6, 10):
        assert 1 <= b.adjust(base, "t|p|sqli") <= 10
        assert 1 <= b.adjust(base, "t|p|xss") <= 10


def test_load_policy_returns_true_and_missing_key_falls_back(monkeypatch, tmp_path):
    pol = _write_policy(tmp_path, {
        "t|p|sqli": {"n": 10, "hit_rate": 0.9, "action": "boost"},
    }, calibrated=2)
    b = ContextualBandit()
    assert b.load_policy(str(pol)) is True
    # 命中组合走了策略，不调用 betavariate
    def boom(*a):
        raise AssertionError("策略命中时不应调用 betavariate")
    monkeypatch.setattr(random, "betavariate", boom)
    assert b.adjust(6, "t|p|sqli") == 8
    # 未命中组合回退 Thompson，调用 betavariate
    b.record("t|p|xss", hit=True)
    calls = []
    monkeypatch.setattr(random, "betavariate", lambda a, s: (calls.append(1) or 0.9))
    assert b.adjust(5, "t|p|xss") == 7
    assert calls


def test_no_policy_zero_behavior_regression(monkeypatch):
    """未加载策略：行为与纯 Thompson 完全一致（会调用 betavariate）。"""
    b = ContextualBandit()
    k = bandit_key("t", "p", "sqli")
    b.record(k, hit=True)
    calls = []
    monkeypatch.setattr(random, "betavariate", lambda a, s: (calls.append((a, s)) or 0.9))
    assert b.adjust(5, k) == 7  # (0.9-0.5)*2*2=1.6 -> round 2
    assert calls


def test_load_policy_bad_file_degrades(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("not json{{{", encoding="utf-8")
    b = ContextualBandit()
    assert b.load_policy(str(bad)) is False
    # 仍可正常 Thompson
    b.record("t|p|sqli", hit=True)
    assert 1 <= b.adjust(5, "t|p|sqli") <= 10  # 有样本时 clamp 于 [1,10]