# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP16.1（A 线）RL 决策层：上下文多臂老虎机 单元测试。

覆盖（全部离线，不触网不调 AI）：
- 默认 enabled=False / 无样本 -> adjust 原值返回（零行为回归）；
- key 提取（engine_bundle 首引擎 / 单引擎 / 回退 url / finding 的 parameter 字段）；
- Thompson 采样：monkeypatch betavariate 定型 -> 确定性浮/降权 + clamp；
- SmartTaskQueue 集成：bandit=None 原优先级；注入 bandit 入队时调整；
  complete_task(success=False) 回注 fail 样本（成功不降权，保守策略）；
- 可选 JSONL 反馈飞轮落盘（未来 RL 训练数据）；
- snapshot 诊断形状。
"""
import json
import random

import pytest

from vulnclaw.ai.v100.bandit import (
    ContextualBandit,
    bandit_key,
    key_from_finding,
    key_from_task,
)
from vulnclaw.ai.v100.smart_queue import SmartTaskQueue

_E = "sqli"


def _b(influence: int = 2, feed_dir: str = "", enabled: bool = True) -> ContextualBandit:
    return ContextualBandit(influence=influence, feed_dir=feed_dir, enabled=enabled)


# ---------- 纯 bandit：默认关 / 无样本 ----------

def test_disabled_returns_base_and_noop_record():
    b = _b(enabled=False)
    k = bandit_key("t", "p", _E)
    b.record(k, hit=True)
    assert b.adjust(7, k) == 7
    assert b.has_sample(k) is False


def test_no_sample_returns_base():
    assert _b().adjust(4, bandit_key("t", "p", _E)) == 4


# ---------- key 提取 ----------

def test_key_from_task_bundle_uses_first_engine():
    td = {"type": "engine_bundle", "target": "http://t/x", "param": "id", "engines": ["xss", "sqli"]}
    assert key_from_task(td) == bandit_key("http://t/x", "id", "xss")


def test_key_from_task_single_engine():
    td = {"target": "http://t/x", "param": "id", "engine": "sqli"}
    assert key_from_task(td) == bandit_key("http://t/x", "id", "sqli")


def test_key_from_task_falls_back_url():
    assert key_from_task({"url": "http://t/x?s=1"}) == bandit_key("http://t/x?s=1", "", "")


def test_key_from_finding_uses_parameter_field():
    f = {"url": "http://t/x", "parameter": "s", "engine": "xss"}
    assert key_from_finding(f) == bandit_key("http://t/x", "s", "xss")


# ---------- Thompson 采样（定型） ----------

def test_positive_hits_raise_priority(monkeypatch):
    b = _b(influence=2)
    k = bandit_key("t", "p", _E)
    for _ in range(3):
        b.record(k, hit=True)
    monkeypatch.setattr(random, "betavariate", lambda a, s: 0.9)
    assert b.adjust(6, k) == 8  # (0.9-0.5)*2*2=1.6 -> round 2


def test_fails_lower_priority(monkeypatch):
    b = _b(influence=2)
    k = bandit_key("t", "p", _E)
    for _ in range(5):
        b.record(k, hit=False)
    monkeypatch.setattr(random, "betavariate", lambda a, s: 0.1)
    assert b.adjust(6, k) == 4  # (0.1-0.5)*2*2=-1.6 -> round -2


def test_clamp_upper(monkeypatch):
    b = _b(influence=4)
    k = bandit_key("t", "p", _E)
    b.record(k, hit=True)
    monkeypatch.setattr(random, "betavariate", lambda a, s: 0.95)
    assert b.adjust(9, k) == 10  # clamp 到 10


def test_distinct_keys_keep_separate_stats():
    b = _b()
    b.record(bandit_key("t", "p", "xss"), hit=True)
    b.record(bandit_key("t", "p", "sqli"), hit=False)
    st = b.stats()
    assert st[bandit_key("t", "p", "xss")] == {"hits": 1, "fails": 0}
    assert st[bandit_key("t", "p", "sqli")] == {"hits": 0, "fails": 1}


# ---------- JSONL 反馈飞轮 ----------

def test_feed_dir_writes_jsonl(tmp_path):
    b = _b(feed_dir=str(tmp_path))
    b.record(bandit_key("t", "p", _E), hit=True)
    b.record(bandit_key("t", "p", _E), hit=False)
    lines = (tmp_path / "bandit_feedback.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["key"] == bandit_key("t", "p", _E) and first["hit"] is True


def test_no_feed_dir_does_not_crash():
    b = _b(feed_dir="")
    b.record(bandit_key("t", "p", _E), hit=True)  # 不抛错即可


# ---------- smart_queue 集成 ----------

@pytest.mark.asyncio
async def test_queue_no_bandit_zero_regression():
    q = SmartTaskQueue(max_size=100)
    q1 = await q.add_task({"target": "http://t/a", "param": "id"}, 8)
    await q.add_task({"target": "http://t/b", "param": "q"}, 4)
    tid, _ = await q.get_next_full()
    assert tid == q1  # 高优先级先出，行为原样


@pytest.mark.asyncio
async def test_queue_with_bandit_adjusts_on_add(monkeypatch):
    b = _b(influence=2)
    k = bandit_key("http://t/x", "id", "xss")
    for _ in range(3):
        b.record(k, hit=True)
    monkeypatch.setattr(random, "betavariate", lambda a, s: 0.9)
    q = SmartTaskQueue(max_size=100, bandit=b)
    low_tid = await q.add_task({"target": "http://t/y", "param": "q"}, 7)   # 无样本 key
    high_tid = await q.add_task({"target": "http://t/x", "param": "id", "engines": ["xss"]}, 6)
    tid, _ = await q.get_next_full()
    assert tid == high_tid  # bandit 把 6 -> 8，超越原生 7
    # 再取一个是 low 任务（bandit 无样本不动）
    tid2, _ = await q.get_next_full()
    assert tid2 == low_tid


@pytest.mark.asyncio
async def test_queue_complete_fail_records_fail():
    b = _b()
    q = SmartTaskQueue(max_size=100, bandit=b)
    tid = await q.add_task({"target": "http://t/x", "param": "id", "engine": "sqli"}, 6)
    _key = key_from_task({"target": "http://t/x", "param": "id", "engine": "sqli"})
    await q.get_next_full()
    await q.complete_task(tid, success=False)
    assert b.stats().get(_key, {}).get("fails") == 1


@pytest.mark.asyncio
async def test_queue_complete_success_no_negative():
    """保守策略：成功无产出不降权（避免误伤慢热组合）。"""
    b = _b()
    q = SmartTaskQueue(max_size=100, bandit=b)
    tid = await q.add_task({"target": "http://t/x", "param": "id"}, 6)
    await q.get_next_full()
    await q.complete_task(tid, success=True)
    assert b.stats() == {}


# ---------- 诊断 ----------

def test_snapshot_sorted_by_hits():
    b = _b()
    b.record(bandit_key("t", "a", "xss"), hit=True)
    b.record(bandit_key("t", "b", "sqli"), hit=False)
    b.record(bandit_key("t", "c", "xss"), hit=True)
    b.record(bandit_key("t", "c", "xss"), hit=True)
    snap = b.snapshot()
    assert snap["total_combos"] == 3
    assert snap["top"][0]["key"] == bandit_key("t", "c", "xss")
    assert snap["top"][0]["hit_rate"] == 1.0