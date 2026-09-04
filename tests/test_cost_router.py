# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A4.4: 任务分层成本路由 单元测试。

覆盖：粗筛标记明显误报 / 解析失败放行 / 调用异常中断；
      VerifyBudgetGate 预算门 consume/allow 语义；usage_site 标签传递。
"""
import pytest

from vulnclaw.ai.cost_router import PRESCREEN_SITE, VerifyBudgetGate, pre_screen_candidates


class _FakeOrch:
    """最小 orchestrator 替身：只实现 _ask_ai（记录 task_type/usage_site）。"""

    def __init__(self, raw=None, exc=None):
        self.raw = raw
        self.exc = exc
        self.calls = 0
        self.kwargs = None

    async def _ask_ai(self, prompt, system="", temperature=0.1, max_tokens=2048,
                      compress=False, use_cache=False, task_type="default",
                      usage_site=""):
        self.calls += 1
        self.kwargs = {"task_type": task_type, "usage_site": usage_site}
        if self.exc:
            raise self.exc
        return self.raw


def _candidates(n=4):
    return [
        {"type": "sqli", "url": "http://t/p", "parameter": "q", "evidence": f"err {i}"}
        for i in range(n)
    ]


@pytest.mark.asyncio
async def test_prescreen_marks_false_positives():
    orch = _FakeOrch(raw='{"false_positives": [0, 2]}')
    cands = _candidates(4)
    fp_ids, calls = await pre_screen_candidates(orch, cands, batch_size=10)
    assert calls == 1
    assert fp_ids == {id(cands[0]), id(cands[2])}
    # 粗筛必须走 filter 档 + 台账标签（A4.4 成本量化依据）
    assert orch.kwargs["task_type"] == "filter"
    assert orch.kwargs["usage_site"] == PRESCREEN_SITE


@pytest.mark.asyncio
async def test_prescreen_parse_fail_releases_all():
    orch = _FakeOrch(raw="不是 JSON 的垃圾输出")
    cands = _candidates(3)
    fp_ids, calls = await pre_screen_candidates(orch, cands)
    assert calls == 1
    assert fp_ids == set()  # 解析失败 → 全量放行进 verify（宁漏筛勿误杀）


@pytest.mark.asyncio
async def test_prescreen_exception_stops():
    orch = _FakeOrch(exc=RuntimeError("model down"))
    cands = _candidates(5)
    fp_ids, calls = await pre_screen_candidates(orch, cands, batch_size=2)
    assert calls == 1  # 第一批失败即中断
    assert fp_ids == set()


@pytest.mark.asyncio
async def test_prescreen_batching():
    orch = _FakeOrch(raw='{"false_positives": []}')
    cands = _candidates(5)
    _, calls = await pre_screen_candidates(orch, cands, batch_size=2)
    assert calls == 3  # ceil(5/2)


@pytest.mark.asyncio
async def test_prescreen_empty():
    fp_ids, calls = await pre_screen_candidates(_FakeOrch(), [])
    assert fp_ids == set() and calls == 0


def test_budget_gate_semantics():
    gate = VerifyBudgetGate(2)
    assert gate.allow()
    assert gate.consume()  # 第 1 次调用被允许
    assert gate.allow()
    assert gate.consume()  # 第 2 次（最后一次预算内）调用仍被允许
    assert not gate.allow()  # 第 3 次起一律拒绝
    assert not gate.consume()  # used=3 → 超预算
    assert gate.stats() == {"used": 3, "max": 2}
