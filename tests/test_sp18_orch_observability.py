# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)

"""SP18 编排可观测性测试。

覆盖三个协调阶段（chain_router / react_deep_dive / agent_coordinator）：
- a) 执行后 phase_timings 写入对应键且值 >= 0；配置关闭时"不写 0 假值"。
- b) orchestration_ledger() 返回 dict 且含三个阶段名（起止/耗时/决策计数）。
- c) run() 的 report dict 写入新键 "orchestration"（只增不改既有键）。

零外网依赖：全部用 object.__new__ 轻量实例 + monkeypatch，不启动真实扫描。
"""
import inspect

import pytest

import vulnclaw.ai.v100.orchestrator as v100
from vulnclaw.ai.v100.orchestrator import V100Orchestrator


def _bare_orchestrator():
    """绕过重量级 __init__（引擎/记忆/检查点），构造轻量实例直测协调记账。"""
    return object.__new__(V100Orchestrator)


async def _noop():
    return None


def _patch_coord_settings(monkeypatch, chain=True, react=True, coord=True):
    """settings 为模块级单例（vulnclaw.core.settings），monkeypatch 其字段即可。"""
    monkeypatch.setattr(v100.settings, "enable_chain_router", chain)
    monkeypatch.setattr(v100.settings, "enable_react_dive", react)
    monkeypatch.setattr(v100.settings, "agent_coordinator_enabled", coord)


# ---------------------------------------------------------------------------
# a) 协调阶段执行后 phase_timings 写入对应键
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_a_coord_stages_write_phase_timings(monkeypatch):
    _patch_coord_settings(monkeypatch)

    inst = _bare_orchestrator()
    inst._phase_timings = {}
    inst._orchestration_stages = {}

    for name in ("chain_router", "react_deep_dive", "agent_coordinator"):
        await inst._record_coord_timing(name, True, _noop())
        assert name in inst._phase_timings, name
        assert name in inst._orchestration_stages, name
        assert inst._phase_timings[name] >= 0, name


@pytest.mark.asyncio
async def test_a_disabled_stage_skips_fake_zero(monkeypatch):
    """配置关闭的协调阶段不写入 phase_timings（避免 0 假值误导归因）。"""
    _patch_coord_settings(monkeypatch, chain=True, react=False, coord=True)

    inst = _bare_orchestrator()
    inst._phase_timings = {}
    inst._orchestration_stages = {}

    await inst._record_coord_timing("react_deep_dive", True, _noop())
    await inst._record_coord_timing("chain_router", True, _noop())

    assert "react_deep_dive" not in inst._phase_timings  # 关闭 -> 不写假数据
    assert "chain_router" in inst._phase_timings          # 启用 -> 正常写


# ---------------------------------------------------------------------------
# b) orchestration_ledger() 决策账本
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_b_ledger_contains_all_coord_stages(monkeypatch):
    _patch_coord_settings(monkeypatch)

    inst = _bare_orchestrator()
    inst._phase_timings = {}
    inst._orchestration_stages = {}
    inst._coord_dispatch_count = 3
    inst.findings = [
        {"source": "chain_router"},
        {"source": "chain_router"},
        {"source": "react_agent"},
        {"source": "scan"},
    ]

    for name in ("chain_router", "react_deep_dive", "agent_coordinator"):
        await inst._record_coord_timing(name, True, _noop())

    ledger = inst.orchestration_ledger()
    assert isinstance(ledger, dict)
    for name in ("chain_router", "react_deep_dive", "agent_coordinator"):
        assert name in ledger, name
        entry = ledger[name]
        assert "start" in entry and "end" in entry and "elapsed" in entry
        assert entry["elapsed"] >= 0

    assert ledger["chain_router"]["chain_routes"] == 2
    assert ledger["react_deep_dive"]["dive_count"] == 1
    assert ledger["agent_coordinator"]["agents_dispatched"] == 3


def test_b_ledger_tolerates_missing_state():
    """未启用任何协调阶段时 ledger 返回空 dict（不崩）。"""
    inst = _bare_orchestrator()  # 无 _orchestration_stages / _phase_timings 等
    ledger = inst.orchestration_ledger()
    assert ledger == {}


# ---------------------------------------------------------------------------
# c) run() 的 report dict 写入 "orchestration" 键（只增不改既有键）
# ---------------------------------------------------------------------------
def test_c_run_writes_orchestration_key():
    run_src = inspect.getsource(V100Orchestrator.run)
    assert 'report["orchestration"] = self.orchestration_ledger()' in run_src
    # 既有 behaviour 不被破坏：phase_timeouts 写仍在
    assert 'report["phase_timeouts"]' in run_src
