# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# tests/test_phase_timeboxed.py
"""
SH17.1 阶段预算（per-phase wall-clock 超时）单元测试。

覆盖：默认配置存在 / 预算内正常执行 / 超时只中断本阶段（跳过继续）/
未配置预算直接透传 / settings 默认值与覆盖。
零外网依赖：全部用本地协程 + monkeypatch，不启动扫描。
"""
import asyncio
import inspect
import types

import pytest

from vulnclaw.ai.v100.orchestrator import V100Orchestrator
from vulnclaw.config.settings import settings


# --------------------------------------------------------------------------- 
# 1) 默认配置
# --------------------------------------------------------------------------- 
def test_phase_timeout_defaults_present():
    for name in V100Orchestrator._STAGES:
        assert getattr(settings, "phase_timeout_%s_s" % name, 0) > 0, name
    assert settings.phase_timeout_fallback_s > 0


def test_phase_timeout_env_override(monkeypatch):
    monkeypatch.setattr(settings, "phase_timeout_scan_s", 0)
    assert settings.phase_timeout_scan_s == 0


# --------------------------------------------------------------------------- 
# 2) timeboxed 行为（轻量对象绑定方法，避免实例化重型 orchestrator）
# --------------------------------------------------------------------------- 
def _fake_orch(budgets):
    f = types.SimpleNamespace()
    f._phase_budgets = dict(budgets)
    f._phase_timeouts_hit = []
    return f


def test_timebox_within_budget_returns_result():
    orch = _fake_orch({"recon": 10})

    async def _work():
        await asyncio.sleep(0.02)
        return "ok"

    async def _main():
        return await V100Orchestrator._run_phase_timeboxed(orch, "recon", _work())

    assert asyncio.run(_main()) == "ok"
    assert orch._phase_timeouts_hit == []


def test_timebox_exceeded_returns_none_and_records():
    orch = _fake_orch({"recon": 1})

    async def _slow():
        await asyncio.sleep(60)  # 远超预算，被 wait_for 取消
        return "late"

    async def _main():
        return await V100Orchestrator._run_phase_timeboxed(orch, "recon", _slow())

    out = asyncio.run(_main())
    assert out is None
    assert orch._phase_timeouts_hit == ["recon"]


def test_timebox_no_budget_passthrough():
    orch = _fake_orch({})  # 未配置任何预算（如全部显式置 0）

    async def _work():
        return 42

    async def _main():
        return await V100Orchestrator._run_phase_timeboxed(orch, "unknown_stage", _work())

    assert asyncio.run(_main()) == 42
    assert orch._phase_timeouts_hit == []


def test_timebox_does_not_leak_to_next_phase():
    """单阶段超时不污染后续阶段：后续 phase 仍被各自预算监管。"""
    orch = _fake_orch({"scan": 1, "verify": 10})

    async def _slow():
        await asyncio.sleep(60)

    async def _fast():
        await asyncio.sleep(0.01)
        return "verify-ok"

    async def _main():
        a = await V100Orchestrator._run_phase_timeboxed(orch, "scan", _slow())
        b = await V100Orchestrator._run_phase_timeboxed(orch, "verify", _fast())
        return a, b

    a, b = asyncio.run(_main())
    assert a is None
    assert b == "verify-ok"
    assert orch._phase_timeouts_hit == ["scan"]


# --------------------------------------------------------------------------- 
# 3) 阶段清单与 run() 包装完整性（防止新增阶段漏包装）
# --------------------------------------------------------------------------- 
def test_run_uses_timeboxed_for_all_stages():
    import vulnclaw.ai.v100.orchestrator as _mod

    run_src = inspect.getsource(_mod.V100Orchestrator.run)
    for name in V100Orchestrator._STAGES:
        assert ("_run_phase_timeboxed(%r," % name) in run_src or (
            f"_run_phase_timeboxed(\"{name}\"" in run_src), name


if __name__ == "__main__":
    pytest.main([__file__, "-q", "--no-header"])