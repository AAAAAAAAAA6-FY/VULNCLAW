# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A3 链规划器回归（hermetic：零网络；真跑闸用假 runner + monkeypatch danger_guard）。

锁死的红线：
  * 不可行必须给原因，**绝不硬编造步骤**；
  * 不闭合的链**不准执行**；
  * 真跑需三重闸（闭合 → allow_real → danger_guard），默认走 dry-run。
"""
import pytest

from vulnclaw.ai.v100.planning import (
    Capability,
    build_capabilities,
    chains_to_findings,
    dry_run,
    execute_chain,
    initial_facts_for,
    plan_chains,
    plan_goal,
    produce_index,
    read_capabilities,
    run_chain_planner_line,
    verify_chain,
)


def _ir():
    """观测：/api/role（需 user 角色，写）→ 可把角色提成 admin；/admin 需 admin。"""
    return {
        "target": "http://t", "version": "ir-1",
        "endpoints": [
            {"id": "login", "method": "POST", "path": "/login",
             "params": [{"name": "username", "in": "body"}],
             "auth": {"required": False, "role": None},
             "effects": [], "idempotent": False},
            {"id": "role", "method": "POST", "path": "/api/role",
             "params": [{"name": "role", "in": "body"}],
             "auth": {"required": True, "role": "user"},
             "effects": [{"entity": "user", "op": "write"}], "idempotent": False},
            {"id": "admin", "method": "GET", "path": "/admin", "params": [],
             "auth": {"required": True, "role": "admin"},
             "effects": [], "idempotent": True},
        ],
        "transitions": [
            {"from_state": "anon", "to_state": "user", "via_endpoint": "login",
             "preconditions": ["access:t"], "postconditions": ["role=user"]},
            {"from_state": "user", "to_state": "admin", "via_endpoint": "role",
             "preconditions": ["role=user"], "postconditions": ["role=admin"]},
        ],
        "goals": [{"id": "g_admin", "requires_facts": ["visited:/admin"]}],
    }


def _caps(**kw):
    return build_capabilities(_ir(), kw.pop("findings", None), **kw)


# ============================================================
# capabilities
# ============================================================
def test_build_capabilities_sources_and_determinism():
    caps = _caps(allow_side_effect=True)
    ids = [c.id for c in caps]
    assert ids == sorted(ids)                                  # 确定性排序
    assert "ep:role" in ids and "ep:admin" in ids and "tr:role" in ids
    ep_admin = next(c for c in caps if c.id == "ep:admin")
    assert ep_admin.requires == ("role=admin",) and ep_admin.produces == ("visited:/admin",)
    assert ep_admin.side_effect is False                       # GET
    ep_role = next(c for c in caps if c.id == "ep:role")
    assert ep_role.side_effect is True                         # POST = 写


def test_side_effect_gating_on_build_and_read():
    assert "ep:role" not in [c.id for c in _caps(allow_side_effect=False)]
    assert "ep:role" in [c.id for c in _caps(allow_side_effect=True)]
    caps = _caps(allow_side_effect=True)
    assert "ep:role" not in [c.id for c in read_capabilities(caps)]          # 默认只读
    assert "ep:role" in [c.id for c in read_capabilities(caps, allow_side_effect=True)]


def test_findings_become_capabilities():
    caps = build_capabilities(_ir(), [{"type": "越权访问", "url": "http://t/api/role"}],
                              allow_side_effect=True)
    fc = [c for c in caps if c.kind == "finding"]
    assert fc and "finding:越权访问" in fc[0].produces and "access:t" in fc[0].produces
    assert fc[0].cost == 0.0


def test_produce_index_sorted():
    idx = produce_index(_caps(allow_side_effect=True))
    assert "role=admin" in idx and [c.id for c in idx["role=admin"]] == sorted(
        c.id for c in idx["role=admin"])


# ============================================================
# planner
# ============================================================
def test_plan_feasible_chain_in_execution_order():
    caps = _caps(allow_side_effect=True)
    ch = plan_goal("g_admin", ["visited:/admin"], caps,
                   ["access:t", "role=user"], allow_side_effect=True)
    assert ch.feasible and not ch.blocked_reason
    assert [s.capability_id for s in ch.steps] == ["tr:role", "ep:admin"]
    assert ch.cost == 2.0 and 0 < ch.score <= 1.0
    assert ch.to_dict()["steps"][0]["requires"] == ["role=user"]


def test_plan_infeasible_gives_reason_never_invents_steps():
    caps = _caps(allow_side_effect=True)
    ch = plan_goal("g_root", ["role=root"], caps, ["access:t"], allow_side_effect=True)
    assert ch.feasible is False and ch.steps == []
    assert "role=root" in ch.blocked_reason


def test_plan_goal_without_facts():
    ch = plan_goal("empty", [], _caps(), [])
    assert ch.feasible is False and "未声明任何事实" in ch.blocked_reason


def test_plan_respects_depth_and_side_effect_gate():
    caps = _caps(allow_side_effect=True)
    assert plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                     allow_side_effect=True, max_depth=1).feasible is False
    # 不允许写动作时，tr:role 仍可用（非写），但若唯一通路是 POST 端点则不可行
    only_ep = [c for c in caps if c.kind == "ir_endpoint"]
    assert plan_goal("g", ["visited:/admin"], only_ep, ["access:t", "role=user"],
                     allow_side_effect=False).feasible is False


def test_plan_is_deterministic_and_cycle_safe():
    caps = _caps(allow_side_effect=True)
    first = plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                      allow_side_effect=True).to_dict()
    for _ in range(3):
        assert plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                         allow_side_effect=True).to_dict() == first
    # 互相前置的环：必须终止并判不可行（不硬编造、不死循环）
    cyc = [Capability(id="a", requires=("x",), produces=("y",)),
           Capability(id="b", requires=("y",), produces=("x",))]
    ch = plan_goal("cyc", ["x"], cyc, [], allow_side_effect=True)
    assert ch.feasible is False and ch.steps == []


def test_plan_chains_sorts_feasible_first_and_dedupes():
    caps = _caps(allow_side_effect=True)
    chains = plan_chains(ir=_ir(), capabilities=caps,
                         initial_facts=["access:t", "role=user"],
                         allow_side_effect=True,
                         goals=[("g_admin", ("visited:/admin",)), ("g_root", ("role=root",))])
    assert chains and chains[0].feasible and chains[0].goal == "g_admin"
    assert any(not c.feasible for c in chains)


# ============================================================
# verifier
# ============================================================
def test_verify_chain_closure_and_violations():
    caps = _caps(allow_side_effect=True)
    ch = plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                   allow_side_effect=True)
    ok = verify_chain(ch, caps, ["access:t", "role=user"])
    assert ok["ok"] and not ok["violations"] and len(ok["trace"]) == 2
    bad = verify_chain(ch, caps, ["access:t"])                 # 缺 role=user
    assert bad["ok"] is False
    assert bad["violations"][0]["missing"] == ["role=user"]
    assert bad["missing_goal"] == ["visited:/admin"]


def test_dry_run_never_executes():
    caps = _caps(allow_side_effect=True)
    ch = plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                   allow_side_effect=True)
    r = dry_run(ch, caps, ["access:t", "role=user"])
    assert r["dry_run"] is True and r["ok"] is True


@pytest.mark.asyncio
async def test_execute_chain_three_gates(monkeypatch):
    caps = _caps(allow_side_effect=True)
    ch = plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                   allow_side_effect=True)
    init = ["access:t", "role=user"]

    # 闸1：链不闭合 → 不执行
    r0 = await execute_chain(ch, runner=lambda s: "ok", initial_facts=["access:t"], allow_real=True)
    assert r0["executed"] is False and "未闭合" in r0["reason"]

    # 闸2：默认 dry-run（未开 allow_real）
    r1 = await execute_chain(ch, runner=lambda s: "ok", initial_facts=init)
    assert r1["executed"] is False and "dry-run" in r1["reason"]

    # 闸2'：开了 allow_real 但没给 runner
    r2 = await execute_chain(ch, initial_facts=init, allow_real=True)
    assert r2["executed"] is False and "runner" in r2["reason"]

    # 闸3：danger_guard 拒绝（默认 deny）
    monkeypatch.setattr("vulnclaw.core.danger_guard.guard.require_approval",
                        lambda op, detail="": False)
    r3 = await execute_chain(ch, runner=lambda s: "ok", initial_facts=init, allow_real=True)
    assert r3["executed"] is False and "danger_guard" in r3["reason"]

    # 三闸全过（模拟放行）→ 真跑；支持 async runner
    monkeypatch.setattr("vulnclaw.core.danger_guard.guard.require_approval",
                        lambda op, detail="": True)

    async def _runner(step):
        return f"ran:{step.capability_id}"

    r4 = await execute_chain(ch, runner=_runner, initial_facts=init, allow_real=True)
    assert r4["executed"] is True
    assert [x["result"] for x in r4["results"]] == ["ran:tr:role", "ran:ep:admin"]


@pytest.mark.asyncio
async def test_execute_chain_aborts_on_step_error(monkeypatch):
    caps = _caps(allow_side_effect=True)
    ch = plan_goal("g", ["visited:/admin"], caps, ["access:t", "role=user"],
                   allow_side_effect=True)
    monkeypatch.setattr("vulnclaw.core.danger_guard.guard.require_approval",
                        lambda op, detail="": True)

    def _boom(step):
        raise RuntimeError("step failed")

    r = await execute_chain(ch, runner=_boom, initial_facts=["access:t", "role=user"],
                            allow_real=True)
    assert r["executed"] is False and "执行中途失败" in r["reason"]


# ============================================================
# line（产线）
# ============================================================
class _Stub:
    def __init__(self, brief):
        self.target = "http://t"
        self.session = None
        self._recon_brief = brief
        self.findings = []
        self.added = []

    def _add_finding(self, f):
        self.added.append(f)


@pytest.mark.asyncio
async def test_line_default_not_reported(monkeypatch):
    monkeypatch.setattr("vulnclaw.ai.v100.planning.line._flag",
                        lambda name, default: default)          # 全部默认（auto=False）
    stub = _Stub({**_ir(), "target": "http://t"})
    stub._recon_brief = {"target": "http://t", "business_ir": _ir()}
    made = await run_chain_planner_line(stub)
    assert made == 0 and stub.added == []                       # 只记日志，不入报告


@pytest.mark.asyncio
async def test_line_auto_report_and_fail_closed(monkeypatch):
    def _flag(name, default):
        if name == "chain_planner_auto_report":
            return True
        if name in ("chain_planner_allow_side_effect",):
            return True
        return default

    monkeypatch.setattr("vulnclaw.ai.v100.planning.line._flag", _flag)
    stub = _Stub(None)
    stub._recon_brief = {"target": "http://t", "business_ir": _ir()}
    stub.findings = [{"type": "信息泄露", "url": "http://t/api/role"}]
    made = await run_chain_planner_line(stub)
    assert made == 1 and len(stub.added) == 1
    assert stub.added[0]["source"] == "chain_planner"
    assert stub.added[0]["needs_verification"] is True
    # 畸形/空输入一律 fail-closed
    assert await run_chain_planner_line(_Stub(None)) == 0
    assert await run_chain_planner_line(_Stub({"business_ir": {}})) == 0
    assert initial_facts_for("http://t/x") == ["access:t"]
    assert initial_facts_for("") == []
    assert chains_to_findings([], target="http://t") == []
    # 不可行链不得变成 finding
    bad = plan_goal("g", ["role=root"], _caps(allow_side_effect=True), [])
    assert chains_to_findings([bad]) == []
