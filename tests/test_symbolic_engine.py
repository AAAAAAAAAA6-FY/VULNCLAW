# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A1 引擎层入口 + 探测器回归（hermetic：零网络、零 LLM）。"""
import pytest

from vulnclaw.engines.symbolic.detectors import (
    differential_verdict,
    findings_from_results,
    invariant_holds,
    objective_to_finding,
    witness_to_payload,
)
from vulnclaw.engines.symbolic.objectives import (
    ObjectiveResult,
    admin_values_for,
    authz_objective,
    evaluate,
    objectives_for,
)
from vulnclaw.engines.symbolic.values import EnumDomain, IntInterval, LinExpr, SetIn, Sym
from vulnclaw.engines.symbolic_engine import SymbolicLogicEngine


# ============================================================
# 高权限值按域自适应（否则 SetIn 与域不相交 → 白丢检出）
# ============================================================
def test_admin_values_for_int_enum_and_interval():
    assert admin_values_for(EnumDomain((0, 1))) == (1,)
    assert admin_values_for(EnumDomain(("user", "admin"))) == ("admin",)
    assert admin_values_for(IntInterval(0, 100)) == (100,)
    # 域内**没有**高权限值时必须返回空：早期实现退回"取最大值"，会让 role∈{0} 的
    # 提权目标变成 role=0（平凡可满足）→ 直接制造误报。
    assert admin_values_for(EnumDomain((0,))) == ()
    assert admin_values_for(IntInterval(0, 0)) == ()
    assert admin_values_for(IntInterval(-5, -1)) == ()
    assert admin_values_for(None) == ("admin", "administrator", "1", True)


def test_objectives_for_uses_domain_aware_admin_values():
    objs = objectives_for(["role"], domains={"role": EnumDomain((0, 1))})
    assert len(objs) == 1
    syms = [Sym("role", EnumDomain((0, 1)))]
    r = evaluate(objs[0], syms)
    assert r.feasible and r.witness == {"role": 1}


# ============================================================
# 探测器（产物化）
# ============================================================
def test_witness_to_payload():
    assert witness_to_payload({"qty": -1, "total": -100}) == "qty=-1&total=-100"
    assert witness_to_payload({"flag": True, "note": None}) == "flag=true&note="
    assert witness_to_payload({}) == ""
    assert witness_to_payload(None) == ""


def test_objective_to_finding_gates():
    syms = [Sym("role", EnumDomain((0, 1)))]
    ok = evaluate(authz_objective("role", (1,)), syms)
    f = objective_to_finding(ok, url="http://t/user/role", method="post")
    assert f["engine"] == "symbolic_logic"
    assert f["method"] == "POST"
    assert f["payload"] == "role=1"
    assert f["deterministic"] is True and f["needs_verification"] is True
    assert f["cwe"] == "CWE-639" and f["confidence"] == "中"

    # 不可行 / 不可判 → 不产出
    blocked = evaluate(authz_objective("role", (1,)), syms, [("inv_role", SetIn("role", (0,)))])
    assert objective_to_finding(blocked, url="http://t") is None
    assert objective_to_finding(evaluate(authz_objective("role", (1,)), []), url="http://t") is None
    assert objective_to_finding(None, url="http://t") is None


def test_findings_from_results_filters_and_orders():
    syms = [Sym("role", EnumDomain((0, 1)))]
    res = [evaluate(authz_objective("role", (1,)), syms),
           ObjectiveResult(authz_objective("role", (1,)), False, None, (), True, "缺值域")]
    assert len(findings_from_results(res, url="http://t")) == 1


def test_invariant_holds_and_differential_verdict():
    inv = LinExpr.var("total") - LinExpr.var("qty") * 100
    assert invariant_holds({"total": 200, "qty": 2}, inv) is True
    assert invariant_holds({"total": 150, "qty": 2}, inv) is False
    assert invariant_holds({"qty": "abc"}, inv) is True          # 非数值 → 视为成立（fail-closed）
    assert invariant_holds({}, object()) is True

    v = differential_verdict({"total": 200, "qty": 2}, {"total": 1, "qty": 2}, [inv])
    assert v["violated"] is True and v["broken_invariants"] == [0]
    ok = differential_verdict({"total": 200, "qty": 2}, {"total": 200, "qty": 2}, [inv])
    assert ok["violated"] is False and ok["considered"] == 1
    none = differential_verdict({}, {}, [])
    assert none["violated"] is False and "无可判定不变量" in none["reason"]


# ============================================================
# 引擎
# ============================================================
def _ir(invariants=None):
    return {
        "target": "http://t", "version": "ir-1",
        "endpoints": [{
            "id": "e1", "method": "POST", "path": "/user/role",
            "params": [{"name": "role", "in": "body", "type": "int",
                        "domain": {"kind": "enum", "values": [0, 1]}}],
            "auth": {"required": True, "role": "user"},
        }],
        "invariants": invariants or [],
        "goals": [],
    }


@pytest.mark.asyncio
async def test_engine_name_and_check_is_none():
    eng = SymbolicLogicEngine()
    assert eng.name == "symbolic_logic"
    assert await eng.check("http://t", "role", (200, "", {}), "role=1", None) is None


@pytest.mark.asyncio
async def test_engine_scan_finds_authz_candidate():
    eng = SymbolicLogicEngine()
    out = await eng.scan("http://t", None, ir=_ir())
    assert len(out) == 1
    f = out[0]
    assert f["engine"] == "symbolic_logic" and f["url"] == "http://t/user/role"
    assert f["parameter"] == "role" and f["payload"] == "role=1"
    assert f["needs_verification"] is True


@pytest.mark.asyncio
async def test_engine_scan_blocked_by_invariant():
    """IR 声明 role==0（服务端锁死）→ 提权目标不可满足 → 不产出（不误报）。"""
    eng = SymbolicLogicEngine()
    ir = _ir([{"id": "inv_role_locked", "expr": {"coeffs": {"role": 1}, "const": 0}}])
    assert await eng.scan("http://t", None, ir=ir) == []


@pytest.mark.asyncio
async def test_engine_scan_fail_closed_without_ir():
    eng = SymbolicLogicEngine()
    assert await eng.scan("http://t", None) == []
    assert await eng.scan("http://t", None, ir={}) == []
    # 参数没有值域 → 不建模 → 不产出
    bare = {"endpoints": [{"id": "e", "params": [{"name": "role"}]}]}
    assert await eng.scan("http://t", None, ir=bare) == []
    # IR 畸形 → 不抛异常
    assert await eng.scan("http://t", None, ir={"endpoints": [None, 1, "x"]}) == []


@pytest.mark.asyncio
async def test_engine_scan_reads_brief_and_is_deterministic():
    eng = SymbolicLogicEngine()
    a = await eng.scan("http://t", None, recon_brief={"business_ir": _ir()})
    b = await eng.scan("http://t", None, recon_brief={"business_ir": _ir()})
    assert a == b and len(a) == 1


@pytest.mark.asyncio
async def test_engine_scan_amount_objective_with_unit_price():
    ir = {
        "target": "http://t", "unit_price": 100,
        "endpoints": [{
            "id": "e2", "method": "POST", "path": "/order",
            "params": [
                {"name": "qty", "domain": {"kind": "int", "lo": -100, "hi": 100}},
                {"name": "total", "domain": {"kind": "int", "lo": -100000, "hi": 100000}},
            ],
        }],
    }
    out = await SymbolicLogicEngine().scan("http://t", None, ir=ir)
    kinds = {f["ir_ref"]["kind"] for f in out}
    assert "amount" in kinds and "quantity" in kinds
    assert all(f["url"] == "http://t/order" for f in out)
