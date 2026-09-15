# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A1 目标谓词库回归 —— 重点是"不变量守门 → 不产出"（FP 控制）与 fail-closed。"""
import pytest

from vulnclaw.engines.symbolic import EnumDomain, IntInterval, LinCmp, LinExpr, SetIn, Sym
from vulnclaw.engines.symbolic.objectives import (
    amount_objective,
    authz_objective,
    classify_param,
    evaluate,
    flow_objective,
    idempotency_objective,
    objectives_for,
    overflow_objective,
    quantity_objective,
)


# ============================================================
# 参数归类
# ============================================================
@pytest.mark.parametrize("name,kind", [
    ("total", "amount"), ("price", "amount"), ("subtotal", "amount"),
    ("qty", "quantity"), ("quantity", "quantity"),
    ("role", "role"), ("is_admin", "role"), ("user_type", "role"),
    ("user_id", "identity"), ("order_id", "identity"),
    ("step", "step"), ("status", "step"),
    ("is_paid", "flag"),
])
def test_classify_param_hits(name, kind):
    assert classify_param(name) == kind


@pytest.mark.parametrize("name", ["foo", "valid", "", None, "xyz"])
def test_classify_param_conservative(name):
    """不认识的参数一律 None（宁缺毋滥）；"valid" 不得被 "id" 误吞。"""
    assert classify_param(name) is None


# ============================================================
# 各目标的判定
# ============================================================
def test_authz_feasible_without_invariant():
    syms = [Sym("role", IntInterval(0, 1))]
    r = evaluate(authz_objective("role", admin_values=(1,), base_values=(0,)), syms)
    assert r.feasible and not r.undecidable
    assert r.witness == {"role": 1}


def test_authz_blocked_by_role_invariant():
    """服务端对角色做硬校验（不变量守门）→ 越权目标判死，不产出。"""
    syms = [Sym("role", IntInterval(0, 1))]
    inv = [("inv_role_fixed", SetIn("role", (0,)))]
    r = evaluate(authz_objective("role", admin_values=(1,), base_values=(0,)), syms, inv)
    assert not r.feasible
    assert r.blocked_by == ("inv_role_fixed",)


def _amount_system():
    syms = [Sym("qty", IntInterval(-100, 100)),
            Sym("total", IntInterval(-10 ** 6, 10 ** 6))]
    inv = [("inv_total_eq_line",
            LinCmp.eq(LinExpr.var("total") - LinExpr.var("qty") * 100))]
    return syms, inv


def test_amount_total_blocked_by_invariant():
    """total == 单价×数量 成立时，"总价低于应收"不可满足 → 不误报。"""
    syms, inv = _amount_system()
    obj = amount_objective(100, qty_name="qty", total_name="total", mode="total")
    r = evaluate(obj, syms, inv)
    assert not r.feasible and not r.undecidable
    assert "inv_total_eq_line" in r.blocked_by


def test_amount_total_feasible_without_invariant():
    """不变量缺失（服务端真没校验）→ 可满足，给出可利用载荷。"""
    syms, _ = _amount_system()
    obj = amount_objective(100, qty_name="qty", total_name="total", mode="total")
    r = evaluate(obj, syms)
    assert r.feasible
    assert r.witness["qty"] > 0
    assert r.witness["total"] < r.witness["qty"] * 100


def test_amount_price_mode():
    syms = [Sym("price", IntInterval(1, 10000))]
    inv = [("inv_price_floor", LinCmp.ge(LinExpr.var("price") - 100))]
    obj = amount_objective(100, price_name="price", mode="price")
    assert not evaluate(obj, syms, inv).feasible
    assert evaluate(obj, syms).feasible


def test_quantity_objective():
    syms = [Sym("qty", IntInterval(-50, 50))]
    obj = quantity_objective("qty", min_allowed=1)
    assert evaluate(obj, syms).feasible
    inv = [("inv_qty_min", LinCmp.ge(LinExpr.var("qty") - 1))]
    r = evaluate(obj, syms, inv)
    assert not r.feasible and r.blocked_by == ("inv_qty_min",)


def test_flow_objective():
    syms = [Sym("step", EnumDomain(("cart", "confirm", "pay")))]
    obj = flow_objective("step", terminal_values=("confirm",))
    assert evaluate(obj, syms).feasible
    inv = [("inv_step_cart", SetIn("step", ("cart",)))]
    r = evaluate(obj, syms, inv)
    assert not r.feasible and r.blocked_by == ("inv_step_cart",)


def test_idempotency_objective():
    syms = [Sym("submit_count", IntInterval(0, 5))]
    obj = idempotency_objective("submit_count", limit=1)
    assert evaluate(obj, syms).feasible
    inv = [("inv_once", LinCmp.le(LinExpr.var("submit_count") - 1))]
    assert not evaluate(obj, syms, inv).feasible


def test_overflow_objective_bounded_vs_wide():
    bounded = [Sym("qty", IntInterval(1, 10))]
    assert not evaluate(overflow_objective("qty", 100), bounded).feasible
    wide = [Sym("qty", IntInterval(-10 ** 9, 10 ** 9))]
    r = evaluate(overflow_objective("qty", 100), wide)
    assert r.feasible and r.witness["qty"] * 100 > 2 ** 31 - 1


# ============================================================
# 推导与纪律
# ============================================================
def test_objectives_for_derives_kinds():
    objs = objectives_for(["role", "qty", "total"], unit_price=100)
    kinds = {o.kind for o in objs}
    assert {"authz", "quantity", "overflow", "amount"} <= kinds
    assert all(o.cwe and o.severity for o in objs)


def test_objectives_for_empty_params():
    assert objectives_for([]) == []
    assert objectives_for(None) == []       # type: ignore[arg-type]


def test_evaluate_undecidable_when_domain_missing():
    """变量没有值域定义 → undecidable（fail-closed），绝不默认无界可满足。"""
    r = evaluate(authz_objective("role", admin_values=(1,)), syms=[])
    assert r.undecidable is True and r.feasible is False
    assert "role" in r.reason


def test_evaluate_is_deterministic():
    syms, _ = _amount_system()
    obj = amount_objective(100, qty_name="qty", total_name="total", mode="total")
    first = evaluate(obj, syms)
    for _ in range(3):
        assert evaluate(obj, syms).witness == first.witness


def test_evaluate_fail_closed_on_garbage():
    assert evaluate(None, [], []).undecidable is True       # type: ignore[arg-type]
    r = evaluate(authz_objective("role", admin_values=(1,)), [Sym("role", IntInterval(0, 1))],
                 [("bad", object())])                        # type: ignore[list-item]
    assert r.feasible is True                                # 非法不变量被忽略，不影响主判定


def test_objective_to_dict_roundtrip_fields():
    obj = quantity_objective("qty")
    d = obj.to_dict()
    assert d["kind"] == "quantity" and d["cwe"] == "CWE-1284"
    assert isinstance(d["goal"], list) and d["goal"][0]["op"] == "lin"
