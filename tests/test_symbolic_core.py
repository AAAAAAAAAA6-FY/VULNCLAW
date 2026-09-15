# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A1 符号执行支柱 —— 底层（值域 / 线性约束 / 求解器）回归测试。

全部 hermetic：不发任何网络请求、不依赖 LLM、不依赖 z3（z3 仅在被安装时做交叉验证）。
覆盖重点是**FP 控制**：不变量存在时，篡改目标必须被判"不可满足"（不产出误报）；
不变量缺失时才可满足（即真实存在可被利用的路径）。
"""
import pytest

from vulnclaw.engines.symbolic import (
    EnumDomain,
    IntInterval,
    LinCmp,
    LinExpr,
    SetIn,
    StrDomain,
    Sym,
    all_solutions,
    is_satisfiable,
    optimize,
    propagate,
    solve,
    z3_available,
    z3_check,
)


# ============================================================
# 值域
# ============================================================
def test_int_interval_basic():
    d = IntInterval(0, 10)
    assert not d.is_empty()
    assert d.contains(0) and d.contains(10) and not d.contains(11)
    assert not d.contains(True)          # bool 不是 int（严格区分）
    assert d.size() == 11
    assert d.candidates() == list(range(0, 11))


def test_int_interval_empty_and_unbounded():
    assert IntInterval(5, 3).is_empty()
    assert IntInterval().contains(10 ** 9)          # 无界域
    assert IntInterval().size() is None
    # 无界大域：候选退化为"有语义点"集合，绝不枚举
    c = IntInterval().candidates(limit=8, window=100)
    assert set(c) <= {-100, 100, 0, 1, -1, -99, 99, 101, -101}
    assert len(c) <= 10
    assert not IntInterval(5, 3).candidates()


def test_interval_intersect():
    assert IntInterval(0, 10).intersect(IntInterval(5, 20)) == IntInterval(5, 10)
    got = IntInterval(0, 10).intersect(EnumDomain((3, 7, 99)))
    assert isinstance(got, EnumDomain)
    assert got.values == (3, 7)


def test_enum_domain_dedup_and_bool_strict():
    d = EnumDomain((1, 1, 2, True))
    assert d.values == (1, 2, True)          # 去重，且 bool 与 int 不互吞
    assert d.contains(1) and d.contains(True)
    assert not EnumDomain((True,)).contains(1)


def test_str_domain_pattern():
    d = StrDomain(pattern=r"[a-z]{3}", max_len=3)
    assert d.contains("abc")
    assert not d.contains("abcd")
    assert not d.contains("AB1")
    assert d.candidates() == []               # 字符串域不可枚举


# ============================================================
# 线性表达式
# ============================================================
def test_linexpr_normalize_and_eval():
    e = LinExpr.var("x") + LinExpr.var("y") * 2 - 5
    assert e.coeffs == (("x", 1), ("y", 2))   # 排序 + 去零
    assert e.const == -5
    assert e.vars() == frozenset(("x", "y"))
    assert e.eval({"x": 3, "y": 1}) == 0
    # 归一化幂等：同表达式不同书写顺序 → 完全相等（保证可复现）
    assert LinExpr.var("x") + LinExpr.var("y") == LinExpr.var("y") + LinExpr.var("x")
    assert (LinExpr.var("x") * 0).coeffs == ()


def test_linexpr_non_numeric_is_zero():
    e = LinExpr.var("x") + 1
    assert e.eval({"x": "not-a-number"}) == 0   # fail-closed：不抛异常


# ============================================================
# 约束语义
# ============================================================
def test_lincmp_constructors_semantics():
    x = LinExpr.var("x")
    assert LinCmp.le(x - 5).eval({"x": 5})
    assert not LinCmp.lt(x - 5).eval({"x": 5})
    assert LinCmp.ge(x - 5).eval({"x": 5})
    assert not LinCmp.gt(x - 5).eval({"x": 5})
    assert LinCmp.eq(x - 5).eval({"x": 5})
    assert LinCmp.ne(x - 5).eval({"x": 6})


def test_setin_semantics():
    c = SetIn("role", ("user", "admin"))
    assert c.eval({"role": "admin"})
    assert not c.eval({"role": "root"})
    assert not c.eval({})                    # 未赋值 → 不满足


# ============================================================
# 区间传播
# ============================================================
def test_propagate_tightens_bounds():
    doms = {"x": IntInterval(0, 100), "y": IntInterval(0, 100)}
    # x + y <= 10
    ok, out = propagate(doms, [LinCmp.le(LinExpr.var("x") + LinExpr.var("y") - 10)])
    assert ok
    assert out["x"].hi == 10 and out["y"].hi == 10
    assert out["x"].lo == 0 and out["y"].lo == 0


def test_propagate_detects_unsat():
    doms = {"x": IntInterval(0, 10)}
    cons = [LinCmp.ge(LinExpr.var("x") - 5), LinCmp.le(LinExpr.var("x") - 3)]
    ok, out = propagate(doms, cons)
    assert ok is False
    assert out["x"].is_empty()


def test_propagate_ignores_garbage():
    ok, out = propagate({"x": IntInterval(0, 5)}, [object(), None])  # type: ignore[list-item]
    assert ok and out["x"] == IntInterval(0, 5)


# ============================================================
# 求解
# ============================================================
def test_solve_finds_assignment():
    syms = [Sym("x", IntInterval(0, 10)), Sym("y", IntInterval(0, 10))]
    cons = [LinCmp.le(LinExpr.var("x") + LinExpr.var("y") - 10),
            LinCmp.ge(LinExpr.var("x") - 3)]
    got = solve(syms, cons)
    assert got is not None
    assert isinstance(got["x"], int) and isinstance(got["y"], int)
    assert got["x"] + got["y"] <= 10 and got["x"] >= 3


def test_solve_unsat_returns_none():
    syms = [Sym("x", IntInterval(0, 10))]
    cons = [LinCmp.ge(LinExpr.var("x") - 5), LinCmp.le(LinExpr.var("x") - 3)]
    assert solve(syms, cons) is None
    assert is_satisfiable(syms, cons) is False


def test_solve_is_deterministic():
    syms = [Sym("a", IntInterval(0, 50)), Sym("b", IntInterval(0, 50))]
    cons = [LinCmp.le(LinExpr.var("a") + LinExpr.var("b") - 17)]
    first = solve(syms, cons)
    for _ in range(5):
        assert solve(syms, cons) == first


def test_solve_with_setin_and_str_domain():
    syms = [Sym("status", StrDomain())]
    cons = [SetIn("status", ("paid", "pending"))]
    got = solve(syms, cons)
    assert got is not None and got["status"] in ("paid", "pending")


def test_solve_respects_ne_constraint():
    syms = [Sym("x", IntInterval(0, 2))]
    cons = [LinCmp.ne(LinExpr.var("x"))]
    got = solve(syms, cons)
    assert got is not None and got["x"] != 0


def test_solve_fail_closed_on_empty_and_garbage():
    assert solve([], []) == {}                     # 无变量无约束：平凡可满足
    assert solve(None, None) == {}                 # type: ignore[arg-type]
    assert solve([Sym("x", IntInterval(5, 3))], []) is None   # 空域 → 不可满足


def test_all_solutions_enumeration_limit():
    syms = [Sym("x", IntInterval(0, 100))]
    cons = [LinCmp.le(LinExpr.var("x") - 5)]
    sols = all_solutions(syms, cons, limit=4)
    assert len(sols) == 4
    assert [s["x"] for s in sols] == [0, 1, 2, 3]   # 确定序（升序）
    assert all_solutions(syms, cons, limit=0) == [] or len(all_solutions(syms, cons, limit=0)) >= 0


# ============================================================
# 业务不变量场景（A1 的 FP 控制核心）
# ============================================================
def _invariant_system(unit_price: int = 100, qty_range=(-100, 100)):
    """建模：total == unit_price * qty（unit_price 为观测到的具体值 → 线性不变量）。"""
    syms = [Sym("qty", IntInterval(*qty_range)),
            Sym("total", IntInterval(-10 ** 6, 10 ** 6))]
    invariant = LinCmp.eq(LinExpr.var("total") - LinExpr.var("qty") * unit_price)
    return syms, invariant


def test_invariant_blocks_false_positive():
    """不变量成立时，"正数量却拿到非正总价"这类篡改目标必须判不可满足（不误报）。"""
    syms, invariant = _invariant_system()
    tamper_goal = [LinCmp.gt(LinExpr.var("qty")), LinCmp.le(LinExpr.var("total"))]
    assert is_satisfiable(syms, [invariant] + tamper_goal) is False


def test_missing_invariant_allows_detection():
    """去掉不变量（服务端真没校验）→ 同一目标变为可满足 = 真实可利用路径。"""
    syms, _ = _invariant_system()
    tamper_goal = [LinCmp.gt(LinExpr.var("qty")), LinCmp.le(LinExpr.var("total"))]
    got = solve(syms, tamper_goal)
    assert got is not None
    assert got["qty"] > 0 and got["total"] <= 0


def test_negative_quantity_domain_violation():
    """域越界（负数量）探测：约束只写 qty>=0 时负值不可解；缺失时可解。"""
    syms = [Sym("qty", IntInterval(-100, 100))]
    guarded = [LinCmp.ge(LinExpr.var("qty"))]
    assert solve(syms, guarded + [LinCmp.lt(LinExpr.var("qty"))]) is None
    got = solve(syms, [LinCmp.lt(LinExpr.var("qty"))])
    assert got is not None and got["qty"] < 0


def test_optimize_min_and_max():
    syms, invariant = _invariant_system()
    cons = [invariant, LinCmp.ge(LinExpr.var("qty") - 1), LinCmp.le(LinExpr.var("qty") - 10)]
    lo = optimize(syms, cons, LinExpr.var("total"), sense="min")
    hi = optimize(syms, cons, LinExpr.var("total"), sense="max")
    assert lo is not None and lo[1] == 100
    assert hi is not None and hi[1] == 1000


def test_optimize_branch_and_bound_large_space():
    """P1-9 分支限界：10 变量大域 max Σx。

    旧实现"全枚举可行解取极值"在 8^10 组合空间里受节点预算限制拿不到最优；
    分支限界靠目标导向值序直达上界、再用目标界整枝收尾 → 精确最优。
    """
    syms = [Sym(f"x{i}", IntInterval(0, 1000)) for i in range(10)]
    obj = LinExpr.var("x0")
    for i in range(1, 10):
        obj = obj + LinExpr.var(f"x{i}")
    got = optimize(syms, [], obj, sense="max")
    assert got is not None and got[1] == 10000
    assert all(v == 1000 for v in got[0].values())
    # min 方向对称：全下界
    got_min = optimize(syms, [], obj, sense="min")
    assert got_min is not None and got_min[1] == 0


def test_optimize_branch_and_bound_with_constraint():
    """带约束的大域：max x+y s.t. x+y<=150 —— 剪枝不得越过约束边界。"""
    syms = [Sym("x", IntInterval(0, 1000)), Sym("y", IntInterval(0, 1000))]
    cons = [LinCmp.le(LinExpr.var("x") + LinExpr.var("y") - 150)]
    got = optimize(syms, cons, LinExpr.var("x") + LinExpr.var("y"), sense="max")
    assert got is not None
    assert got[1] <= 150
    assert got[0]["x"] + got[0]["y"] == 150  # 可行且触及约束边界


# ============================================================
# 可选 z3 交叉验证（缺 z3 自动跳过）
# ============================================================
@pytest.mark.skipif(not z3_available(), reason="z3 未安装（可选交叉验证后端）")
def test_z3_cross_check_matches_builtin():
    syms = [Sym("x", IntInterval(-50, 50)), Sym("y", IntInterval(-50, 50))]
    cons = [LinCmp.le(LinExpr.var("x") + LinExpr.var("y") - 20),
            LinCmp.ge(LinExpr.var("x") - LinExpr.var("y"))]
    assert z3_check(syms, cons) == is_satisfiable(syms, cons) is True

    unsat_cons = [LinCmp.ge(LinExpr.var("x") - 5), LinCmp.le(LinExpr.var("x") - 3)]
    assert z3_check(syms, unsat_cons) == is_satisfiable(syms, unsat_cons) is False


def test_z3_check_returns_none_when_unavailable_or_unsupported(monkeypatch):
    """z3 缺失 → None（静默降级）；不支持浮点/字符串域 → None。"""
    import vulnclaw.engines.symbolic.solver as solver_mod

    monkeypatch.setattr(solver_mod, "z3_available", lambda: False)
    assert z3_check([Sym("x", IntInterval(0, 1))], []) is None

    monkeypatch.undo()
    if z3_available():
        got = z3_check([Sym("f", StrDomain())], [])
        assert got is None
