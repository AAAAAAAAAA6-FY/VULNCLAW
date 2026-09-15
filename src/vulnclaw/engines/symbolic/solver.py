# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/solver.py
"""约束求解器 —— 区间传播（bound consistency）+ 确定性回溯搜索。

定位
----
A1 符号执行支柱的"求解引擎"：给定符号变量（带值域）+ 线性约束系统，回答三种问题：
  1. `is_satisfiable(...)`  有没有解？（可用于判定"这条攻击路径是否可行"）
  2. `solve(...)`           给我一个解（可直接当攻击载荷用）
  3. `optimize(...)`        给我"最有利"的解（如让 total 相对应有金额偏得最多）

实现纪律
--------
* **确定性**：变量排序、候选值顺序、搜索顺序全部固定 → 同输入同输出，可复现。
* **可判定性**：整数域做区间传播（bound consistency），剪枝后回溯；带节点预算上限，
  超预算即判"未找到"（fail-closed，不返回半成品解）。
* **零新硬依赖**：核心只用标准库。z3 若已安装则作为**交叉验证后端**（`z3_check`），
  缺失时静默降级为 None，绝不 import 失败。
"""
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .values import (
    DEFAULT_WINDOW,
    Constraint,
    Domain,
    EnumDomain,
    IntInterval,
    LinCmp,
    LinExpr,
    SetIn,
    Sym,
    sort_key,
)

__all__ = [
    "propagate",
    "is_satisfiable",
    "solve",
    "optimize",
    "all_solutions",
    "z3_available",
    "z3_check",
]


# ============================================================
# 整数算术辅助（Python 的 // 对负数已是 floor，ceil 需换算）
# ============================================================
def _floor_div(a: int, b: int) -> int:
    return a // b


def _ceil_div(a: int, b: int) -> int:
    return -((-a) // b)


# ============================================================
# 区间传播
# ============================================================
def _tighten_linear(doms: Dict[str, Domain], expr: LinExpr, strict: bool) -> Tuple[bool, bool]:
    """按 `expr <= 0`（strict=True 时 `expr < 0`）收紧各变量的整数区间。

    对每个变量 j，可推出**唯一方向**的界（cj>0 得上界 / cj<0 得下界）：
        cj·xj ≤ RHS_max,  RHS_max = -k - min(Σ_{i≠j} ci·xi)
    取 min 时：ci>0 用 xi 下界、ci<0 用 xi 上界。整数域下 `< 0` 等价于 `≤ -1`。

    返回 (是否仍可能可满足, 是否有收紧)。区间无界/非整数域 → 跳过该变量（保守）。
    """
    if expr.is_const():
        v = expr.const
        ok = (v < 0) if strict else (v <= 0)
        return ok, False

    k = expr.const - (1 if strict else 0)   # 整数域：严格不等 ↔ 常数减 1
    items = list(expr.coeffs)
    changed = False

    for name, cj in items:
        dom = doms.get(name)
        if not isinstance(dom, IntInterval) or dom.is_empty():
            continue
        # 其余变量的"最小贡献"（用于把 RHS 放到最大，得到最紧但**可靠**的界）
        sum_min: Optional[int] = 0
        for n2, c2 in items:
            if n2 == name:
                continue
            d2 = doms.get(n2)
            if not isinstance(d2, IntInterval):
                sum_min = None
                break
            bound = d2.lo if c2 > 0 else d2.hi
            if bound is None:
                sum_min = None
                break
            sum_min += c2 * bound
        if sum_min is None:
            continue

        rhs_max = -k - sum_min
        if cj > 0:
            new_dom: Domain = IntInterval(None, _floor_div(rhs_max, cj))
        else:
            new_dom = IntInterval(_ceil_div(rhs_max, cj), None)

        merged = dom.intersect(new_dom)
        if isinstance(merged, IntInterval) and merged != dom:
            doms[name] = merged
            changed = True
            if merged.is_empty():
                return False, changed
    return True, changed


def propagate(
    doms: Dict[str, Domain],
    constraints: Iterable[Constraint],
    max_rounds: int = 32,
) -> Tuple[bool, Dict[str, Domain]]:
    """区间传播到不动点。返回 (是否可能可满足, 收紧后的域)。

    不可满足 → (False, 当前域)；域被清空即确定性判死。
    """
    cur = dict(doms or {})
    cons = [c for c in (constraints or []) if isinstance(c, Constraint)]

    # 空域直接判死
    for name, d in cur.items():
        if isinstance(d, Domain) and d.is_empty():
            return False, cur

    for _ in range(max(1, int(max_rounds))):
        changed = False
        for c in cons:
            if isinstance(c, LinCmp):
                if c.sense in ("le", "lt"):
                    ok, ch = _tighten_linear(cur, c.expr, strict=(c.sense == "lt"))
                elif c.sense == "eq":
                    ok, ch1 = _tighten_linear(cur, c.expr, strict=False)
                    ch = ch1
                    if ok:
                        ok, ch2 = _tighten_linear(cur, -c.expr, strict=False)
                        ch = ch or ch2
                else:  # ne：无法做区间收紧，只能靠赋值后的叶子判定
                    ok, ch = True, False
                if not ok:
                    return False, cur
                changed = changed or ch
            elif isinstance(c, SetIn):
                d = cur.get(c.var)
                if isinstance(d, (IntInterval, EnumDomain)):
                    if len(c.values) == 0:
                        return False, cur
                    merged = d.intersect(EnumDomain(tuple(c.values)))
                    if merged != d:
                        cur[c.var] = merged
                        changed = True
                        if merged.is_empty():
                            return False, cur
        if not changed:
            break
    return True, cur


# ============================================================
# 候选值 / 变量序
# ============================================================
def _candidates_for(name: str, dom: Domain, constraints: Sequence[Constraint],
                    max_enum: int, window: int) -> List[Any]:
    """某变量在传播后域中的候选值：域自采样 ∪ SetIn 白名单，稳定排序。"""
    vals: List[Any] = []
    try:
        vals.extend(dom.candidates(max_enum, window))
    except Exception:  # noqa: BLE001 - 采样异常不影响后续
        pass
    for c in constraints:
        if isinstance(c, SetIn) and c.var == name:
            for v in c.values:
                try:
                    if dom.contains(v):
                        vals.append(v)
                except Exception:  # noqa: BLE001
                    continue
    out: List[Any] = []
    for v in sorted(vals, key=sort_key):
        if not any(_same_val(v, x) for x in out):
            out.append(v)
        if len(out) >= max(1, int(max_enum)):
            break
    return out


def _same_val(a: Any, b: Any) -> bool:
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def _var_order(doms: Dict[str, Domain], constraints: Sequence[Constraint]) -> List[str]:
    """变量排序：域小的先（搜索空间窄的先定），同规模按名字 → 确定性。"""
    def size(d: Domain) -> int:
        if isinstance(d, IntInterval):
            s = d.size()
            return s if s is not None else 10 ** 9
        if isinstance(d, EnumDomain):
            return max(1, len(d.values))
        return 10 ** 8  # 不可枚举（str）放最后

    return sorted(doms.keys(), key=lambda n: (size(doms[n]), n))


# ============================================================
# 回溯搜索
# ============================================================
def solve(
    syms: Sequence[Sym],
    constraints: Iterable[Constraint],
    *,
    max_enum: int = 64,
    max_nodes: int = 50000,
    window: int = DEFAULT_WINDOW,
) -> Optional[Dict[str, Any]]:
    """求一个满足全部约束的**具体赋值**；无解/超预算 → None（fail-closed）。

    搜索策略：区间传播剪枝 → 贪心定序 → 逐变量从小到大试值 → 每步再传播。
    """
    cons = [c for c in (constraints or []) if isinstance(c, Constraint)]
    doms: Dict[str, Domain] = {}
    for s in syms or ():
        if isinstance(s, Sym) and s.name:
            doms[s.name] = s.domain

    ok, doms = propagate(doms, cons)
    if not ok:
        return None

    order = _var_order(doms, cons)
    budget = [max(1, int(max_nodes))]
    return _search(0, order, doms, cons, {}, budget, max_enum, window)


def _search(
    idx: int,
    order: List[str],
    doms: Dict[str, Domain],
    cons: Sequence[Constraint],
    assign: Dict[str, Any],
    budget: List[int],
    max_enum: int,
    window: int,
) -> Optional[Dict[str, Any]]:
    if budget[0] <= 0:
        return None
    budget[0] -= 1

    if idx >= len(order):
        # 叶子：所有变量已定，逐条判定（ne / SetIn / 非整数域在此收口）
        return dict(assign) if all(_safe_eval(c, assign) for c in cons) else None

    name = order[idx]
    for v in _candidates_for(name, doms[name], cons, max_enum, window):
        assign[name] = v
        nxt = dict(doms)
        nxt[name] = _pin(doms[name], v)
        ok, nxt = propagate(nxt, cons)
        if ok:
            got = _search(idx + 1, order, nxt, cons, assign, budget, max_enum, window)
            if got is not None:
                assign.pop(name, None)
                return got
        assign.pop(name, None)
    return None


def _pin(dom: Domain, value: Any) -> Domain:
    """把域钉死为单值（不构造新类型，只做交集）。"""
    try:
        return dom.intersect(EnumDomain((value,)))
    except Exception:  # noqa: BLE001
        return EnumDomain((value,))


def _safe_eval(c: Constraint, assign: Dict[str, Any]) -> bool:
    """约束求值永不让异常外泄：异常按"不满足"处理（fail-closed）。"""
    try:
        return bool(c.eval(assign))
    except Exception:  # noqa: BLE001
        return False


# ============================================================
# 公共查询
# ============================================================
def is_satisfiable(
    syms: Sequence[Sym],
    constraints: Iterable[Constraint],
    *,
    max_enum: int = 64,
    max_nodes: int = 20000,
    window: int = DEFAULT_WINDOW,
) -> bool:
    """是否存在满足约束的赋值。"""
    return solve(syms, constraints, max_enum=max_enum,
                 max_nodes=max_nodes, window=window) is not None


def all_solutions(
    syms: Sequence[Sym],
    constraints: Iterable[Constraint],
    *,
    limit: int = 32,
    max_enum: int = 64,
    window: int = DEFAULT_WINDOW,
) -> List[Dict[str, Any]]:
    """枚举最多 limit 个解（确定序）。域不大的场景用于"多载荷候选"。"""
    cons = [c for c in (constraints or []) if isinstance(c, Constraint)]
    doms: Dict[str, Domain] = {s.name: s.domain for s in (syms or ()) if isinstance(s, Sym) and s.name}
    ok, doms = propagate(doms, cons)
    if not ok:
        return []
    order = _var_order(doms, cons)
    out: List[Dict[str, Any]] = []
    budget = [max(200, int(limit) * 200)]

    def _walk(i: int, cur: Dict[str, Domain], assign: Dict[str, Any]):
        if len(out) >= int(limit) or budget[0] <= 0:
            return
        budget[0] -= 1
        if i >= len(order):
            if all(_safe_eval(c, assign) for c in cons):
                out.append(dict(assign))
            return
        name = order[i]
        for v in _candidates_for(name, cur[name], cons, max_enum, window):
            assign[name] = v
            nxt = dict(cur)
            nxt[name] = _pin(cur[name], v)
            ok2, nxt = propagate(nxt, cons)
            if ok2:
                _walk(i + 1, nxt, assign)
                if len(out) >= int(limit):
                    assign.pop(name, None)
                    return
            assign.pop(name, None)

    _walk(0, doms, {})
    return out


def optimize(
    syms: Sequence[Sym],
    constraints: Iterable[Constraint],
    objective: LinExpr,
    *,
    sense: str = "min",
    max_enum: int = 64,
    window: int = DEFAULT_WINDOW,
    max_nodes: int = 20000,
) -> Optional[Tuple[Dict[str, Any], int]]:
    """在可行域上优化线性目标（业务场景：让 total 相对应收金额偏得最多）。

    返回 (最优赋值, 目标值)；不可行 → None。
    P1-9（2026-09-15）：由"全枚举可行解取极值"升级为**分支限界**——
    ① 区间传播对目标表达式估计上下界，界不可能严格超越当前最优的子树整枝；
    ② 候选值按目标系数定向排序（min 下正系数先小值 / 负系数先大值），
       尽早命中好解让剪枝更早生效。
    确定性不变：同输入同输出；节点预算超限返回已找到的最优（仍是可行解）。
    """
    objs = objective if isinstance(objective, LinExpr) else LinExpr.of_const(int(objective))
    cons = [c for c in (constraints or []) if isinstance(c, Constraint)]
    doms: Dict[str, Domain] = {
        s.name: s.domain for s in (syms or ()) if isinstance(s, Sym) and s.name
    }
    ok, doms = propagate(doms, cons)
    if not ok:
        return None

    order = _var_order(doms, cons)
    coef = dict(objs.coeffs)
    k0 = objs.const
    minimize = str(sense).lower() != "max"
    budget = [max(1000, int(max_nodes))]
    best: List[Optional[Tuple[Dict[str, Any], Any]]] = [None]

    def _bound(cur: Dict[str, Domain]) -> Optional[Tuple[Any, Any]]:
        """目标在当前域上的 [lo, hi]；含无界/不可枚举变量 → None（不可剪枝）。"""
        lo = hi = k0
        for name, c in coef.items():
            d = cur.get(name)
            if not isinstance(d, IntInterval) or d.lo is None or d.hi is None:
                return None
            lo += c * d.lo
            hi += c * d.hi
        return lo, hi

    def _better(val: Any) -> bool:
        if best[0] is None:
            return True
        return val < best[0][1] if minimize else val > best[0][1]

    def _ordered(vals: List[Any], name: str) -> List[Any]:
        """目标导向值序：正×min / 负×max → 小值优先（候选本就升序，否则反转）。"""
        c = coef.get(name)
        if not c or not vals:
            return vals
        favor_small = (c > 0) == minimize
        return vals if favor_small else list(reversed(vals))

    def _walk(i: int, cur: Dict[str, Domain], assign: Dict[str, Any]) -> None:
        if budget[0] <= 0:
            return
        budget[0] -= 1
        b = _bound(cur)
        if b is not None and best[0] is not None:
            lo, hi = b
            if minimize and lo >= best[0][1]:
                return  # 子树上界也不可能严格更优 → 整枝
            if (not minimize) and hi <= best[0][1]:
                return
        if i >= len(order):
            if all(_safe_eval(c, assign) for c in cons):
                val = objs.eval(assign)
                if _better(val):
                    best[0] = (dict(assign), val)
            return
        name = order[i]
        for v in _ordered(_candidates_for(name, cur[name], cons, max_enum, window), name):
            assign[name] = v
            nxt = dict(cur)
            nxt[name] = _pin(cur[name], v)
            ok2, nxt = propagate(nxt, cons)
            if ok2:
                _walk(i + 1, nxt, assign)
            assign.pop(name, None)
            if budget[0] <= 0:
                return

    _walk(0, doms, {})
    return best[0]


# ============================================================
# 可选 z3 后端（交叉验证；缺省静默降级）
# ============================================================
def z3_available() -> bool:
    try:
        import z3  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 - 缺 z3 是常态，不是错误
        return False


def z3_check(
    syms: Sequence[Sym],
    constraints: Iterable[Constraint],
) -> Optional[bool]:
    """用 z3 独立复算可满足性；z3 未安装或不支持该约束形态 → None。

    只用于**交叉验证**（自检/测试），不参与主求解路径 → 主路径确定性不受影响。
    """
    if not z3_available():
        return None
    try:
        import z3  # type: ignore
    except Exception:  # noqa: BLE001
        return None

    try:
        vars_ = {}
        solver = z3.Solver()
        for s in syms or ():
            if not isinstance(s, Sym):
                continue
            d = s.domain
            if isinstance(d, IntInterval):
                v = z3.Int(s.name)
                if d.lo is not None:
                    solver.add(v >= int(d.lo))
                if d.hi is not None:
                    solver.add(v <= int(d.hi))
            elif isinstance(d, EnumDomain):
                numeric = [x for x in d.values if isinstance(x, int) and not isinstance(x, bool)]
                if len(numeric) != len(d.values):
                    return None      # 非整数枚举不由 z3 复算
                v = z3.Int(s.name)
                solver.add(z3.Or([v == int(x) for x in numeric]) if numeric else z3.BoolVal(False))
            else:
                return None          # 浮点/字符串域不由 z3 复算
            vars_[s.name] = v

        for c in constraints or ():
            if isinstance(c, LinCmp):
                e = z3.IntVal(int(c.expr.const))
                for name, coef in c.expr.coeffs:
                    if name not in vars_:
                        return None
                    e = e + int(coef) * vars_[name]
                if c.sense == "le":
                    solver.add(e <= 0)
                elif c.sense == "lt":
                    solver.add(e < 0)
                elif c.sense == "eq":
                    solver.add(e == 0)
                else:
                    solver.add(e != 0)
            elif isinstance(c, SetIn):
                if c.var not in vars_:
                    return None
                numeric = [x for x in c.values if isinstance(x, int) and not isinstance(x, bool)]
                if len(numeric) != len(c.values):
                    return None
                solver.add(z3.Or([vars_[c.var] == int(x) for x in numeric]))
            else:
                return None
        return solver.check() == z3.sat
    except Exception:  # noqa: BLE001 - 交叉验证失败不视为错误
        return None
