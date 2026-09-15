# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/objectives.py
"""目标谓词库 —— 把"逻辑洞要达成什么"翻译成可判定约束系统。

A1 的判定链
-----------
    IR（业务模型） → 目标谓词（本模块） → 约束系统 → solver 判定可行性
      · 可行   = 在"服务端无该校验"前提下攻击目标成立 → 生成候选交验证层
      · 不可行 = 被业务不变量挡住 → **不产出**（这就是 A1 的误报控制核心）

六类目标（覆盖"无 payload 特征"的逻辑洞）
------------------------------------------
    authz        越权（水平 IDOR / 垂直提权）
    amount       金额篡改（改总价 / 改单价）
    quantity     数量越界（负值 / 零 / 超上限）
    flow         流程跳跃（跳过前置步骤直达终态）
    idempotency  幂等破坏（重复提交 / 重放）
    overflow     数值溢出（单价 × 数量的定宽整型溢出）

**fail-closed**：目标或不变量的变量缺值域定义 → 判 `undecidable`（不产出），
绝不默认"无界可满足"——那是误报的主要来源。
"""
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .solver import solve
from .values import (
    DEFAULT_WINDOW,
    Constraint,
    EnumDomain,
    FloatInterval,
    IntInterval,
    LinCmp,
    LinExpr,
    SetIn,
    Sym,
    sort_key,
)

__all__ = [
    "PARAM_SYNONYMS",
    "classify_param",
    "admin_values_for",
    "Objective",
    "ObjectiveResult",
    "authz_objective",
    "amount_objective",
    "quantity_objective",
    "flow_objective",
    "idempotency_objective",
    "overflow_objective",
    "objectives_for",
    "evaluate",
    "VULN_TYPES",
]

# 参数名 → 语义类（业务参数命名千变万化，这里只做保守归类）
PARAM_SYNONYMS: Dict[str, Tuple[str, ...]] = {
    "amount": ("amount", "total", "price", "fee", "cost", "money", "balance",
               "pay", "payment", "subtotal", "sum", "discount", "coupon_value"),
    "quantity": ("qty", "quantity", "count", "num", "quantity_num", "cart_num"),
    "role": ("role", "is_admin", "isadmin", "admin", "level", "privilege",
             "permission", "group", "kind", "user_type", "usertype"),
    "identity": ("id", "uid", "user_id", "userid", "account", "account_id", "owner",
                 "owner_id", "uuid", "pid", "order_id", "orderid", "item_id"),
    "step": ("step", "stage", "phase", "progress", "confirm", "verify", "checkout",
             "state", "status"),
    "flag": ("flag", "enabled", "active", "verified", "approved", "paid", "locked",
             "is_paid", "is_verified"),
}

VULN_TYPES = {
    "authz": ("越权访问（水平/垂直）", "CWE-639", "high"),
    "amount": ("金额篡改", "CWE-840", "high"),
    "quantity": ("数量越界", "CWE-1284", "medium"),
    "flow": ("业务流程序列绕过", "CWE-841", "high"),
    "idempotency": ("幂等破坏/重放", "CWE-837", "medium"),
    "overflow": ("数值溢出", "CWE-190", "medium"),
}


def classify_param(name: str) -> Optional[str]:
    """把参数名归到语义类；无法归类返回 None（宁缺毋滥）。"""
    if not isinstance(name, str) or not name:
        return None
    low = name.strip().lower()
    # 先精确匹配，再做包含匹配（精确优先，避免 "id" 吞掉 "valid"）
    for kind, words in PARAM_SYNONYMS.items():
        if low in words:
            return kind
    for kind, words in PARAM_SYNONYMS.items():
        for w in words:
            if len(w) >= 4 and w in low:
                return kind
    return None


def _looks_privileged(v: Any) -> bool:
    """该值看起来是否"高权限"（真值 / 正整数 / admin 类词）。"""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v >= 1
    s = str(v).strip().lower()
    return s in ("admin", "administrator", "root", "superuser", "super",
                 "1", "true", "yes", "on")


def admin_values_for(domain: Any,
                     fallback: Sequence[Any] = ("admin", "administrator", "1", True)
                     ) -> Tuple[Any, ...]:
    """按参数**值域**挑选高权限值。

    直接给 "admin"/True 这类字面量在当前域里可能根本不存在（如 role 是 int 域 {0,1}），
    SetIn 与值域天然不相交 → 目标恒不可满足 → 白丢检出。故按域自适应：
      * 枚举域：优先域内"看起来高权限"的值；没有则取最大元素
      * 整数区间：取上界（上界为 0 时退化为 1）
      * 其它（字符串域等）：用 fallback
    """
    if isinstance(domain, EnumDomain) and domain.values:
        # 只保留**确实是高权限**的值。一个都没有时返回空元组（目标不可满足）——
        # 早期实现退回"取最大值"，会让 role∈{0} 这种情形把目标变成 role=0（平凡可满足）
        # → 直接制造误报。宁可不报，绝不退化。
        return tuple(sorted((v for v in domain.values if _looks_privileged(v)), key=sort_key))
    if isinstance(domain, IntInterval):
        if domain.hi is None:
            return tuple(fallback)          # 无界：交由 evaluate 的"值域无约束力"闸拦截
        return (domain.hi,) if domain.hi >= 1 else ()
    return tuple(fallback)


@dataclass(frozen=True)
class Objective:
    """一个可判定的攻击目标：goal 约束全部成立 ⇔ 该逻辑洞成立。"""

    id: str
    kind: str
    vuln_type: str
    cwe: str
    severity: str
    params: Tuple[str, ...]
    goal: Tuple[Constraint, ...]
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "kind": self.kind, "vuln_type": self.vuln_type,
            "cwe": self.cwe, "severity": self.severity,
            "params": list(self.params),
            "goal": [c.to_dict() for c in self.goal],
            "note": self.note,
        }


@dataclass
class ObjectiveResult:
    """判定结果。undecidable=True 表示输入信息不足（缺值域），一律**不产出**。"""

    objective: Objective
    feasible: bool
    witness: Optional[Dict[str, Any]] = None
    blocked_by: Tuple[str, ...] = ()
    undecidable: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "objective": self.objective.to_dict(),
            "feasible": self.feasible,
            "witness": self.witness,
            "blocked_by": list(self.blocked_by),
            "undecidable": self.undecidable,
            "reason": self.reason,
        }


def _mk(kind: str, params: Sequence[str], goal: Sequence[Constraint],
        *, oid: str = "", note: str = "") -> Objective:
    vtype, cwe, sev = VULN_TYPES.get(kind, ("未知", "", "medium"))
    return Objective(
        id=oid or f"{kind}:{','.join(params)}",
        kind=kind, vuln_type=vtype, cwe=cwe, severity=sev,
        params=tuple(params), goal=tuple(goal), note=note,
    )


# ============================================================
# 六类目标构造器
# ============================================================
def authz_objective(param: str,
                    admin_values: Sequence[Any] = ("admin", "administrator", "1", True),
                    base_values: Sequence[Any] = ("user", "0", False)) -> Objective:
    """垂直越权：把角色/权限参数置于"高权限值"。

    目标本身只是"取到高权限值"（SetIn）；是否**真的**越权由不变量（服务端对角色
    的硬校验）判定——若 IR 里存在 role 受限的不变量，本目标会被判死（不产出）。
    """
    goal = [SetIn(param, tuple(admin_values))]
    return _mk("authz", (param,), goal,
               note=f"高权限值={list(admin_values)}，基线值={list(base_values)}；"
                    f"服务端若对 {param} 做硬校验则目标不可满足")


def amount_objective(unit_price: int, *, price_name: Optional[str] = None,
                     qty_name: Optional[str] = None,
                     total_name: Optional[str] = None,
                     mode: str = "total") -> Objective:
    """金额篡改。unit_price 为**观测到的真实单价**（具体值 → 约束保持线性）。

    mode="total"：qty>0 且 total < 真实单价×数量  → 总价被压低
    mode="price"：qty>0 且 price < 真实单价        → 单价被压低
    """
    params: List[str] = []
    goal: List[Constraint] = []
    if mode == "price":
        pname = price_name or "price"
        params.append(pname)
        goal.append(LinCmp.lt(LinExpr.var(pname) - int(unit_price)))
        if qty_name:                      # 有数量参数时补 qty>0，贴近真实下单语义
            params.append(qty_name)
            goal.append(LinCmp.gt(LinExpr.var(qty_name)))
    else:
        tname = total_name or "total"
        qname = qty_name or "qty"
        params.extend([tname, qname])
        goal.append(LinCmp.lt(LinExpr.var(tname) - LinExpr.var(qname) * int(unit_price)))
        goal.append(LinCmp.gt(LinExpr.var(qname)))
    return _mk("amount", params, goal, oid=f"amount:{mode}:{','.join(params)}",
               note=f"真实单价={unit_price}；{mode} 模式下目标是否可满足")


def quantity_objective(qty_name: str, min_allowed: int = 1) -> Objective:
    """数量越界：低于业务下限（负值 / 零 / 低于起订量）。"""
    goal = [LinCmp.lt(LinExpr.var(qty_name) - int(min_allowed))]
    return _mk("quantity", (qty_name,), goal,
               note=f"目标：{qty_name} < {min_allowed}（应为服务端硬校验）")


def flow_objective(step_param: str, terminal_values: Sequence[Any],
                   precondition_values: Sequence[Any] = ()) -> Objective:
    """流程跳跃：直接落在终态。precondition_values 给出"正常应处于的前置状态"，
    由 IR 的 transitions.preconditions 提供；不变量守门时会被判死。"""
    goal: List[Constraint] = [SetIn(step_param, tuple(terminal_values))]
    return _mk("flow", (step_param,), goal,
               note=f"直达终态 {list(terminal_values)}；前置态={list(precondition_values)}")


def idempotency_objective(counter_name: str = "submit_count",
                          limit: int = 1) -> Objective:
    """幂等破坏：同一业务动作被允许重复生效（计数超过容忍次数）。"""
    goal = [LinCmp.gt(LinExpr.var(counter_name) - int(limit))]
    return _mk("idempotency", (counter_name,), goal,
               note=f"同一动作生效次数 > {limit}（重复下单/重复领券）")


def overflow_objective(qty_name: str, unit_price: int,
                       max_value: int = 2 ** 31 - 1) -> Objective:
    """数值溢出：单价 × 数量超出定宽整型上限（服务端常见 32 位截断）。"""
    goal = [LinCmp.gt(LinExpr.var(qty_name) * int(unit_price)
                      - LinExpr.of_const(int(max_value)))]
    return _mk("overflow", (qty_name,), goal,
               note=f"{qty_name}×{unit_price} > {max_value}（定宽溢出）")


def objectives_for(params: Sequence[str], *, unit_price: Optional[int] = None,
                   admin_values: Sequence[Any] = ("admin", "administrator", "1", True),
                   terminal_values: Sequence[Any] = (),
                   domains: Optional[Dict[str, Any]] = None) -> List[Objective]:
    """从参数名清单推导候选目标（纯启发式，确定性；不猜的不报）。

    domains：可选 {参数名: Domain}。给了就按域自适应高权限值（见 admin_values_for），
    避免"字面量不在域内 → 目标恒不可满足"造成的白丢检出。
    """
    names = [str(p) for p in (params or []) if p]
    kinds: Dict[str, List[str]] = {}
    for n in names:
        k = classify_param(n)
        if k:
            kinds.setdefault(k, []).append(n)

    out: List[Objective] = []
    dom_map = domains or {}
    for n in kinds.get("role", []):
        vals = admin_values_for(dom_map.get(n), admin_values) if n in dom_map else tuple(admin_values)
        out.append(authz_objective(n, vals))
    for n in kinds.get("quantity", []):
        out.append(quantity_objective(n))
        if unit_price:
            out.append(overflow_objective(n, int(unit_price)))
    if unit_price:
        pname = (kinds.get("amount") or [None])[0]
        if pname:
            out.append(amount_objective(int(unit_price), price_name=pname, mode="price"))
        qty = (kinds.get("quantity") or [None])[0]
        if qty:
            out.append(amount_objective(int(unit_price), qty_name=qty, mode="total"))
    if terminal_values:
        for n in kinds.get("step", []):
            out.append(flow_objective(n, terminal_values))
    return out


# ============================================================
# 判定
# ============================================================
def _uninformative(dom: Any) -> bool:
    """值域是否"无约束力"（无法对目标构成真正约束）。

    无界整数/浮点区间、空枚举、字符串域都算无信息：此时"目标可满足"是**空洞的**
    （只是我们自己挑了个值），不能作为"服务端缺少校验"的证据。缺这道闸，A1 会对任何
    参数名像 role/qty 的端点批量产出误报——这是本引擎最危险的失手模式。
    """
    if isinstance(dom, IntInterval):
        return dom.lo is None or dom.hi is None
    if isinstance(dom, FloatInterval):
        return dom.lo is None or dom.hi is None
    if isinstance(dom, EnumDomain):
        return len(dom.values) == 0
    return True                      # StrDomain / 未知类型：不可枚举 → 无约束力


def _missing_domains(syms: Sequence[Sym], constraints: Sequence[Constraint]) -> List[str]:
    have = {s.name for s in syms or () if isinstance(s, Sym)}
    need: set = set()
    for c in constraints or ():
        try:
            need |= set(c.vars())
        except Exception:  # noqa: BLE001
            continue
    return sorted(need - have)


def evaluate(objective: Objective, syms: Sequence[Sym],
             invariants: Sequence[Tuple[str, Constraint]] = (),
             *, max_enum: int = 64, window: int = DEFAULT_WINDOW) -> ObjectiveResult:
    """判定目标在（可选）业务不变量约束下是否可行。

    invariants: [(不变量 id, 约束)]，来自 IR 的 `invariants`。
    变量缺值域 → undecidable（fail-closed，不产出）。
    """
    if not isinstance(objective, Objective):
        return ObjectiveResult(_mk("unknown", (), ()), False, None, (), True, "非法目标")

    inv = [(str(i), c) for i, c in (invariants or ()) if isinstance(c, Constraint)]
    goal = list(objective.goal)
    all_cons = goal + [c for _, c in inv]

    miss = _missing_domains(syms, all_cons)
    if miss:
        return ObjectiveResult(objective, False, None, (), True,
                               f"缺少值域定义: {','.join(miss)}")

    # 值域无约束力（无界区间 / 纯字符串域）→ 目标可满足是空洞的，不构成校验缺失证据
    dom_map = {s.name: s.domain for s in syms or () if isinstance(s, Sym)}
    goal_vars: set = set()
    for c in goal:
        try:
            goal_vars |= set(c.vars())
        except Exception:  # noqa: BLE001
            continue
    vacuous = sorted(v for v in goal_vars if _uninformative(dom_map.get(v)))
    if vacuous:
        return ObjectiveResult(objective, False, None, (), True,
                               f"值域无约束力（证据不足，不据此判定）: {','.join(vacuous)}")

    try:
        witness = solve(syms, all_cons, max_enum=max_enum, window=window)
    except Exception as exc:  # noqa: BLE001 - 求解异常按"不产出"处理
        return ObjectiveResult(objective, False, None, (), True, f"求解异常: {exc}")

    if witness is not None:
        return ObjectiveResult(objective, True, witness, (), False, "目标可行（需验证层确认）")

    # 不可行 → 诊断哪条不变量挡住了它（用于报告解释 + 低置信不变量转人工复核）
    blockers: List[str] = []
    for idx, (iid, _c) in enumerate(inv):
        rest = goal + [cc for j, (_, cc) in enumerate(inv) if j != idx]
        try:
            if solve(syms, rest, max_enum=max_enum, window=window) is not None:
                blockers.append(iid)
        except Exception:  # noqa: BLE001
            continue
    return ObjectiveResult(objective, False, None, tuple(blockers), False,
                           "被业务不变量挡住" if blockers else "约束系统无解")
