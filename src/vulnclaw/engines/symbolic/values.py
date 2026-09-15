# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/values.py
"""符号值 / 值域 / 线性约束 —— A1 符号执行支柱的最底层。

分层：
    Domain（值域） → Sym（符号变量） → LinExpr（线性表达式） → Constraint（约束） → ConstraintSet

为什么需要这一层（能力定位）
------------------------------
现有 75 个引擎检测的是"有 payload 特征"的注入类；对**无 payload 特征**的逻辑洞
（越权 / 金额篡改 / 数量越界 / 流程跳跃）只能靠启发式猜。本层把业务参数建模为
**带值域的符号变量** + **约束系统**，于是"找一个能让 total < Σ price×qty 成立的输入"
变成一个可判定、可复现、可审计的求解问题——这是纯确定性推理，与 LLM 无关。

纪律（与项目一致）
------------------
* **纯确定性**：无随机、无时间依赖、无全局可变状态 → 同输入同输出，可复现可审计。
* **零新硬依赖**：只用标准库；z3 仅在 solver 层可选（装了才用，缺则降级）。
* **fail-closed**：空域 / 非法表达式一律判"不可满足"，绝不把异常抛给调用方。
"""
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

__all__ = [
    "Domain",
    "IntInterval",
    "FloatInterval",
    "EnumDomain",
    "StrDomain",
    "BOOL_DOMAIN",
    "Sym",
    "LinExpr",
    "Constraint",
    "LinCmp",
    "SetIn",
    "ConstraintSet",
    "sort_key",
]

# 搜索窗口：无界域的候选采样范围（避免无界枚举爆炸）
DEFAULT_WINDOW = 1000


def sort_key(v: Any) -> Tuple[int, float, str]:
    """跨类型稳定排序键：数值在前（含 bool），字符串在后；保证求解顺序可复现。"""
    if isinstance(v, bool):
        return (0, int(v), "")
    if isinstance(v, (int, float)):
        return (0, float(v), "")
    return (1, 0.0, str(v))


# ============================================================
# 值域
# ============================================================
class Domain:
    """值域基类。所有子类必须保证 contains() 是**纯函数**且无副作用。"""

    kind: str = "any"

    def is_empty(self) -> bool:  # pragma: no cover - 抽象
        raise NotImplementedError

    def contains(self, v: Any) -> bool:  # pragma: no cover - 抽象
        raise NotImplementedError

    def intersect(self, other: "Domain") -> "Domain":  # pragma: no cover - 抽象
        raise NotImplementedError

    def candidates(self, limit: int = 64, window: int = DEFAULT_WINDOW) -> List[Any]:
        """确定性候选值列表（升序）。无法枚举的域返回 []。"""
        return []

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": self.kind}


@dataclass(frozen=True)
class IntInterval(Domain):
    """整数区间域（含端点）；lo/hi 为 None 表示该侧无界。"""

    lo: Optional[int] = None
    hi: Optional[int] = None
    kind: str = "int"

    def __post_init__(self):
        if self.lo is not None:
            object.__setattr__(self, "lo", int(self.lo))
        if self.hi is not None:
            object.__setattr__(self, "hi", int(self.hi))

    @classmethod
    def of(cls, lo: Optional[int] = None, hi: Optional[int] = None) -> "IntInterval":
        return cls(lo, hi)

    def is_empty(self) -> bool:
        return self.lo is not None and self.hi is not None and self.lo > self.hi

    def contains(self, v: Any) -> bool:
        if isinstance(v, bool) or not isinstance(v, int):
            return False
        if self.lo is not None and v < self.lo:
            return False
        if self.hi is not None and v > self.hi:
            return False
        return True

    def size(self) -> Optional[int]:
        if self.lo is None or self.hi is None:
            return None
        return max(0, self.hi - self.lo + 1)

    def intersect(self, other: "Domain") -> Domain:
        if isinstance(other, IntInterval):
            lo = _max_opt(self.lo, other.lo)
            hi = _min_opt(self.hi, other.hi)
            return IntInterval(lo, hi)
        if isinstance(other, EnumDomain):
            vals = [v for v in other.values if self.contains(v)]
            return EnumDomain(tuple(vals))
        return self

    def candidates(self, limit: int = 64, window: int = DEFAULT_WINDOW) -> List[Any]:
        if self.is_empty():
            return []
        lo = self.lo if self.lo is not None else -int(window)
        hi = self.hi if self.hi is not None else int(window)
        if hi < lo:
            return []
        if hi - lo + 1 <= int(limit):
            return list(range(lo, hi + 1))
        # 大域：只取"有语义"的点（边界 / 0 / ±1 / 邻界），避免枚举爆炸
        pts = {lo, hi, 0, 1, -1, lo + 1, hi - 1, lo - 1, hi + 1}
        return sorted(v for v in pts if self.contains(v))

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": "int", "lo": self.lo, "hi": self.hi}


@dataclass(frozen=True)
class FloatInterval(Domain):
    """浮点区间域（含端点）。求解不做区间收紧（只做取值判定），避免浮点误差污染推理。"""

    lo: Optional[float] = None
    hi: Optional[float] = None
    kind: str = "float"

    def is_empty(self) -> bool:
        return self.lo is not None and self.hi is not None and self.lo > self.hi

    def contains(self, v: Any) -> bool:
        if isinstance(v, bool) or not isinstance(v, (int, float)):
            return False
        if self.lo is not None and float(v) < float(self.lo):
            return False
        if self.hi is not None and float(v) > float(self.hi):
            return False
        return True

    def intersect(self, other: "Domain") -> Domain:
        if isinstance(other, FloatInterval):
            return FloatInterval(_max_opt(self.lo, other.lo), _min_opt(self.hi, other.hi))
        if isinstance(other, EnumDomain):
            return EnumDomain(tuple(v for v in other.values if self.contains(v)))
        return self

    def candidates(self, limit: int = 64, window: int = DEFAULT_WINDOW) -> List[Any]:
        if self.is_empty():
            return []
        lo = self.lo if self.lo is not None else -float(window)
        hi = self.hi if self.hi is not None else float(window)
        if hi < lo:
            return []
        pts = {float(lo), float(hi), 0.0, 1.0, -1.0, 0.01, -0.01}
        return sorted(v for v in pts if self.contains(v))

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": "float", "lo": self.lo, "hi": self.hi}


@dataclass(frozen=True)
class EnumDomain(Domain):
    """枚举域（字符串 / 布尔 / 少量候选整数的闭合集合）；构造时去重且保序。"""

    values: Tuple[Any, ...] = ()
    kind: str = "enum"

    def __post_init__(self):
        seen = []
        for v in self.values:
            if not any(_same(v, x) for x in seen):
                seen.append(v)
        object.__setattr__(self, "values", tuple(seen))

    def is_empty(self) -> bool:
        return len(self.values) == 0

    def contains(self, v: Any) -> bool:
        return any(_same(v, x) for x in self.values)

    def intersect(self, other: "Domain") -> Domain:
        if isinstance(other, IntInterval):
            return EnumDomain(tuple(v for v in self.values if other.contains(v)))
        if isinstance(other, EnumDomain):
            return EnumDomain(tuple(v for v in self.values if other.contains(v)))
        if isinstance(other, StrDomain):
            return EnumDomain(tuple(v for v in self.values if other.contains(v)))
        return self

    def candidates(self, limit: int = 64, window: int = DEFAULT_WINDOW) -> List[Any]:
        return sorted(self.values, key=sort_key)[: int(limit)]

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": "enum", "values": list(self.values)}


@dataclass(frozen=True)
class StrDomain(Domain):
    """字符串域：可选正则全匹配 + 长度上限。不可枚举（candidates 恒为 []），
    取值只能来自 SetIn 约束或显式给定。"""

    pattern: Optional[str] = None
    max_len: Optional[int] = None
    kind: str = "str"

    def is_empty(self) -> bool:
        return self.max_len is not None and int(self.max_len) < 0

    def contains(self, v: Any) -> bool:
        if not isinstance(v, str):
            return False
        if self.max_len is not None and len(v) > int(self.max_len):
            return False
        if self.pattern:
            import re

            try:
                if re.fullmatch(self.pattern, v) is None:
                    return False
            except re.error:
                return False
        return True

    def intersect(self, other: "Domain") -> Domain:
        if isinstance(other, EnumDomain):
            return EnumDomain(tuple(v for v in other.values if self.contains(v)))
        if isinstance(other, StrDomain):
            return StrDomain(self.pattern or other.pattern,
                             _min_opt(self.max_len, other.max_len))
        return self

    def to_dict(self) -> Dict[str, Any]:
        return {"kind": "str", "pattern": self.pattern, "max_len": self.max_len}


def _same(a: Any, b: Any) -> bool:
    """值等价判定：bool 与 int 严格区分（True 不等于 1），避免值域被悄悄放宽。"""
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    return a == b


def _max_opt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _min_opt(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


# 布尔域：业务里的开关型参数（is_admin / verified / enabled）。
# 注意必须定义在 _same 之后——EnumDomain.__post_init__ 会在构造期调用它。
BOOL_DOMAIN = EnumDomain((False, True))


def domain_from_dict(d: Dict[str, Any]) -> Domain:
    """从 IR 的 `domain` 字段还原值域（容错：非法输入退化为"无界"而非抛错）。"""
    if not isinstance(d, dict):
        return IntInterval()
    kind = str(d.get("kind") or "").lower()
    try:
        if kind == "int":
            return IntInterval(d.get("lo"), d.get("hi"))
        if kind == "float":
            return FloatInterval(d.get("lo"), d.get("hi"))
        if kind == "enum":
            vals = d.get("values") or []
            return EnumDomain(tuple(vals)) if isinstance(vals, (list, tuple)) else EnumDomain()
        if kind == "str":
            return StrDomain(d.get("pattern"), d.get("max_len"))
    except (TypeError, ValueError):
        return IntInterval()
    return IntInterval()


# ============================================================
# 符号变量
# ============================================================
@dataclass(frozen=True)
class Sym:
    """符号变量：一个待求解的输入（业务参数 / 状态字段）。"""

    name: str
    domain: Domain = field(default_factory=IntInterval)
    role: str = "input"          # input | derived
    note: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "role": self.role,
                "domain": self.domain.to_dict(), "note": self.note}


# ============================================================
# 线性表达式（整数系数；业务不变量几乎都是线性形态）
# ============================================================
@dataclass(frozen=True)
class LinExpr:
    """线性表达式 Σ c_i·x_i + k。构造时归一化（去零系数 + 变量名排序）→ 可复现。"""

    coeffs: Tuple[Tuple[str, int], ...] = ()
    const: int = 0

    def __post_init__(self):
        norm = tuple(sorted((str(k), int(v)) for k, v in self.coeffs if int(v) != 0))
        object.__setattr__(self, "coeffs", norm)
        object.__setattr__(self, "const", int(self.const))

    # ---- 构造器
    @classmethod
    def var(cls, name: str) -> "LinExpr":
        return cls(((str(name), 1),), 0)

    @classmethod
    def of_const(cls, k: int) -> "LinExpr":
        return cls((), int(k))

    # ---- 运算
    def __add__(self, other) -> "LinExpr":
        o = other if isinstance(other, LinExpr) else LinExpr.of_const(int(other))
        acc: Dict[str, int] = dict(self.coeffs)
        for k, v in o.coeffs:
            acc[k] = acc.get(k, 0) + v
        return LinExpr(tuple(acc.items()), self.const + o.const)

    def __sub__(self, other) -> "LinExpr":
        o = other if isinstance(other, LinExpr) else LinExpr.of_const(int(other))
        return self.__add__(o.__neg__())

    def __neg__(self) -> "LinExpr":
        return LinExpr(tuple((k, -v) for k, v in self.coeffs), -self.const)

    def __mul__(self, k: int) -> "LinExpr":
        return LinExpr(tuple((n, c * int(k)) for n, c in self.coeffs), self.const * int(k))

    __rmul__ = __mul__

    # ---- 查询
    def vars(self) -> frozenset:
        return frozenset(k for k, _ in self.coeffs)

    def is_const(self) -> bool:
        return not self.coeffs

    def eval(self, assignment: Dict[str, int]) -> int:
        """在给定赋值下求值；缺省变量按 0 计（fail-closed：宁可判错也不抛错）。"""
        total = self.const
        for k, c in self.coeffs:
            v = assignment.get(k, 0)
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                return 0  # 非数值参与线性表达式 → 视为 0（该约束交给 eval 侧判定）
            total += c * v
        return int(total)

    def to_dict(self) -> Dict[str, Any]:
        return {"coeffs": {k: v for k, v in self.coeffs}, "const": self.const}

    def __str__(self) -> str:
        parts = [f"{c}*{k}" for k, c in self.coeffs]
        if self.const or not parts:
            parts.append(str(self.const))
        return " + ".join(parts)


def _as_expr(x) -> LinExpr:
    return x if isinstance(x, LinExpr) else LinExpr.of_const(int(x))


# ============================================================
# 约束
# ============================================================
class Constraint:
    """约束基类。eval() 必须是纯函数；vars() 返回涉及的符号名。"""

    op: str = "?"

    def eval(self, assignment: Dict[str, Any]) -> bool:  # pragma: no cover - 抽象
        raise NotImplementedError

    def vars(self) -> frozenset:  # pragma: no cover - 抽象
        return frozenset()

    def to_dict(self) -> Dict[str, Any]:  # pragma: no cover - 抽象
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - 调试
        return f"<{self.op} {self.to_dict()}>"


@dataclass(frozen=True)
class LinCmp(Constraint):
    """线性比较：把 sense 归一到 `expr <= 0 / < 0 / == 0 / != 0`，便于统一传播。"""

    expr: LinExpr
    sense: str = "le"          # le | lt | eq | ne
    op: str = "lincmp"

    def __post_init__(self):
        if not isinstance(self.expr, LinExpr):
            object.__setattr__(self, "expr", _as_expr(self.expr))
        if self.sense not in ("le", "lt", "eq", "ne"):
            object.__setattr__(self, "sense", "le")

    # ---- 便捷构造（语义读起来贴近业务：price*qty >= total 之类）
    @classmethod
    def le(cls, expr) -> "LinCmp":
        return cls(_as_expr(expr), "le")

    @classmethod
    def lt(cls, expr) -> "LinCmp":
        return cls(_as_expr(expr), "lt")

    @classmethod
    def eq(cls, expr) -> "LinCmp":
        return cls(_as_expr(expr), "eq")

    @classmethod
    def ne(cls, expr) -> "LinCmp":
        return cls(_as_expr(expr), "ne")

    @classmethod
    def ge(cls, expr) -> "LinCmp":
        return cls(-_as_expr(expr), "le")

    @classmethod
    def gt(cls, expr) -> "LinCmp":
        return cls(-_as_expr(expr), "lt")

    def eval(self, assignment: Dict[str, Any]) -> bool:
        v = self.expr.eval(assignment)
        if self.sense == "le":
            return v <= 0
        if self.sense == "lt":
            return v < 0
        if self.sense == "eq":
            return v == 0
        return v != 0

    def vars(self) -> frozenset:
        return self.expr.vars()

    def to_dict(self) -> Dict[str, Any]:
        return {"op": "lin", "sense": self.sense, "expr": self.expr.to_dict()}


@dataclass(frozen=True)
class SetIn(Constraint):
    """集合成员约束：变量取值必须落在给定集合内（枚举/白名单场景）。"""

    var: str
    values: Tuple[Any, ...] = ()
    op: str = "setin"

    def __post_init__(self):
        if not isinstance(self.values, tuple):
            object.__setattr__(self, "values", tuple(self.values or ()))

    def eval(self, assignment: Dict[str, Any]) -> bool:
        if self.var not in assignment:
            return False
        return any(_same(assignment[self.var], v) for v in self.values)

    def vars(self) -> frozenset:
        return frozenset((self.var,))

    def to_dict(self) -> Dict[str, Any]:
        return {"op": "in", "var": self.var, "values": list(self.values)}


@dataclass
class ConstraintSet:
    """约束集合（可迭代 + 可增量添加；顺序稳定 → 传播结果可复现）。"""

    items: List[Constraint] = field(default_factory=list)

    def add(self, c: Constraint) -> "ConstraintSet":
        if isinstance(c, Constraint):
            self.items.append(c)
        return self

    def extend(self, cs: Iterable[Constraint]) -> "ConstraintSet":
        for c in cs or ():
            self.add(c)
        return self

    def vars(self) -> frozenset:
        acc = set()
        for c in self.items:
            acc |= set(c.vars())
        return frozenset(acc)

    def eval(self, assignment: Dict[str, Any]) -> bool:
        return all(c.eval(assignment) for c in self.items)

    def to_dict(self) -> Dict[str, Any]:
        return {"constraints": [c.to_dict() for c in self.items]}

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self):
        return iter(self.items)
