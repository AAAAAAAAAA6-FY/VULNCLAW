# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/state.py
"""应用状态机 —— 把 Web 应用建模为「事实集合 + 转移」的可探索空间。

模型
----
* **事实（Fact）**：字符串谓词，如 `role=admin` / `owns:order:42` / `step=confirm`。
  用字符串而非对象：可哈希、可排序、可序列化 → 状态去重天然可靠、结果可复现。
* **转移（Transition）**：一次业务动作（通常对应一个端点 / 一次请求）：
    - `requires_facts` 硬前置事实（具体、可判定的门）
    - `preconditions`  符号约束（由 solver 判定可满足性 = **服务端校验是否存在**）
    - `produces` / `consumes`  对事实集合的增删
    - `side_effect`    写操作（默认**不真跑**，仅规划）
* **状态（AppState）**：**不可变**快照（frozenset 事实 + 轨迹）。`apply()` 派生新状态而
  不原地修改 → **回滚 = 持有旧快照**，无需 undo 逻辑。

确定性：事实集是 frozenset、转移按 id 排序、派生为纯函数 → 同输入同输出。
"""
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from .solver import solve
from .values import DEFAULT_WINDOW, Constraint, Sym

__all__ = ["Fact", "Transition", "AppState", "StateMachine"]

Fact = str


@dataclass(frozen=True)
class Transition:
    """一次业务动作（端点级）。字段全部可哈希 → 可复现。"""

    id: str
    endpoint_id: str = ""
    method: str = "GET"
    path: str = ""
    requires_facts: Tuple[str, ...] = ()
    preconditions: Tuple[Constraint, ...] = ()
    produces: Tuple[str, ...] = ()
    consumes: Tuple[str, ...] = ()
    side_effect: bool = False
    cost: float = 1.0
    note: str = ""

    def __post_init__(self):
        for attr in ("requires_facts", "preconditions", "produces", "consumes"):
            v = getattr(self, attr)
            if not isinstance(v, tuple):
                object.__setattr__(self, attr, tuple(v or ()))

    def applicable(self, facts: Iterable[str]) -> bool:
        """硬前置是否成立（纯集合判定，不涉及符号求解）。"""
        have = set(facts or ())
        return all(f in have for f in self.requires_facts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "endpoint_id": self.endpoint_id,
            "method": self.method, "path": self.path,
            "requires_facts": list(self.requires_facts),
            "preconditions": [c.to_dict() for c in self.preconditions],
            "produces": list(self.produces), "consumes": list(self.consumes),
            "side_effect": self.side_effect, "cost": self.cost, "note": self.note,
        }


@dataclass(frozen=True)
class AppState:
    """不可变应用状态：事实集合 + 已走轨迹。"""

    facts: FrozenSet[str] = field(default_factory=frozenset)
    trace: Tuple[str, ...] = ()

    def __contains__(self, fact: str) -> bool:
        return fact in self.facts

    def has(self, *facts: str) -> bool:
        return all(f in self.facts for f in facts)

    def satisfies(self, required: Iterable[str]) -> bool:
        req = tuple(required or ())
        return all(f in self.facts for f in req)

    def key(self) -> Tuple[str, ...]:
        """状态去重键：**只看事实**（轨迹不同但事实相同 = 同一状态，不重复展开）。"""
        return tuple(sorted(self.facts))

    def snapshot(self) -> "AppState":
        """本类不可变 → 快照即自身（回滚 = 保留旧引用，零成本）。"""
        return self

    def with_facts(self, *facts: str) -> "AppState":
        return AppState(self.facts | set(facts), self.trace)

    def without_facts(self, *facts: str) -> "AppState":
        return AppState(self.facts - set(facts), self.trace)

    def apply(self, t: Transition) -> "AppState":
        """施加一次转移 → 新状态（consumes 先扣、produces 后加）。"""
        if not isinstance(t, Transition):
            return self
        facts = (self.facts - set(t.consumes)) | set(t.produces)
        return AppState(frozenset(facts), self.trace + (t.id,))

    def to_dict(self) -> Dict[str, Any]:
        return {"facts": sorted(self.facts), "trace": list(self.trace)}


@dataclass
class StateMachine:
    """状态机：转移集合 + 初始事实。探索逻辑见 `executor.explore`。"""

    transitions: Tuple[Transition, ...] = ()
    initial_facts: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self):
        if not isinstance(self.transitions, tuple):
            self.transitions = tuple(self.transitions or ())
        # 按 id 排序 → 探索顺序确定（可复现的前提）
        self.transitions = tuple(sorted(self.transitions, key=lambda t: t.id))
        self._by_id = {t.id: t for t in self.transitions}

    def initial_state(self) -> AppState:
        return AppState(frozenset(self.initial_facts or frozenset()), ())

    def get(self, tid: str) -> Optional[Transition]:
        return getattr(self, "_by_id", {}).get(tid)

    def applicable(
        self,
        state: AppState,
        syms: Sequence[Sym] = (),
        *,
        allow_side_effect: bool = False,
        max_enum: int = 64,
        window: int = DEFAULT_WINDOW,
    ) -> List[Tuple[Transition, Dict[str, Any]]]:
        """当前状态下"真正走得通"的转移：硬前置成立 **且** 符号前置可满足。

        符号前置不可满足 = 服务端存在该校验 → 该转移被挡（这是 A1 判定"不可利用"的依据）。
        """
        out: List[Tuple[Transition, Dict[str, Any]]] = []
        for t in self.transitions:
            if t.side_effect and not allow_side_effect:
                continue
            if not t.applicable(state.facts):
                continue
            if t.preconditions:
                try:
                    witness = solve(syms, t.preconditions, max_enum=max_enum, window=window)
                except Exception:  # noqa: BLE001 - 求解异常按"走不通"处理
                    continue
                if witness is None:
                    continue
            else:
                witness = {}
            out.append((t, witness))
        return out

    def apply(
        self,
        state: AppState,
        tid: str,
        syms: Sequence[Sym] = (),
        *,
        allow_side_effect: bool = False,
        max_enum: int = 64,
        window: int = DEFAULT_WINDOW,
    ) -> Optional[AppState]:
        """按 id 施加一次转移；该转移当前走不通 → None。"""
        t = self.get(tid)
        if t is None:
            return None
        ok = self.applicable(state, syms, allow_side_effect=allow_side_effect,
                             max_enum=max_enum, window=window)
        if not any(x.id == tid for x, _ in ok):
            return None
        return state.apply(t)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "initial_facts": sorted(self.initial_facts or frozenset()),
            "transitions": [t.to_dict() for t in self.transitions],
        }


def build_machine(ir_like: Dict[str, Any], *, side_effect_ids: Sequence[str] = ()) -> StateMachine:
    """从 IR-like 字典构建状态机（容错：缺字段按空处理，绝不抛异常）。

    映射约定（A2 的 IR 字段先行）：
      endpoints[].id / method / path          → 转移主键与描述
      transitions[].from_state/to_state/...   → requires_facts / produces
      invariants[]                            → 由调用方另行并入 preconditions（见 detector）
    """
    if not isinstance(ir_like, dict):
        return StateMachine()
    trans: List[Transition] = []
    side = set(side_effect_ids or ())
    se: set = set()
    for t in (ir_like.get("transitions") or []):
        if isinstance(t, dict) and t.get("via_endpoint"):
            se.add(str(t.get("via_endpoint")))
    for ep in (ir_like.get("endpoints") or []):
        if not isinstance(ep, dict):
            continue
        eid = str(ep.get("id") or ep.get("path") or "")
        if not eid:
            continue
        auth = ep.get("auth") or {}
        requires = []
        if isinstance(auth, dict) and auth.get("required") and auth.get("role"):
            requires.append(f"role={auth.get('role')}")
        produces = []
        for eff in (ep.get("effects") or []):
            if isinstance(eff, dict) and eff.get("entity"):
                produces.append(f"{eff.get('op', 'write')}:{eff.get('entity')}")
        trans.append(Transition(
            id=f"ep:{eid}",
            endpoint_id=eid,
            method=str(ep.get("method") or "GET").upper(),
            path=str(ep.get("path") or ""),
            requires_facts=tuple(requires),
            produces=tuple(produces),
            side_effect=(eid in side) or (eid in se),
        ))
    return StateMachine(tuple(trans), frozenset())
