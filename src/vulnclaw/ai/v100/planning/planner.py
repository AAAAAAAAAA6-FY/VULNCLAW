# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/planning/planner.py
"""攻击链规划器 —— 目标导向的**后向搜索**（与 A1 的前向状态探索互补）。

为什么不复用 A1 的 forward BFS
-------------------------------
A1 在"应用状态机"上前向探索，回答"从这个状态能走到哪"；A3 回答的是相反的问题：
"要拿到 admin 面板（目标事实），**最少需要哪几步、顺序如何**"。后向搜索天然是
目标导向的：从目标事实反推需要哪些前缀事实，递归到已知事实为止。

纪律
----
* **确定性**：事实与能力都排序后遍历 → 同输入同输出；有环即剪（不重复展开同一需求集）。
* **不可行必须说清楚**：规划不出时返回 `feasible=False` + `blocked_reason`（列出无从获得的事实），
  **绝不硬编造步骤**——这跟 A1 的"不可满足就不产出"是同一条红线。
* 写动作默认不参与规划（`allow_side_effect=False`）。
"""
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Sequence, Tuple

from .capabilities import Capability, build_capabilities, produce_index, read_capabilities

__all__ = [
    "ChainStep",
    "AttackChain",
    "plan_goal",
    "plan_chains",
    "blocking_facts",
]


@dataclass(frozen=True)
class ChainStep:
    """链上一步（由 Capability 投影而来，便于序列化与验证）。"""

    capability_id: str
    requires: Tuple[str, ...] = ()
    produces: Tuple[str, ...] = ()
    cost: float = 1.0
    side_effect: bool = False
    method: str = ""
    path: str = ""
    kind: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "capability": self.capability_id, "kind": self.kind,
            "requires": list(self.requires), "produces": list(self.produces),
            "cost": self.cost, "side_effect": self.side_effect,
            "method": self.method, "path": self.path,
        }


@dataclass
class AttackChain:
    """一条攻击链。`feasible=False` 时 `blocked_reason` 必须说明卡在哪。"""

    id: str
    goal: str
    goal_facts: Tuple[str, ...] = ()
    steps: List[ChainStep] = field(default_factory=list)
    feasible: bool = False
    score: float = 0.0
    cost: float = 0.0
    executed: bool = False
    verify: Dict[str, Any] = field(default_factory=dict)
    blocked_reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "goal": self.goal, "goal_facts": list(self.goal_facts),
            "steps": [s.to_dict() for s in self.steps],
            "feasible": self.feasible, "score": self.score, "cost": self.cost,
            "executed": self.executed, "verify": self.verify,
            "blocked_reason": self.blocked_reason,
        }


def _backward(need: FrozenSet[str], initial: FrozenSet[str],
              prod_idx: Dict[str, List[Capability]], depth: int,
              allow_side_effect: bool, memo: Dict[Any, Optional[List[Capability]]]
              ) -> Optional[List[Capability]]:
    """后向递归：把 need 归约到 initial 可达，返回**按执行顺序**排列的动作列表。

    memo 既做记忆化也做**防环占位**（先置 None，成功再覆盖）——避免相互依赖的事实死循环。
    """
    if not (need - initial):
        return []
    if depth <= 0:
        return None
    key = (need, depth)
    if key in memo:
        return memo[key]
    memo[key] = None

    missing = sorted(need - initial)
    target = missing[0]                      # 确定性：总是先攻克字典序最小的事实
    for cap in prod_idx.get(target, []):
        if cap.side_effect and not allow_side_effect:
            continue
        sub_need = (need - {target}) | frozenset(cap.requires)
        sub = _backward(frozenset(sub_need), initial, prod_idx, depth - 1,
                        allow_side_effect, memo)
        if sub is not None:
            plan = sub + [cap]               # 依赖先执行，本步在后
            memo[key] = plan
            return plan
    return None


def blocking_facts(need: Sequence[str], initial: Sequence[str],
                   caps: Sequence[Capability], *, allow_side_effect: bool = False,
                   limit: int = 6) -> List[str]:
    """哪些目标事实在给定动作集下**根本无从获得**（用于给出不可行原因）。"""
    reachable = set(initial or ())
    usable = [c for c in (caps or ())
              if isinstance(c, Capability) and (allow_side_effect or not c.side_effect)]
    changed = True
    while changed:                            # 事实可达闭包（不动点）
        changed = False
        for c in usable:
            if all(f in reachable for f in c.requires):
                for f in c.produces:
                    if f not in reachable:
                        reachable.add(f)
                        changed = True
    return sorted(set(need or ()) - reachable)[: max(1, int(limit))]


def _to_steps(caps: Sequence[Capability]) -> List[ChainStep]:
    return [ChainStep(capability_id=c.id, requires=c.requires, produces=c.produces,
                      cost=float(c.cost), side_effect=bool(c.side_effect),
                      method=c.method, path=c.path, kind=c.kind) for c in caps]


def plan_goal(goal_id: str, goal_facts: Sequence[str],
              caps: Sequence[Capability], initial_facts: Sequence[str] = (),
              *, allow_side_effect: bool = False, max_depth: int = 8) -> AttackChain:
    """为单个目标规划一条链（不可行时返回带 `blocked_reason` 的 `feasible=False`）。"""
    gid = str(goal_id or "goal")
    gfacts = tuple(sorted({str(f) for f in (goal_facts or ()) if f}))
    chain = AttackChain(id=f"chain:{gid}", goal=gid, goal_facts=gfacts)

    if not gfacts:
        chain.blocked_reason = "目标未声明任何事实（requires_facts 为空）"
        return chain

    usable = read_capabilities(caps, allow_side_effect=allow_side_effect)
    idx = produce_index(usable)
    initial = frozenset(str(f) for f in (initial_facts or ()) if f)
    plan = _backward(frozenset(gfacts), initial, idx, max(1, int(max_depth)),
                     allow_side_effect, {})

    if plan is None:
        blockers = blocking_facts(gfacts, initial, usable,
                                  allow_side_effect=allow_side_effect)
        chain.blocked_reason = (
            f"无从获得的目标事实: {','.join(blockers)}" if blockers
            else f"深度 {max_depth} 内未找到可行组合（可能依赖互相前置）"
        )
        return chain

    chain.steps = _to_steps(plan)
    chain.feasible = True
    chain.cost = round(sum(float(c.cost) for c in plan), 6)
    chain.score = round(1.0 / (1.0 + chain.cost), 4)      # 代价越小分越高
    return chain


def plan_chains(ir: Optional[Dict[str, Any]] = None,
                findings: Optional[Sequence[Dict[str, Any]]] = None,
                goals: Optional[Sequence[Any]] = None,
                *, initial_facts: Sequence[str] = (),
                allow_side_effect: bool = False,
                max_chains: int = 5, max_depth: int = 8,
                capabilities: Optional[Sequence[Capability]] = None
                ) -> List[AttackChain]:
    """规划多条链：可行链按 (代价, id) 排序在前，不可行链（带原因）附在后面。

    goals 缺省取 `ir["goals"]`（每项需含 `id` 与 `requires_facts`）。
    """
    caps = list(capabilities) if capabilities is not None \
        else build_capabilities(ir, findings, allow_side_effect=allow_side_effect)

    glist: List[Tuple[str, Tuple[str, ...]]] = []
    src = goals if goals is not None else (ir or {}).get("goals") or []
    for g in (src or ()):
        if isinstance(g, dict) and g.get("id"):
            glist.append((str(g["id"]), tuple(g.get("requires_facts") or ())))
        elif isinstance(g, (tuple, list)) and len(g) == 2:
            glist.append((str(g[0]), tuple(g[1] or ())))
    glist.sort(key=lambda x: x[0])

    out: List[AttackChain] = []
    seen: set = set()
    for gid, gfacts in glist:
        ch = plan_goal(gid, gfacts, caps, initial_facts,
                       allow_side_effect=allow_side_effect, max_depth=max_depth)
        key = (ch.feasible, tuple(s.capability_id for s in ch.steps))
        if key in seen:
            continue
        seen.add(key)
        out.append(ch)

    feasible = sorted((c for c in out if c.feasible), key=lambda c: (c.cost, c.id))
    infeasible = sorted((c for c in out if not c.feasible), key=lambda c: c.id)
    limit = max(1, int(max_chains))
    return (feasible + infeasible)[:limit]
