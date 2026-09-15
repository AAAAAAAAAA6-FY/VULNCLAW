# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/symbolic/executor.py
"""符号路径探索器 —— 在状态机上做目标导向的确定性搜索。

职责
----
* 从初始状态出发，只用**当前状态下真正走得通**的转移扩展搜索树。走不通有两种：
    ① 硬前置事实不成立（`requires_facts` 不在当前事实集里）；
    ② 符号前置不可满足 —— 即**服务端已存在该校验** → 该边天然被剪掉。
  ②正是 A1 的误报控制：靠"约束不可满足"证明攻击路径不存在，而不是靠启发式猜。
* 命中目标事实集 → 记录一条 `Path`（含每步见证赋值，可直接落成攻击载荷）。
* `allow_side_effect=False`（默认）只规划只读路径；写操作需显式开启（上层应交 danger_guard）。

纪律
----
* **确定性**：转移按 id 排序、BFS 层序、状态按事实集去重 → 同输入同输出。
* **有界**：`max_states` / `max_depth` / `max_paths` 三重预算，超限置 `truncated=True`
  并给出原因（fail-closed，绝不返回半成品路径当结论）。
* **零网络**：探索不发任何请求；`render_plan` 只产出步骤描述，是否真跑由上层决定。
"""
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .state import AppState, StateMachine, Transition
from .values import DEFAULT_WINDOW, Sym

__all__ = ["Goal", "Path", "ExplorationResult", "explore", "best_path", "render_plan"]


Goal = Tuple[str, Tuple[str, ...]]      # (目标 id, 必须成立的事实集)


@dataclass(frozen=True)
class Path:
    """一条从初始状态到目标的转移序列（含每步见证赋值）。"""

    transitions: Tuple[str, ...] = ()
    witnesses: Tuple[Tuple[Tuple[str, Any], ...], ...] = ()
    goal: str = ""
    cost: float = 0.0

    def steps(self) -> int:
        return len(self.transitions)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "transitions": list(self.transitions),
            "witnesses": [{k: v for k, v in w} for w in self.witnesses],
            "goal": self.goal, "cost": self.cost, "steps": self.steps(),
        }


@dataclass
class ExplorationResult:
    """探索结果。`truncated=True` 表示预算耗尽、结论**不完整**（不得当"不可达"用）。"""

    paths: List[Path] = field(default_factory=list)
    visited: int = 0
    truncated: bool = False
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"paths": [p.to_dict() for p in self.paths],
                "visited": self.visited, "truncated": self.truncated, "reason": self.reason}


def _freeze(w: Dict[str, Any]) -> Tuple[Tuple[str, Any], ...]:
    """见证赋值 → 可哈希、可排序的元组（保证 Path 可比较、可复现）。"""
    out: List[Tuple[str, Any]] = []
    for k in sorted((w or {}).keys()):
        v = (w or {})[k]
        if v is None or isinstance(v, (str, int, float, bool)):
            out.append((str(k), v))
        else:
            out.append((str(k), str(v)))
    return tuple(out)


def explore(
    machine: StateMachine,
    goals: Sequence[Goal],
    syms: Sequence[Sym] = (),
    *,
    max_states: int = 2000,
    max_depth: int = 12,
    max_paths: int = 8,
    allow_side_effect: bool = False,
    max_enum: int = 64,
    window: int = DEFAULT_WINDOW,
) -> ExplorationResult:
    """目标导向的 BFS 探索。返回按 (代价, 步数, 目标 id) 排序的路径列表。"""
    if not isinstance(machine, StateMachine):
        return ExplorationResult([], 0, False, "非法状态机")

    glist: List[Goal] = []
    for g in (goals or ()):
        if isinstance(g, (tuple, list)) and len(g) == 2:
            glist.append((str(g[0]), tuple(g[1] or ())))
    glist.sort(key=lambda g: g[0])

    start = machine.initial_state()
    frontier = deque([(start, ())])          # (state, steps)；steps=((tid, witness, cost),...)
    seen = {start.key()}
    visited = 0
    truncated = False
    reason = ""
    found: List[Path] = []
    max_states = max(1, int(max_states))
    max_depth = max(0, int(max_depth))
    max_paths = max(1, int(max_paths))

    while frontier:
        state, steps = frontier.popleft()
        visited += 1
        if visited > max_states:
            truncated, reason = True, f"状态预算耗尽({max_states})"
            break

        for gid, req in glist:
            if state.satisfies(req):
                cand = Path(tuple(s[0] for s in steps),
                            tuple(s[1] for s in steps),
                            gid, round(sum(s[2] for s in steps), 6))
                if cand not in found:
                    found.append(cand)

        if len(steps) >= max_depth:
            continue

        for t, witness in machine.applicable(
                state, syms, allow_side_effect=allow_side_effect,
                max_enum=max_enum, window=window):
            nxt = state.apply(t)
            key = nxt.key()
            if key in seen:
                continue
            seen.add(key)
            frontier.append((nxt, steps + ((t.id, _freeze(witness), float(t.cost)),)))

        if len(found) >= max_paths:
            break

    if not found and frontier and not truncated:
        reason = reason or "预算内未找到可达目标"
    found.sort(key=lambda p: (p.cost, p.steps(), p.goal, p.transitions))
    return ExplorationResult(found[:max_paths], visited, truncated, reason)


def best_path(result: ExplorationResult) -> Optional[Path]:
    """代价最小的一条路径（结果已排序，取首条）；无解 → None。"""
    if not isinstance(result, ExplorationResult) or not result.paths:
        return None
    return result.paths[0]


def render_plan(machine: StateMachine, path: Path) -> List[Dict[str, Any]]:
    """把路径渲染成"可执行步骤描述"（含方法与见证），**不发请求**。

    上层据此决定：只读步骤可直接跑；`side_effect=True` 的步骤必须过 danger_guard 与授权。
    """
    if not isinstance(machine, StateMachine) or not isinstance(path, Path):
        return []
    out: List[Dict[str, Any]] = []
    for i, tid in enumerate(path.transitions):
        t: Optional[Transition] = machine.get(tid)
        witness = dict(path.witnesses[i]) if i < len(path.witnesses) else {}
        out.append({
            "step": i + 1,
            "transition": tid,
            "endpoint_id": t.endpoint_id if t else "",
            "method": t.method if t else "GET",
            "path": t.path if t else "",
            "requires_facts": list(t.requires_facts) if t else [],
            "produces": list(t.produces) if t else [],
            "side_effect": bool(t.side_effect) if t else False,
            "witness": witness,
            "cost": float(t.cost) if t else 0.0,
        })
    return out
