# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A1 状态机 + 路径探索器回归测试（hermetic：零网络、零 LLM、纯确定性）。"""
import pytest

from vulnclaw.engines.symbolic import IntInterval, LinCmp, LinExpr, Sym
from vulnclaw.engines.symbolic.executor import (
    ExplorationResult,
    Path,
    best_path,
    explore,
    render_plan,
)
from vulnclaw.engines.symbolic.state import (
    AppState,
    StateMachine,
    Transition,
    build_machine,
)


# ============================================================
# 状态
# ============================================================
def test_appstate_facts_and_immutability():
    s0 = AppState(frozenset({"session=1"}))
    s1 = s0.apply(Transition(id="t", produces=("cart=1",), consumes=("session=1",)))
    assert s0.facts == frozenset({"session=1"})        # 原状态不变（回滚 = 留旧引用）
    assert s1.facts == frozenset({"cart=1"})
    assert s1.trace == ("t",)
    assert s0.snapshot() is s0                          # 不可变 → 快照即自身
    assert s1.has("cart=1") and not s1.satisfies(("session=1",))


def test_appstate_key_dedup_and_dict():
    a = AppState(frozenset({"b", "a"}))
    b = AppState(frozenset({"a", "b"}), trace=("x",))
    assert a.key() == b.key() == ("a", "b")            # 事实相同即同一状态（轨迹不参与）
    assert a.with_facts("c").facts == frozenset({"a", "b", "c"})
    assert a.without_facts("a").facts == frozenset({"b"})
    assert a.to_dict()["facts"] == ["a", "b"]


def test_transition_applicable():
    t = Transition(id="t", requires_facts=("session=1",))
    assert t.applicable({"session=1", "x"})
    assert not t.applicable({"x"})


# ============================================================
# 状态机
# ============================================================
def _machine(**kw):
    """t1 登录 → t4 提权（带符号前置）→ t3 访问管理页；t2 是写操作。"""
    t1 = Transition(id="t1", method="POST", path="/login", produces=("session=1",))
    t4 = Transition(id="t4", method="POST", path="/role", requires_facts=("session=1",),
                    produces=("role=admin",),
                    preconditions=(LinCmp.ge(LinExpr.var("role") - 1),))
    t3 = Transition(id="t3", method="GET", path="/admin", requires_facts=("role=admin",),
                    produces=("admin=1",))
    t2 = Transition(id="t2", method="POST", path="/order", requires_facts=("session=1",),
                    produces=("order=42",), side_effect=True)
    return StateMachine((t1, t2, t3, t4), frozenset())


def test_machine_sorted_and_get():
    m = _machine()
    assert [t.id for t in m.transitions] == ["t1", "t2", "t3", "t4"]
    assert m.get("t3").path == "/admin"
    assert m.get("nope") is None


def test_machine_applicable_gates():
    m = _machine()
    s0 = m.initial_state()
    ids = [t.id for t, _ in m.applicable(s0)]
    assert "t1" in ids
    assert "t4" not in ids                      # 缺 session=1（硬前置）
    assert "t2" not in ids                      # 写操作默认不规划
    s1 = s0.apply(m.get("t1"))                  # 登录后才具备 session=1
    assert "t2" not in [t.id for t, _ in m.applicable(s1)]              # 仍被写闸挡住
    assert "t2" in [t.id for t, _ in m.applicable(s1, allow_side_effect=True)]


def test_machine_precondition_unsat_prunes_edge():
    """服务端校验存在（符号前置不可满足）→ 该转移被剪掉：这是 A1 不误报的依据。"""
    m = _machine()
    s1 = m.initial_state().apply(m.get("t1"))
    # role 域为 {0} → 提权前置 role>=1 不可满足
    blocked = [t.id for t, _ in m.applicable(s1, [Sym("role", IntInterval(0, 0))])]
    assert "t4" not in blocked
    ok = [t.id for t, _ in m.applicable(s1, [Sym("role", IntInterval(0, 1))])]
    assert "t4" in ok


def test_machine_apply_by_id():
    m = _machine()
    s0 = m.initial_state()
    s1 = m.apply(s0, "t1")
    assert s1 is not None and s1.has("session=1")
    assert m.apply(s0, "t4") is None            # 前置不成立
    assert m.apply(s0, "ghost") is None


def test_build_machine_from_ir_like():
    ir = {
        "endpoints": [
            {"id": "e1", "method": "get", "path": "/me",
             "auth": {"required": True, "role": "user"}, "effects": [{"entity": "user", "op": "read"}]},
            {"id": "e2", "method": "post", "path": "/order", "effects": [{"entity": "order", "op": "write"}]},
        ],
        "transitions": [{"via_endpoint": "e2", "from_state": "cart", "to_state": "paid"}],
    }
    m = build_machine(ir)
    assert [t.id for t in m.transitions] == ["ep:e1", "ep:e2"]
    assert m.get("ep:e1").requires_facts == ("role=user",)
    assert m.get("ep:e1").produces == ("read:user",)
    assert m.get("ep:e2").side_effect is True    # transitions.via_endpoint 标记为写
    assert build_machine(None).transitions == ()  # 容错


# ============================================================
# 探索
# ============================================================
GOAL = ("admin_access", ("admin=1",))


def test_explore_finds_chain_and_witness():
    m = _machine()
    r = explore(m, [GOAL], [Sym("role", IntInterval(0, 1))])
    p = best_path(r)
    assert p is not None
    assert p.transitions == ("t1", "t4", "t3")
    assert p.goal == "admin_access"
    assert len(p.witnesses) == 3
    assert not r.truncated


def test_explore_blocks_when_server_validates():
    """role 域被服务端钉死为 {0} → 提权不可行 → 目标不可达（不产出）。"""
    m = _machine()
    r = explore(m, [GOAL], [Sym("role", IntInterval(0, 0))])
    assert r.paths == []
    assert not r.truncated


def test_explore_is_deterministic():
    m = _machine()
    a = explore(m, [GOAL], [Sym("role", IntInterval(0, 1))]).to_dict()
    for _ in range(3):
        assert explore(m, [GOAL], [Sym("role", IntInterval(0, 1))]).to_dict() == a


def test_explore_respects_max_depth():
    m = _machine()
    r = explore(m, [GOAL], [Sym("role", IntInterval(0, 1))], max_depth=2)
    assert r.paths == []


def test_explore_respects_max_states_truncation_flag():
    m = _machine()
    r = explore(m, [GOAL], [Sym("role", IntInterval(0, 1))], max_states=1)
    assert r.truncated is True
    assert "预算" in r.reason


def test_explore_state_dedup_keeps_visited_bounded():
    """两条转移产生同一事实集 → 状态只展开一次（不爆炸）。"""
    t1 = Transition(id="a1", produces=("x=1",))
    t2 = Transition(id="a2", produces=("x=1",))
    t3 = Transition(id="a3", requires_facts=("x=1",), produces=("done=1",))
    m = StateMachine((t1, t2, t3), frozenset())
    r = explore(m, [("g", ("done=1",))])
    assert r.paths and r.paths[0].transitions[-1] == "a3"
    assert r.visited <= 5                      # 去重生效：状态数远小于路径数


def test_explore_unreachable_goal():
    m = StateMachine((Transition(id="a", produces=("x=1",)),), frozenset())
    r = explore(m, [("never", ("z=1",))])
    assert r.paths == [] and r.truncated is False


def test_explore_fail_closed_on_garbage():
    assert explore(None, [GOAL]).paths == []              # type: ignore[arg-type]
    m = _machine()
    assert explore(m, None, None).paths == [] or explore(m, [], []).paths == []
    r = explore(m, [("bad",)], [Sym("role", IntInterval(0, 1))])   # 目标格式非法 → 忽略
    assert isinstance(r, ExplorationResult)


def test_render_plan_orders_steps_without_network():
    m = _machine()
    p = best_path(explore(m, [GOAL], [Sym("role", IntInterval(0, 1))]))
    plan = render_plan(m, p)
    assert [s["step"] for s in plan] == [1, 2, 3]
    assert plan[0]["path"] == "/login" and plan[2]["path"] == "/admin"
    assert plan[2]["requires_facts"] == ["role=admin"]
    assert plan[0]["witness"] == {}
    assert all("side_effect" in s for s in plan)
    assert render_plan(m, None) == [] and render_plan(None, p) == []   # type: ignore[arg-type]


def test_best_path_none_when_empty():
    assert best_path(ExplorationResult()) is None
    assert best_path(None) is None                     # type: ignore[arg-type]
    assert isinstance(Path().to_dict(), dict)
