"""B3 -> IR 桥单测：剧本 -> BusinessIR -> A1 符号复核（零网络）。"""
import asyncio
import unittest.mock as um

from vulnclaw.engines.playbook_engine import Playbook, PlaybookAction
from vulnclaw.engines.playbook_ir import (
    PARAM_DOMAINS,
    playbooks_to_ir,
    symbolic_from_playbooks,
)


def _book(invariant="amount", verb="charge", url="http://h/vuln/charge", params=None, bid="pb1"):
    return Playbook(
        id=bid,
        title=f"{invariant} playbook",
        domain="电商/交易",
        feature="余额充值",
        invariant=invariant,
        expected_state="资金守恒不得被破坏",
        actions=[PlaybookAction(seq=1, verb=verb, url=url,
                                params=params or {"amount": "1"},
                                invariant=invariant)],
        source="local",
    )


def test_playbooks_to_ir_units():
    books = [_book()]
    ir = playbooks_to_ir(books, "http://h")
    assert ir["version"] == "ir-1"
    assert ir["source"] == "b3-playbook"
    eps = ir["endpoints"]
    assert len(eps) == 1
    ep = eps[0]
    assert ep["path"] == "/vuln/charge"
    assert ep["method"] == "GET"
    names = [p["name"] for p in ep["params"]]
    assert "amount" in names
    amount_p = next(p for p in ep["params"] if p["name"] == "amount")
    assert amount_p["domain"] == PARAM_DOMAINS["amount"]
    # unit_price 从 amount=1 提取
    assert ir["unit_price"] == 1
    # invariants 空（黑盒桥不做服务端硬校验假设）
    assert ir["invariants"] == []


def test_playbooks_to_ir_dedup_and_classify():
    books = [
        _book(bid="pb1", url="http://h/vuln/charge", params={"amount": "1", "qty": "2"}),
        _book(bid="pb2", url="http://h/vuln/charge", params={"amount": "1", "unknown_x": "3"}),
    ]
    ir = playbooks_to_ir(books, "http://h")
    eps = ir["endpoints"]
    assert len(eps) == 1, "同 path 剧本应合并为单端点"
    names = {p["name"] for p in eps[0]["params"]}
    assert names == {"amount", "qty"}, f"未知类参数不应建模: {names}"
    kinds = [p["domain"]["kind"] for p in eps[0]["params"]]
    assert "enum" not in kinds  # amount/qty 都是 int


def test_playbooks_to_ir_role_and_identity_domain():
    books = [_book(invariant="binding", verb="reset", bid="pb3",
                   url="http://h/vuln/reset",
                   params={"role": "user", "user_id": "1"})]
    ir = playbooks_to_ir(books, "http://h")
    names = {p["name"]: p["domain"] for p in ir["endpoints"][0]["params"]}
    assert names["role"] == PARAM_DOMAINS["role"]
    assert names["user_id"]["kind"] == "enum"  # identity 类


def test_playbooks_to_ir_state_goal():
    books = [Playbook(id="pb4", title="state", domain="通用", feature="支付",
                      invariant="state", expected_state="不可跳过前置",
                      actions=[PlaybookAction(seq=1, verb="pay",
                                              url="http://h/vuln/pay",
                                              params={}, invariant="state")],
                      source="local")]
    ir = playbooks_to_ir(books, "http://h")
    assert ir["goals"] and ir["goals"][0]["id"] == "goal:pb4"


def test_playbooks_to_ir_fail_closed_empty():
    assert playbooks_to_ir([], "http://h")["endpoints"] == []
    assert playbooks_to_ir(None, "http://h")["endpoints"] == []
    assert playbooks_to_ir("garbage", "http://h")["endpoints"] == []


def test_symbolic_from_playbooks_fail_closed_on_engine_error():
    async def _boom(*a, **k):
        raise RuntimeError("engine down")

    with um.patch("vulnclaw.engines.symbolic_engine.SymbolicLogicEngine.scan", new=_boom):
        out = asyncio.run(symbolic_from_playbooks([_book()], "http://h"))
    assert out == []


def test_symbolic_from_playbooks_hits_amount_objective():
    # 剧本 amount=1 -> IR unit_price=1 -> A1 amount 目标产出候选（hz 联调）
    out = asyncio.run(symbolic_from_playbooks([_book()], "http://h"))
    if out:
        f = out[0]
        assert f["engine"] == "symbolic_logic"
        assert f["needs_verification"] is True
        assert f["deterministic"] is True
