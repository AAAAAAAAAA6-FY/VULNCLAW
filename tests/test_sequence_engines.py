# -*- coding: utf-8 -*-
"""SequenceChainEngine 专项测试：并发竞态 + 多步序列 + fail-closed 边界。

全部用注入的 requester 模拟响应，不发真实网络请求。
"""
import pytest

from vulnclaw.config.settings import settings
from vulnclaw.engines.sequence_engines import (
    SequenceChainEngine,
    default_biz_oracle,
    extract_biz_identifiers,
)


@pytest.fixture(autouse=True)
def _sequence_enabled(monkeypatch):
    """引擎总开关默认关闭（竞态有业务副作用），测试内显式开启。"""
    monkeypatch.setattr(settings, "sequence_chain_enabled", True, raising=False)


def _requester(responses):
    """按调用顺序返回 responses，超出则重复最后一项。"""
    state = {"n": 0}

    async def _req(url, **kwargs):
        i = state["n"]
        state["n"] += 1
        return responses[i] if i < len(responses) else responses[-1]

    return _req


# ---------------------------------------------------------------- 竞态
@pytest.mark.asyncio
async def test_race_reports_duplicate_success_with_distinct_ids():
    """并发多次成功且产出不同订单号 → 强证据竞态（high）。"""
    eng = SequenceChainEngine()
    req = _requester([
        (200, '{"success": true, "order_id": "ORD100001"}', {}),
        (200, '{"success": true, "order_id": "ORD100002"}', {}),
        (200, '{"success": true, "order_id": "ORD100003"}', {}),
        (200, '{"success": true, "order_id": "ORD100004"}', {}),
    ])
    f = await eng.detect_race(
        "https://x.test/coupon/claim", method="POST", concurrency=4, requester=req
    )
    assert f is not None
    assert f["type"] == "race_condition"
    assert f["severity"] == "high"
    assert f["race_success_count"] == 4
    assert len(f["race_identifiers"]) >= 2


@pytest.mark.asyncio
async def test_race_preflight_zero_concurrency_when_idempotent():
    """串行预检发现基础防重（第二次被拒）→ 零并发、不产出、不重复提交。"""
    eng = SequenceChainEngine()
    calls = {"n": 0}

    async def _req(url, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            return (200, '{"success": true, "order_id": "ORD210001"}', {})
        return (200, '{"error": "already claimed"}', {})

    f = await eng.detect_race(
        "https://x.test/coupon/claim", method="POST", concurrency=8, requester=_req
    )
    assert f is None
    assert calls["n"] == 2  # 预检 2 次即停，完全没进入并发


@pytest.mark.asyncio
async def test_race_fail_closed_when_only_one_concurrent_success():
    """预检通过（疑似无防重）但并发里只有 1 次成功 → 不产出。"""
    eng = SequenceChainEngine()
    req = _requester([
        (200, '{"success": true, "order_id": "ORD200001"}', {}),  # 预检1
        (200, '{"success": true, "order_id": "ORD200002"}', {}),  # 预检2 成功 -> 进入并发
        (200, '{"success": true, "order_id": "ORD200003"}', {}),  # 并发 唯一一次成功
        (200, '{"error": "already claimed"}', {}),
        (200, '{"error": "already claimed"}', {}),
    ])
    f = await eng.detect_race(
        "https://x.test/coupon/claim", method="POST", concurrency=3, requester=req
    )
    assert f is None


@pytest.mark.asyncio
async def test_race_fail_closed_on_server_errors():
    """5xx/429 不算业务成功 → 不产出。"""
    eng = SequenceChainEngine()
    req = _requester([(500, "internal error", {}), (429, "too many requests", {})])
    f = await eng.detect_race(
        "https://x.test/coupon/claim", method="POST", concurrency=4, requester=req
    )
    assert f is None


@pytest.mark.asyncio
async def test_race_skips_get_unless_explicitly_allowed():
    """GET 默认跳过；allow_get=True 才跑。"""
    eng = SequenceChainEngine()
    req = _requester([(200, '{"success": true, "order_id": "ORD300001"}', {})] * 4)

    assert await eng.detect_race(
        "https://x.test/query", method="GET", concurrency=4, requester=req
    ) is None

    req2 = _requester([
        (200, '{"success": true, "order_id": "ORD300002"}', {}),
        (200, '{"success": true, "order_id": "ORD300003"}', {}),
    ])
    f = await eng.detect_race(
        "https://x.test/query", method="GET", concurrency=2, requester=req2, allow_get=True
    )
    assert f is not None


# ---------------------------------------------------------------- 多步序列
@pytest.mark.asyncio
async def test_sequence_passes_variable_between_steps():
    """第一步提取 token，第二步 URL 中的 {{token}} 被替换 → 链可达。"""
    eng = SequenceChainEngine()
    seen = []

    async def _req(url, **kwargs):
        seen.append(url)
        if "confirm" in url:
            assert "token=RESETABC123" in url  # 变量已注入
            return (200, '{"success": true, "order_id": "ORD400001"}', {})
        return (200, "reset page token=RESETABC123", {})

    f = await eng.run_sequence(
        steps=[
            {"url": "https://x.test/reset", "method": "GET",
             "extract": {"token": r"token=([A-Za-z0-9]{6,})"}},
            {"url": "https://x.test/reset/confirm?token={{token}}", "method": "GET"},
        ],
        requester=_req,
    )
    assert f is not None
    assert f["type"] == "sequence_chain"
    assert f["sequence_steps"] == 2
    assert f["sequence_variables"]["token"] == "RESETABC123"
    assert len(seen) == 2


@pytest.mark.asyncio
async def test_sequence_fail_closed_when_final_oracle_rejects():
    """末步不满足业务成功判据 → 不产出。"""
    eng = SequenceChainEngine()
    req = _requester([(200, "token=RESETABC123", {}), (200, '{"error": "invalid token"}', {})])
    f = await eng.run_sequence(
        steps=[
            {"url": "https://x.test/reset", "method": "GET",
             "extract": {"token": r"token=([A-Za-z0-9]{6,})"}},
            {"url": "https://x.test/reset/confirm?token={{token}}", "method": "GET"},
        ],
        requester=req,
    )
    assert f is None


@pytest.mark.asyncio
async def test_sequence_fail_closed_on_bad_url():
    """步骤 URL 非法（无 scheme）→ 不产出、不请求。"""
    eng = SequenceChainEngine()
    req = _requester([(200, "success", {})])
    f = await eng.run_sequence(steps=[{"url": "/relative/path"}], requester=req)
    assert f is None


# ---------------------------------------------------------------- 通用入口与工具
@pytest.mark.asyncio
async def test_check_is_noop_outside_orchestration():
    """不进通用参数级调度池：check() 恒 None。"""
    eng = SequenceChainEngine()
    assert await eng.check("https://x.test/a", "id", (200, "x", {}), "", None) is None


def test_default_oracle_rules():
    assert default_biz_oracle(200, '{"success": true}') is True
    assert default_biz_oracle(200, '{"error": "boom"}') is False
    assert default_biz_oracle(500, '{"success": true}') is False
    assert default_biz_oracle(200, "") is False


def test_write_candidates_keeps_only_reversible_by_default(monkeypatch):
    """默认只保留可逆动作（领券）；不可逆（下单/支付）全部排除。"""
    from vulnclaw.ai.v100.phases.phases_taskgen import _collect_write_candidates

    monkeypatch.setattr(settings, "sequence_endpoint_allowlist", "", raising=False)
    monkeypatch.setattr(settings, "sequence_allow_financial", False, raising=False)
    monkeypatch.setattr(settings, "sequence_allow_irreversible", False, raising=False)
    brief = {"crawled_endpoints": [
        "https://x.test/order/create",
        "https://x.test/pay/submit",
        "https://x.test/coupon/claim",
    ]}
    assert _collect_write_candidates(brief) == ["https://x.test/coupon/claim"]

    # 显式允许不可逆后：下单类回来，但资金类仍被 financial 闸挡住
    monkeypatch.setattr(settings, "sequence_allow_irreversible", True, raising=False)
    out2 = _collect_write_candidates(brief)
    assert "https://x.test/order/create" in out2
    assert "https://x.test/pay/submit" not in out2


def test_write_candidates_respects_allowlist(monkeypatch):
    """白名单非空时只跑显式指定的端点。"""
    from vulnclaw.ai.v100.phases.phases_taskgen import _collect_write_candidates

    monkeypatch.setattr(settings, "sequence_endpoint_allowlist", "coupon/claim", raising=False)
    out = _collect_write_candidates({
        "crawled_endpoints": ["https://x.test/order/create", "https://x.test/coupon/claim"]
    })
    assert out == ["https://x.test/coupon/claim"]


def test_extract_biz_identifiers():
    ids = extract_biz_identifiers(
        '{"order_id": "ORD500001"}, {"order_id": "ORD500002"}, {"order_id": "ORD500001"}'
    )
    assert ids == ["ORD500001", "ORD500002"]  # 去重保序
