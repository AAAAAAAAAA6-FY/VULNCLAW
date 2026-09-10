# -*- coding: utf-8 -*-
"""MetamorphicEngine 专项测试：元orphic 不变量探针三条元规则 + fail-closed 边界。

全部用注入的 requester 模拟响应，不发真实网络请求。
requester 签名：await requester(endpoint, params, method) -> (status, text, headers)
"""
import pytest

from vulnclaw.config.settings import settings
from vulnclaw.engines.metamorphic_engines import (
    MetamorphicEngine,
    detect_amount_fields,
    detect_id_fields,
)


def _requester(responses):
    """按调用顺序返回 responses，超出则重复最后一项。"""
    state = {"n": 0}

    async def _req(endpoint, params, method):
        i = state["n"]
        state["n"] += 1
        return responses[i] if i < len(responses) else responses[-1]

    return _req


def _by_cases(cases):
    """按参数内容分派响应：cases 为 [((predicate), response)]，predicate 收到 params。"""
    async def _req(endpoint, params, method):
        for pred, resp in cases:
            if pred(params):
                return resp
        return cases[-1][1]

    return _req


@pytest.fixture(autouse=True)
def _meta_enabled(monkeypatch):
    """默认开启（含状态变更授权）；个别用例再单独关闭验证闸门。"""
    monkeypatch.setattr(settings, "metamorphic_enabled", True, raising=False)
    monkeypatch.setattr(settings, "metamorphic_allow_state_changing", True, raising=False)


# ---------------------------------------------------------------- 字段识别
def test_detect_amount_fields():
    assert detect_amount_fields({"price": "100", "qty": "2", "total": "200"}) == ["price", "total"]
    assert detect_amount_fields({"qty": "2"}) == []


def test_detect_id_fields():
    assert detect_id_fields({"user_id": "1001", "name": "alice"}) == ["user_id"]
    assert detect_id_fields({"name": "alice"}) == []


# ---------------------------------------------------------------- 1) 金额篡改
@pytest.mark.asyncio
async def test_price_tampering_detects_echoed_amount():
    """服务端原样回显篡改金额 -> 强证据 high。"""
    eng = MetamorphicEngine()
    req = _by_cases([
        (lambda p: p.get("price") == "100", (200, '{"success":true,"order_id":"ORD1","price":"100"}', {})),
        (lambda p: p.get("price") == "0.01", (200, '{"success":true,"order_id":"ORD2","price":"0.01"}', {})),
    ])
    f = await eng.probe_price_tampering(
        "https://x.test/order/create", {"price": "100", "qty": "1"}, method="POST", requester=req
    )
    assert f is not None
    assert f["type"] == "price_tampering"
    assert f["severity"] == "high"
    assert f["tampered_value"] == "0.01"


@pytest.mark.asyncio
async def test_price_tampering_skips_without_amount_field():
    """没有金额字段 -> 本元规则不适用。"""
    eng = MetamorphicEngine()
    req = _requester([(200, '{"success":true,"order_id":"ORD1"}', {})])
    assert await eng.probe_price_tampering(
        "https://x.test/order/create", {"qty": "1"}, method="POST", requester=req
    ) is None


@pytest.mark.asyncio
async def test_price_tampering_requires_state_changing_authorization(monkeypatch):
    """未授权状态变更（默认）-> 金额篡改不跑（避免真的建单）。"""
    monkeypatch.setattr(settings, "metamorphic_allow_state_changing", False, raising=False)
    eng = MetamorphicEngine()
    req = _requester([(200, '{"success":true,"price":"0.01"}', {})])
    assert await eng.probe_price_tampering(
        "https://x.test/order/create", {"price": "100"}, method="POST", requester=req
    ) is None


# ---------------------------------------------------------------- 2) 重放幂等
@pytest.mark.asyncio
async def test_replay_detects_two_distinct_resources():
    """重放两次均成功且资源标识不同 -> 非幂等。"""
    eng = MetamorphicEngine()
    req = _requester([
        (200, '{"success":true,"coupon_code":"CP100001"}', {}),
        (200, '{"success":true,"coupon_code":"CP100002"}', {}),
    ])
    f = await eng.probe_replay_idempotency(
        "https://x.test/coupon/claim", {"coupon_id": "C1"}, method="POST", requester=req
    )
    assert f is not None
    assert f["type"] == "replay_not_idempotent"
    assert f["first_identifiers"] == ["CP100001"]
    assert f["second_identifiers"] == ["CP100002"]


@pytest.mark.asyncio
async def test_replay_idempotent_when_second_rejected():
    """第二次被拒 -> 幂等正常，不产出。"""
    eng = MetamorphicEngine()
    req = _requester([
        (200, '{"success":true,"coupon_code":"CP200001"}', {}),
        (200, '{"error":"already claimed"}', {}),
    ])
    assert await eng.probe_replay_idempotency(
        "https://x.test/coupon/claim", {"coupon_id": "C1"}, method="POST", requester=req
    ) is None


# ---------------------------------------------------------------- 3) ID 越权候选
@pytest.mark.asyncio
async def test_idor_candidate_detects_foreign_data():
    """改 ID 后仍返回不同业务数据、且非无权限页 -> 越权候选（只读探测）。"""
    eng = MetamorphicEngine()
    req = _by_cases([
        (lambda p: p.get("user_id") == "1001",
         (200, '{"success":true,"data":{"user":"alice","orders":[]}}', {})),
        (lambda p: p.get("user_id") == "1002",
         (200, '{"success":true,"data":{"user":"bob","orders":[{"id":9001,"item":"laptop"}],'
               '"address":"Shanghai"}}', {})),
    ])
    f = await eng.probe_idor_candidate(
        "https://x.test/profile", {"user_id": "1001"}, method="GET", requester=req
    )
    assert f is not None
    assert f["type"] == "idor_candidate"
    assert f["mutated_value"] == "1002"


@pytest.mark.asyncio
async def test_idor_candidate_skips_when_denied():
    """改 ID 后被拒（403/无权限）-> 服务端有鉴权，不产出。"""
    eng = MetamorphicEngine()
    req = _by_cases([
        (lambda p: p.get("user_id") == "1001", (200, '{"success":true,"name":"alice"}', {})),
        (lambda p: p.get("user_id") == "1002", (403, '{"error":"unauthorized"}', {})),
    ])
    assert await eng.probe_idor_candidate(
        "https://x.test/profile", {"user_id": "1001"}, method="GET", requester=req
    ) is None


@pytest.mark.asyncio
async def test_idor_candidate_is_readonly_and_always_allowed(monkeypatch):
    """只读元规则：即使未授权状态变更也可跑（零副作用）。"""
    monkeypatch.setattr(settings, "metamorphic_allow_state_changing", False, raising=False)
    eng = MetamorphicEngine()
    req = _by_cases([
        (lambda p: p.get("user_id") == "1001",
         (200, '{"success":true,"data":{"user":"alice","orders":[]}}', {})),
        (lambda p: p.get("user_id") == "1002",
         (200, '{"success":true,"data":{"user":"bob","orders":[{"id":9001,"item":"laptop"}],'
               '"address":"Shanghai"}}', {})),
    ])
    f = await eng.probe_idor_candidate(
        "https://x.test/profile", {"user_id": "1001"}, method="GET", requester=req
    )
    assert f is not None


# ---------------------------------------------------------------- 通用入口与批量
@pytest.mark.asyncio
async def test_check_is_noop_outside_orchestration():
    eng = MetamorphicEngine()
    assert await eng.check("https://x.test/a", "id", (200, "x", {}), "", None) is None


@pytest.mark.asyncio
async def test_probe_all_runs_applicable_rules(monkeypatch):
    """批量执行：无金额/ID 字段时全部不适用 -> 空列表（fail-closed）。"""
    monkeypatch.setattr(settings, "metamorphic_allow_state_changing", True, raising=False)
    eng = MetamorphicEngine()
    req = _requester([(200, '{"success":true,"order_id":"ORD9"}', {})])
    out = await eng.probe_all("https://x.test/order/create", {"qty": "1"},
                              method="POST", requester=req)
    assert out == []


# ---------------------------------------------------------------- 新范式：多位置注入点
@pytest.mark.asyncio
async def test_probe_spec_detects_amount_in_json_body():
    """JSON body 里的金额字段——旧 build_attack_url 路径（只认 query）测不到。"""
    from vulnclaw.core.attack_surface import PointLocation, spec_from_url

    eng = MetamorphicEngine()

    async def _req(spec):
        if spec.json_obj.get("total") == 0.01:
            return (200, '{"success":true,"order_id":"ORD1","total":0.01}', {})
        return (200, '{"success":true,"order_id":"ORD0","total":200}', {})

    spec = spec_from_url("https://x.test/api/order", "POST",
                         json_obj={"total": 200, "items": [{"price": 50}]})
    out = await eng.probe_spec(spec, requester=_req)
    assert out and out[0]["type"] == "price_tampering"
    assert out[0]["point_location"] == PointLocation.BODY_JSON.value


@pytest.mark.asyncio
async def test_probe_spec_detects_idor_in_header():
    """header 里的身份 ID（X-User-Id）——同样不属于 query 注入面。"""
    from vulnclaw.core.attack_surface import spec_from_url

    eng = MetamorphicEngine()

    async def _req(spec):
        if spec.headers.get("X-User-Id") == "1002":
            return (200, '{"success":true,"data":{"user":"bob","orders":[{"id":9001}],'
                         '"address":"Shanghai"}}', {})
        return (200, '{"success":true,"data":{"user":"alice","orders":[]}}', {})

    spec = spec_from_url("https://x.test/api/me", "GET", headers={"X-User-Id": "1001"})
    out = await eng.probe_spec(spec, requester=_req)
    assert out and out[0]["type"] == "idor_candidate"
    assert out[0]["parameter"] == "header:X-User-Id"


@pytest.mark.asyncio
async def test_probe_spec_detects_idor_in_path_segment():
    """路径段里的 ID（/api/profile/1001）——路径段的"名字"就是值本身。"""
    from vulnclaw.core.attack_surface import spec_from_url

    eng = MetamorphicEngine()

    async def _req(spec):
        if spec.url.endswith("/1002"):
            return (200, '{"success":true,"data":{"user":"bob","orders":[{"id":9001}],'
                         '"address":"Shanghai"}}', {})
        return (200, '{"success":true,"data":{"user":"alice","orders":[]}}', {})

    spec = spec_from_url("https://x.test/api/profile/1001", "GET")
    out = await eng.probe_spec(spec, requester=_req)
    assert out and out[0]["type"] == "idor_candidate"
    assert out[0]["parameter"].startswith("path[")
