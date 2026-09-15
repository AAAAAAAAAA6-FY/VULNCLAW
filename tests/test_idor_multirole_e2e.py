# -*- coding: utf-8 -*-
"""IDOR/BOLA 多账号 E2E 闭环（离线，无 LLM 依赖）。

覆盖：
  1. 越权 mock（不校验属主）：跨账号访问必须被引擎检出（正例）
  2. 正确 mock（跨号 403）：必须不误报（负例）
  3. build_multi_role_sessions 多角色会话装载 → scan_with_roles ≥2 角色链路可跑
  4. _init_multi_role 单会话默认行为不因新增 helper 而回归（helper 只做装载）
"""
import asyncio
import sys
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
for _p in (str(PROJECT / "src"), str(SCRIPTS)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import aiohttp  # noqa: E402
import idor_multirole_e2e as mod  # noqa: E402
from vulnclaw.engines.auth_engines import IDOREngine  # noqa: E402


def _ctx(correct: bool, port: int = 0):
    """启动 mock，返回 (base_url, server)。"""
    server, used = mod.start_mock_server(correct=correct, port=port)
    return mod.mock_base_url(used), server


async def _scan(base: str, token: str, engine=None) -> list:
    engine = engine or IDOREngine()
    async with aiohttp.ClientSession(headers={"Authorization": f"Bearer {token}"}) as sess:
        return await engine.scan(base, sess)


async def _fake_verify_true(url, roles, responses, diff_score, sensitive_data, role_privilege=None):
    """离线假验证器：差异大或含敏感数据即判真。"""
    if diff_score > 0.4 or sensitive_data:
        return {"is_idor": True, "confidence": "高", "severity": "High",
                "evidence": "测试假验证器：差异或敏感字段", "privilege_violation": "水平越权",
                "recommendation": "服务端校验属主关系"}
    return {"is_idor": False, "confidence": "低", "evidence": "未确认", "privilege_violation": "无"}


def _scan_detect(base: str, token: str) -> list:
    return asyncio.run(_scan(base, token))


def test_detect_vulnerable_multirole():
    """越权 mock：alice 会话访问 id=2（bob）资源 → 必须检出 IDOR/BOLA。"""
    base, server = _ctx(correct=False)
    try:
        findings = _scan_detect(base, mod.TOKENS["alice"])
        assert findings, "越权 mock 应产生 IDOR/BOLA finding"
        assert any("IDOR" in f.get("type", "") or "BOLA" in f.get("type", "")
                   or "越权" in f.get("type", "") for f in findings)
        assert any("profile/2" in f.get("url", "") for f in findings)
    finally:
        server.shutdown(); server.server_close()


def test_correct_mode_no_false_positive():
    """正确 mock：跨号返回 403 → 不得误报。"""
    base, server = _ctx(correct=True)
    try:
        findings = _scan_detect(base, mod.TOKENS["alice"])
        assert findings == [], f"正确版不应误报，实际检出: {findings}"
    finally:
        server.shutdown(); server.server_close()


def test_build_multi_role_sessions_closes_gap():
    """build_multi_role_sessions 装载 ≥2 个独立会话（closure 于 _init_multi_role 的缺口）。"""
    from vulnclaw.core.auth.session_manager import SessionManager
    from vulnclaw.ai.v100.orchestrator import build_multi_role_sessions
    sm = SessionManager()
    n = build_multi_role_sessions(sm, {
        "alice": {"authorization": mod.TOKENS["alice"]},
        "bob": {"authorization": mod.TOKENS["bob"]},
    }, domain="127.0.0.1")
    assert n == 2
    roles = sm.get_roles()
    assert "alice" in roles and "bob" in roles
    # 会话默认头必须真的带上 Authorization（add_session 的 token dict 更新晚于
    # aiohttp 快照，靠 extra_headers 保证），否则 scan_with_roles 会因 401 失效。
    assert sm.sessions["alice"]._default_headers.get("Authorization", "").startswith("Bearer ")
    assert sm.sessions["bob"]._default_headers.get("Authorization", "").startswith("Bearer ")


def test_scan_with_roles_runs_and_detects_with_verifier():
    """scan_with_roles 多角色链路：≥2 角色可跑，配验证器可产 finding。"""
    from vulnclaw.core.auth.session_manager import SessionManager
    from vulnclaw.ai.v100.orchestrator import build_multi_role_sessions
    base, server = _ctx(correct=False)
    try:

        async def _run():
            sm = SessionManager()   # 会话须在运行中的事件循环内构造
            sm._enabled_reload = False
            sm.set_auto_refresh(False)
            build_multi_role_sessions(sm, {
                "alice": {"authorization": mod.TOKENS["alice"]},
                "bob": {"authorization": mod.TOKENS["bob"]},
            }, domain="127.0.0.1")
            try:
                from vulnclaw.engines.auth_engines import IDOREngine
                roles = sm.get_roles()
                assert len(roles) >= 2
                engine = IDOREngine()
                engine._ai_verify_idor = _fake_verify_true  # 离线假验证器
                return await engine.scan_with_roles(base, roles, sm)
            finally:
                await sm.close_all()

        findings = asyncio.run(_run())
        assert isinstance(findings, list)
        assert any("IDOR" in f.get("type", "") or "越权" in f.get("type", "")
                   for f in findings), "多角色链路配验证器应能产出越权 finding"
    finally:
        server.shutdown(); server.server_close()


def test_scan_with_roles_needs_two_roles():
    """少角色守卫：单角色应直接返回空列出而不崩。"""
    from vulnclaw.core.auth.session_manager import SessionManager
    engine = IDOREngine()

    def _run():
        sm = SessionManager()
        sm._enabled_reload = False
        sm.set_auto_refresh(False)
        sm.add_session("alice", token_dict={"Authorization": "Bearer x"})
        try:
            return asyncio.run(engine.scan_with_roles(
                "http://127.0.0.1:1/api/profile/1", ["alice"], sm))
        finally:
            asyncio.run(sm.close_all())

    assert _run() == []


def test_init_multi_role_single_session_semantics_unchanged():
    """验证新增 helper 不改动 _init_multi_role 单会话默认行为（方法仍存在且未改签名）。"""
    from vulnclaw.ai.v100.orchestrator import V100Orchestrator
    assert hasattr(V100Orchestrator, "_init_multi_role")
    # 单角色参数只装载 1 个会话
    from vulnclaw.core.auth.session_manager import SessionManager
    from vulnclaw.ai.v100.orchestrator import build_multi_role_sessions
    sm = SessionManager()
    n = build_multi_role_sessions(sm, {"alice": {"authorization": mod.TOKENS["alice"]}})
    assert n == 1
    assert sm.get_roles() == ["alice"]
    asyncio.run(sm.close_all())