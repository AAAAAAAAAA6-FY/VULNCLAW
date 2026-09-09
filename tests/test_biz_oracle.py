# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""B 方案契约测试：双会话差分业务逻辑 oracle（专治水平越权）。

覆盖：无鉴权越权实锤 / 双账号确认 / 授权已强制 / SPA壳排除 / fail-closed /
降级链（真实双角色→匿名兜底→无身份跳过 / 开关回滚 / findings 字段契约）。
全部离线，不经真实网络。
"""
import asyncio
import json

from vulnclaw.engines.biz_oracle_engines import DualSessionOracleEngine
from vulnclaw.ai.v100.phases import phases_taskgen
from vulnclaw.config.settings import settings
from vulnclaw.core.biz_oracle.diff_oracle import dual_session_probe, oracle_verdict
from vulnclaw.core.biz_oracle.identity_matrix import IdentityMatrix


# ---------------- 离线双身份桩 ----------------

class _FakeMgr:
    """伪 SessionManager：role 级路由，支持 0/1/2 角色场景。"""

    def __init__(self, roles, router):
        self._roles = list(roles)
        self._router = router
        self.default_headers = {"User-Agent": "pytest", "Accept": "*/*"}

    def get_roles(self):
        return list(self._roles)

    async def request(self, role, method, url, timeout=None, retry_count=0, **kwargs):
        return self._router(role, url, method)


class _Resp:
    def __init__(self, status, text, headers=None):
        self.status = status
        self._text = text
        self.headers = headers or {}

    async def text(self):
        return self._text

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _Anon:
    """伪匿名会话：无 Cookie/无 Authorization，按 URL 路由返回工件响应。"""

    def __init__(self, router):
        self._router = router

    def request(self, method, url, **kwargs):
        status, text, headers = self._router(url, method)
        return _Resp(status, text, headers)


def _router_map(routes):
    """routes: {url_substr: {role: (status, text)}} → (role,url)->(status,text,{})；空则 (404,'',{})。"""
    items = list(routes.items())

    def route(role, url, method):
        for sub, table in items:
            if sub in url:
                hit = table.get(role)
                if hit is not None:
                    return hit[0], hit[1], {}
        return 404, "", {}

    return route


def _run(coro):
    return asyncio.run(coro)


def _alice_html():
    return '<div class="mail">alice@example.com</div>'


def _bob_html():
    return '<div class="mail">bob@example.com</div>'


# ---------------- 正向：无鉴权水平越权（匿名身份 B 拿到他人私有数据） ----------------

def test_anon_horizontal_leak_machine_proof():
    mgr = _FakeMgr(["role_a"], _router_map({
        "id=101": {"role_a": (200, _alice_html())},
    }))
    im = IdentityMatrix(mgr, anon_session=_Anon(lambda u, m: (200, _bob_html(), {})))
    assert _run(im.ensure_second_identity("x.test")) == "oracle_anon"
    assert im.anon is True

    f = _run(DualSessionOracleEngine().diagnose(
        "https://x.test/profile?id=101", "id", "101", im, mgr))
    assert f is not None
    assert f["severity"] == "High"
    assert f["anonymity"] == "anonymous"
    assert f["method"] == "idor_dual_session"
    assert f["parameter"] == "id"
    assert "id=101" in f["url"]
    d = f["oracle_diff"]
    assert d["ok"] is True and d["b_private"] and d["anon"] is True
    # 契约字段（B 堆 finding 必备）
    for k in ("type", "severity", "title", "description", "evidence", "remediation",
              "recommendation", "url", "parameter", "method", "confidence",
              "cvss", "curl_command"):
        assert k in f, k
    # oracle_diff 结构化可序列化（喂 AI 证据包 / 报告）
    json.dumps(d)


def test_second_account_confirmed_leak():
    mgr = _FakeMgr(["role_a", "role_b"], _router_map({
        "id=7": {
            "role_a": (200, '{"uid":"11111111-1111-1111-1111-111111111111"}'),
            "role_b": (200, '{"uid":"22222222-2222-2222-2222-222222222222"}'),
        },
    }))
    im = IdentityMatrix(mgr)
    assert _run(im.ensure_second_identity("x.test")) == "role_b"
    assert im.anon is False

    f = _run(DualSessionOracleEngine().diagnose(
        "https://x.test/api/user?id=7", "user", "7", im, mgr))
    assert f is not None
    assert f["anonymity"] == "second_account"
    assert f["oracle_diff"]["b_private"]["uuid"] == "22222222-2222-2222-2222-222222222222"


# ---------------- 负向：授权已强制 / 公开壳 / 网络失败 ----------------

def test_auth_enforced_no_finding():
    mgr = _FakeMgr(["role_a", "role_b"], _router_map({
        "id=7": {
            "role_a": (200, '{"uid":"11111111-1111-1111-1111-111111111111"}'),
            "role_b": (401, "Unauthorized"),
        },
    }))
    im = IdentityMatrix(mgr)
    _run(im.ensure_second_identity("x.test"))
    f = _run(DualSessionOracleEngine().diagnose(
        "https://x.test/api/user?id=7", "user", "7", im, mgr))
    assert f is None  # B 被拦 → 授权强制 → 差分线无产出


def test_spa_shell_excluded():
    shell = "<html><div id=app>public landing page for everyone</div></html>"
    mgr = _FakeMgr(["role_a", "role_b"], _router_map({
        "id=1": {"role_a": (200, shell), "role_b": (200, shell)},
    }))
    im = IdentityMatrix(mgr)
    _run(im.ensure_second_identity("x.test"))
    f = _run(DualSessionOracleEngine().diagnose(
        "https://x.test/profile?id=1", "id", "1", im, mgr))
    assert f is None  # A/B 同构且无私有标记 → 公开壳排除


def test_fail_closed_on_net_failure():
    mgr = _FakeMgr(["role_a"], lambda r, u, m: (200, "hello", {}))
    im = IdentityMatrix(mgr, anon_session=_Anon(lambda u, m: (0, "", {})))
    _run(im.ensure_second_identity("x.test"))
    f = _run(DualSessionOracleEngine().diagnose(
        "https://x.test/profile?id=1", "id", "1", im, mgr))
    assert f is None  # 探针失败 → error → 不产出


def test_oracle_verdict_units():
    assert oracle_verdict({"ok": False}) == "error"
    assert oracle_verdict({"ok": True, "b_blocked": True}) == "auth_enforced"
    assert oracle_verdict({"ok": True, "b_blocked": False, "status_parity": True,
                           "body_sim": 0.97, "b_private": None}) == "public_shell"
    assert oracle_verdict({"ok": True, "b_blocked": False, "status_parity": True,
                           "body_sim": 0.9, "b_private": {"email": "x@y.z"}}) == "horizontal_leak"
    assert oracle_verdict({"ok": True, "b_blocked": False, "status_parity": False,
                           "body_sim": 0.2, "b_private": None}) == "error"


# ---------------- 降级链 / 开关回滚 ----------------

def test_two_roles_prefer_real_second():
    mgr = _FakeMgr(["role_a", "role_b"], lambda r, u, m: (200, "ok", {}))
    im = IdentityMatrix(mgr)
    assert _run(im.ensure_second_identity("x.test")) == "role_b"
    assert im.anon is False


def test_no_second_identity_when_anon_disabled(monkeypatch):
    monkeypatch.setattr(settings, "idor_anon_pair", False)
    mgr = _FakeMgr(["role_a"], lambda r, u, m: (200, "ok", {}))
    im = IdentityMatrix(mgr)
    assert _run(im.ensure_second_identity("x.test")) is None
    assert im.identity_b is None


def test_probe_missing_identity_fail_closed():
    sig = _run(dual_session_probe(
        "https://x.test/?id=1", "GET", "role_a", None, identities=None))
    assert sig.get("ok") is False


def test_switch_off_falls_back_old_behavior(monkeypatch):
    monkeypatch.setattr(settings, "idor_dual_session", False)

    class _FakeSelf:
        target = "https://x.test/"
        _recon_brief = {}

        def __init__(self):
            self._idor_findings = 0

        def _add_finding(self, f):
            self._finder = f

    s = _FakeSelf()
    assert _run(phases_taskgen._run_idor_dual_session_line(s)) == 0
    assert s._idor_findings == 0


# ---------------- 候选收集 ----------------

def test_collect_idor_candidates():
    brief = {"crawled_endpoints": [
        "https://x.test/profile?id=101",
        "https://x.test/static/app.js",
        "https://x.test/order?order_id=abc&page=2",
    ]}
    out = phases_taskgen._collect_idor_candidates(brief, "https://x.test/")
    params = sorted(set(p for _, p, _ in out))
    assert "id" in params and "order_id" in params


def test_collect_idor_candidates_empty():
    assert phases_taskgen._collect_idor_candidates(
        {"crawled_endpoints": ["https://x.test/about"]}, "https://x.test/") == []
