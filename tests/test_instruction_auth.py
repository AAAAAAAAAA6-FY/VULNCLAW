# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP27: 指令消费层（instruction_auth）单元测试。

覆盖（全部离线，monkeypatch 登录动作）：
- 无凭据 / 全失败 → 返回 False（回退既有流程）
- 主账号 cookie 落盘 cookies/{domain}.json（格式与既有一致）
- 多账号：角色 cookie 落盘 cookies/{domain}@{role}.json
- 角色文件名清洗；HTTP 表单降级（httpx MockTransport：成功/失败）
"""
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from vulnclaw.core.auth import instruction_auth  # noqa: E402
from vulnclaw.core.instructions import Instruction, Acct  # noqa: E402


def _run(coro):
    return asyncio.run(coro)


def _ins(*accts):
    return Instruction(accounts=list(accts))


# ---------- 回退路径 ----------

def test_no_credentials_returns_false(tmp_path, monkeypatch):
    monkeypatch.setattr(instruction_auth, "COOKIE_DIR", tmp_path)
    assert _run(instruction_auth.try_instruction_login("http://t.local", "t.local", Instruction())) is False
    assert _run(instruction_auth.try_instruction_login("http://t.local", "t.local", None)) is False


def test_all_fail_returns_false(tmp_path, monkeypatch):
    async def _fake_login(*a, **k):
        return None

    monkeypatch.setattr(instruction_auth, "COOKIE_DIR", tmp_path)
    monkeypatch.setattr(instruction_auth, "_login_one", _fake_login)
    ins = _ins(Acct("user", "u1@t.local", "p1"), Acct("admin", "u2@t.local", "p2"))
    assert _run(instruction_auth.try_instruction_login("http://t.local", "t.local", ins)) is False


# ---------- 单账号落盘 ----------

def test_main_account_saved(tmp_path, monkeypatch):
    async def _fake_login(*a, **k):
        return {"session": "abc", "uid": "42"}

    monkeypatch.setattr(instruction_auth, "COOKIE_DIR", tmp_path)
    monkeypatch.setattr(instruction_auth, "_login_one", _fake_login)
    ins = _ins(Acct("管理员", "admin@t.local", "secret"))
    ok = _run(instruction_auth.try_instruction_login("http://t.local", "t.local", ins))
    assert ok is True
    f = tmp_path / "t.local.json"
    assert f.exists()
    import json

    data = json.loads(f.read_text(encoding="utf-8"))
    assert data == {"t.local": {"session": "abc", "uid": "42"}}


# ---------- 多账号：角色文件 ----------

def test_role_account_saved(tmp_path, monkeypatch):
    async def _fake_login(login_url, acct, *a, **k):
        # 按用户名返回不同 cookie（充当不同会话）
        return {"session": "s_" + acct.username.split("@")[0]}

    monkeypatch.setattr(instruction_auth, "COOKIE_DIR", tmp_path)
    monkeypatch.setattr(instruction_auth, "_login_one", _fake_login)
    ins = _ins(Acct("user", "alice@t.local", "p1"), Acct("admin", "bob@t.local", "p2"))
    ok = _run(instruction_auth.try_instruction_login("http://t.local", "t.local", ins))
    assert ok is True
    assert (tmp_path / "t.local.json").exists()
    assert (tmp_path / "t.local@admin.json").exists()
    import json

    admin = json.loads((tmp_path / "t.local@admin.json").read_text(encoding="utf-8"))
    assert admin["t.local"]["session"] == "s_bob"


# ---------- 角色名清洗 ----------

def test_role_suffix_sanitize():
    assert instruction_auth._role_suffix("") == ""
    assert instruction_auth._role_suffix("default") == ""
    assert instruction_auth._role_suffix("管理员") == "@管理员"
    assert instruction_auth._role_suffix("a/b:c*d") == "@a_b_c_d"


# ---------- HTTP 表单降级成功 ----------

def test_http_form_login_success():
    import httpx

    login_html = (
        '<form action="/do-login" method="post">'
        '<input name="_csrf" type="hidden" value="tok123">'
        '<input name="email" type="email">'
        '<input name="password" type="password">'
        "</form>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            if request.url.path == "/dashboard":
                # 跟随 302 后的着陆页：无密码框，且正文含用户名 → 判定登录成功
                return httpx.Response(200, text="<h1>dashboard alice@t.local</h1>")
            return httpx.Response(
                200,
                text=login_html,
                headers={"content-type": "text/html"},
            )
        # POST 提交成功：302 跳转 dashboard + 下发 session cookie
        return httpx.Response(
            302,
            headers={
                "location": "/dashboard",
                "set-cookie": "session=abc123; Path=/",
            },
            text="",
        )

    transport = httpx.MockTransport(handler)
    cookies = _run(instruction_auth._http_form_login(
        "http://t.local/login", "alice@t.local", "p1", transport=transport,
    ))
    assert cookies and cookies.get("session") == "abc123"


# ---------- HTTP 表单降级失败（无 cookie） ----------

def test_http_form_login_no_cookie():
    import httpx

    login_html = (
        '<form action="/do-login" method="post">'
        '<input name="email" type="email">'
        '<input name="password" type="password">'
        "</form>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=login_html)
        # 提交后仍返回登录页（无 cookie）→ 视为失败
        return httpx.Response(200, text=login_html)

    transport = httpx.MockTransport(handler)
    cookies = _run(instruction_auth._http_form_login(
        "http://t.local/login", "alice@t.local", "p1", transport=transport,
    ))
    assert cookies is None


# ---------- HTTP 表单降级：仍显示密码框 → 判定失败 ----------

def test_http_form_login_still_form():
    import httpx

    login_html = (
        '<form action="/do-login" method="post">'
        '<input name="email" type="email">'
        '<input name="password" type="password">'
        "</form>"
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(200, text=login_html)
        # 有 cookie 但页面仍带密码框，且正文无用户名 → 疑似失败
        return httpx.Response(
            200,
            headers={"set-cookie": "session=zzz; Path=/"},
            text=login_html,
        )

    transport = httpx.MockTransport(handler)
    cookies = _run(instruction_auth._http_form_login(
        "http://t.local/login", "alice@t.local", "p1", transport=transport,
    ))
    assert cookies is None
