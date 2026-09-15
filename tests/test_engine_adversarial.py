# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""A1 对抗性响应验收：异常响应 / WAF 拦截 / 超时 / 重定向。

目的：验证引擎在"拒绝合作的目标"上的行为是 **fail-closed**：
  - 不产生误报（无证据 → None/空 findings）
  - 不崩溃（畸形体 / 非 UTF-8 / 重定向循环都不得抛异常）
  - 不失控（请求数上限 + 耗时上限，time.monotonic 断言）

与 tests/test_engines_core.py 的分工：该文件负责"正向检测能力"（正反例四件套），
本文件负责"防守侧"（对抗响应下不误报、不崩、不失控）。靶场为本文件内建。
"""
import asyncio
import time

import pytest
import pytest_asyncio
from aiohttp import ClientSession, ClientTimeout, web
from aiohttp.test_utils import TestServer

from vulnclaw.engines.http_engines import HostHeaderEngine, OpenRedirectEngine
from vulnclaw.engines.net_engines import GraphQLEngine, SSRFEngine
from vulnclaw.core.settings import settings
from vulnclaw.engines.auth_engines import JWTEngine
from vulnclaw.engines.web_engines import (
    CMDIEngine,
    LFIEngine,
    NoSQLEngine,
    SQLiEngine,
    SSTIEngine,
    XSSEngine,
)
from vulnclaw.engines.input_engines import CORSEngine, LDAPEngine

# 靶场请求计数（对抗场景下同样要做"请求数上限"断言）
_ADV_HITS: dict = {}


@web.middleware
async def _adv_hit_counter(request, handler):
    _ADV_HITS[request.path] = _ADV_HITS.get(request.path, 0) + 1
    return await handler(request)


def _build_adversarial_app():
    async def _ok(request):
        return web.Response(
            text="<html><body><h1>OK</h1><p>" + "row data " * 30 + "</p></body></html>"
        )

    async def _err500(request):
        """异常响应：500 通用错误页（无任何 SQL/命令/模板/路径特征）。"""
        return web.Response(
            text="<html><body><h1>Internal Server Error</h1></body></html>",
            status=500,
        )

    async def _empty(request):
        """异常响应：200 空体。"""
        return web.Response(text="")

    async def _malformed(request):
        """异常响应：非 UTF-8 畸形字节体。"""
        return web.Response(body=b"\x00\xff\xfe\x01\x02<no-page>\x00", content_type="text/html")

    async def _waf(request):
        """WAF 拦截：403 固定拦截页（不回显任何输入）。"""
        return web.Response(
            text=(
                "<html><body><h1>403 Forbidden</h1>"
                "<p>Request blocked by WAF (ModSecurity CRS)</p></body></html>"
            ),
            status=403,
        )

    async def _slow(request):
        """超时响应：服务端延迟回包（客户端短超时 0.8s → 引擎必须 fail-closed）。

        延迟取 1.0s：仅需超过客户端短超时即可触发，压缩测试总时长。
        """
        await asyncio.sleep(1.0)
        return web.Response(text="late response " * 20)

    async def _redir_safe(request):
        """重定向响应：同站 302 → 安全页。"""
        raise web.HTTPFound(location="/ok")

    async def _redir_loop(request):
        """重定向响应：无限自循环。"""
        raise web.HTTPFound(location="/redir-loop")

    app = web.Application(middlewares=[_adv_hit_counter])
    app.router.add_get("/ok", _ok)
    app.router.add_get("/adv/err500", _err500)
    app.router.add_get("/adv/empty", _empty)
    app.router.add_get("/adv/malformed", _malformed)
    app.router.add_get("/adv/waf", _waf)
    app.router.add_get("/adv/slow", _slow)
    app.router.add_get("/redir-safe", _redir_safe)
    app.router.add_get("/redir-loop", _redir_loop)
    return app


@pytest_asyncio.fixture
async def adv_base():
    _ADV_HITS.clear()
    server = TestServer(_build_adversarial_app())
    await server.start_server()
    base = f"http://127.0.0.1:{server.port}"
    try:
        yield base
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession(timeout=ClientTimeout(total=20)) as s:
        yield s


@pytest_asyncio.fixture
async def short_session():
    """短超时会话：专用于超时对抗场景。"""
    async with ClientSession(timeout=ClientTimeout(total=0.8)) as s:
        yield s


def _normal():
    return (200, "<html><body><h1>OK</h1>" + "<p>row data</p>" * 30 + "</body></html>", {})


def _assert_bounded(path: str, max_hits: int) -> None:
    hits = _ADV_HITS.get(path, 0)
    assert hits <= max_hits, f"对抗场景下请求过多: {path} 命中 {hits} 次（上限 {max_hits}）"


def _assert_timebound(t0: float, max_seconds: float) -> None:
    elapsed = time.monotonic() - t0
    assert elapsed < max_seconds, f"耗时 {elapsed:.1f}s 超上限 {max_seconds}s"


# ============================================================
# 1) 异常响应（500 / 空体 / 畸形体）：无证据 → 不得误报
# ============================================================
@pytest.mark.asyncio
async def test_sqli_no_fp_on_500_error_page(adv_base, session):
    eng = SQLiEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/err500?id=x", "id", _normal(), "id=x", session)
    assert result is None, f"SQLi 引擎在 500 通用错误页误报: {result}"
    _assert_bounded("/adv/err500", 16)
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_lfi_no_fp_on_empty_body(adv_base, session):
    eng = LFIEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/empty?file=x", "file", _normal(), "file=x", session)
    assert result is None, f"LFI 引擎在空体响应误报: {result}"
    _assert_bounded("/adv/empty", 20)
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
@pytest.mark.xfail(strict=False, reason="真实缺陷：长度启发式把非 UTF-8 畸形体（9B）整体视为'响应长度异常变化'，diff_ratio=0.94 触发分号注入-id 疑似误报（FP, 与 NoSQL/LDAP WAF 模板用例同类的已知缺陷）。")
async def test_cmdi_no_fp_on_malformed_body(adv_base, session):
    """畸形（非 UTF-8）响应体：引擎要么 fail-closed，要么被内部捕获——不得抛异常。"""
    eng = CMDIEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/malformed?cmd=x", "cmd", _normal(), "cmd=x", session)
    assert result is None, f"CMDI 引擎在畸形体响应误报: {result}"
    _assert_bounded("/adv/malformed", 12)
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_ssti_no_fp_on_500_error_page(adv_base, session):
    eng = SSTIEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/err500?name=x", "name", _normal(), "name=x", session)
    assert result is None, f"SSTI 引擎在 500 错误页误报: {result}"
    _assert_bounded("/adv/err500", 16)
    _assert_timebound(t0, 20)


# ============================================================
# 2) WAF 拦截（403 固定页，不回显输入）：不得误报
# ============================================================
@pytest.mark.asyncio
async def test_sqli_no_fp_on_waf_block_page(adv_base, session):
    eng = SQLiEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/waf?id=x", "id", _normal(), "id=x", session)
    assert result is None, f"SQLi 引擎在 WAF 拦截页误报: {result}"
    _assert_bounded("/adv/waf", 12)
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_xss_no_fp_on_waf_block_page(adv_base, session):
    """WAF 页不回显 payload —— XSS 引擎必须无证据即放行（None），不得凭"页面含 403"乱报。"""
    eng = XSSEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/waf?q=x", "q", _normal(), "q=x", session)
    assert result is None, f"XSS 引擎在 WAF 拦截页误报: {result}"
    _assert_bounded("/adv/waf", 12)
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_lfi_no_fp_on_waf_block_page(adv_base, session):
    eng = LFIEngine()
    t0 = time.monotonic()
    result = await eng.check(f"{adv_base}/adv/waf?file=x", "file", _normal(), "file=x", session)
    assert result is None, f"LFI 引擎在 WAF 拦截页误报: {result}"
    _assert_bounded("/adv/waf", 12)
    _assert_timebound(t0, 20)


# ============================================================
# 3) 超时（服务端 3s，客户端 0.8s）：fail-closed，不挂
# ============================================================
@pytest.mark.asyncio
async def test_sqli_fail_closed_on_slow_target(adv_base, short_session, monkeypatch):
    # 引擎内部走 _timeout_for_url(settings.timeout=30s)，monkeypatch 单例属性不生效；
    # 直接强制短超时，让慢端点（sleep 1s）真正触发 status=0 的 fail-closed 路径。
    monkeypatch.setattr("vulnclaw.core.utils._timeout_for_url", lambda url, base=0: 0.2)
    eng = SQLiEngine()
    eng.payloads = eng.payloads[:2]  # 限制超时窗口下的请求轮数
    t0 = time.monotonic()
    result = await eng.check(
        f"{adv_base}/adv/slow?id=x", "id", _normal(), "id=x", short_session
    )
    assert result is None, f"SQLi 引擎在超时目标误报: {result}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_cmdi_fail_closed_on_slow_target(adv_base, short_session, monkeypatch):
    monkeypatch.setattr("vulnclaw.core.utils._timeout_for_url", lambda url, base=0: 0.2)
    eng = CMDIEngine()
    eng.payloads = eng.payloads[:2]
    t0 = time.monotonic()
    result = await eng.check(
        f"{adv_base}/adv/slow?cmd=x", "cmd", _normal(), "cmd=x", short_session
    )
    assert result is None, f"CMDI 引擎在超时目标误报: {result}"
    _assert_timebound(t0, 30)


# ============================================================
# 4) 重定向（同站安全跳转 / 无限循环）：不误报、不失控
# ============================================================
@pytest.mark.asyncio
async def test_xss_no_fp_on_same_site_redirect(adv_base, session):
    """同站 302 → 安全页：无回显，XSS 引擎不得报。"""
    eng = XSSEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{adv_base}/redir-safe?q=test", "q", _normal(), "q=test", session
    )
    assert result is None, f"XSS 引擎在安全重定向目标误报: {result}"
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_engine_survives_redirect_loop(adv_base, session):
    """无限重定向循环：调用必须完成（有界请求/耗时），不得挂死。"""
    eng = SQLiEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{adv_base}/redir-loop?id=x", "id", _normal(), "id=x", session
    )
    assert result is None or isinstance(result, dict)
    _assert_bounded("/redir-loop", 140)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_open_redirect_no_fp_on_same_site_redirect(adv_base, session):
    """同站 302：开放重定向引擎不得把它判成"开放重定向"（目标域名未越出本站）。"""
    eng = OpenRedirectEngine()
    t0 = time.monotonic()
    try:
        result = await eng.check(
            f"{adv_base}/redir-safe?next=/ok", "next", _normal(), "next=/ok", session
        )
    except TypeError:
        # 若该引擎无参数级 check 签名（走 scan 入口），改走 scan 断言
        findings = await eng.scan(f"{adv_base}/redir-safe", session)
        result = findings[0] if findings else None
    if result is not None:
        location = str(result.get("evidence") or "") + str(result.get("payload") or "")
        assert "external-evil" not in location
    _assert_timebound(t0, 25)


# ============================================================
# 5) 基线本身异常：SSRF 引擎在 500 基线下的行为
# ============================================================
@pytest.mark.asyncio
async def test_ssrf_fail_closed_on_error_baseline(adv_base, session):
    eng = SSRFEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    result = await eng.check(
        f"{adv_base}/adv/err500?url=https%3A%2F%2Fexample.com", "url",
        _normal(), "url=https%3A%2F%2Fexample.com", session,
    )
    assert result is None, f"SSRF 引擎在 500 基线下误报: {result}"
    _assert_bounded("/adv/err500", 14)
    _assert_timebound(t0, 30)


# ============================================================
# 6) L4 对抗覆盖增强（P1 引擎 + P0 补充）
#    —— 对 P1（XSS/NoSQL/LDAP/JWT/CORS/GraphQL/OpenRedirect/HostHeader/WebSocket）
#       与 P0 引擎实施对抗响应（变形/编码/废弃/大响应）下的 FP / FN 双门禁。
#    FP 门禁 (a)：恶意载荷被 WAF/变形/截断/超长后，无真实证据 → 引擎不得误报。
#    FN 门禁 (b)：变形后仍存在的真实漏洞 → 引擎必须检出。
#    纯离线（aiohttp TestServer + mock session），无外网 / 无 Docker。
#    全部沿用本文件既有 fixture/monkeypatch 机制。
#    标注 xfail(strict=False) 的用例 = 暴露的真实引擎缺陷（勿通过改检测逻辑掩盖）。
# ============================================================
import base64  # noqa: E402  JWT 凭证构造（沿用既有 import 风格，置于节内）
import json as _json  # noqa: E402

# ---- 对抗响应体固定基线（供引擎作 normal_resp，避免长度启发式误触）----
_P1_TRUNC = (200, "OKOKOKOKOK", {})                       # 截断到 10 字节
_P1_HUGE = (200, "A" * (1024 * 1024), {})                 # 膨胀到 1MB 静态填充
_P1_WAF200_TEXT = (
    "<!DOCTYPE html><html><body><title>Access Denied</title>"
    "<!-- ModSecurity/3.0.14 --><h1>Request blocked by security policy</h1>"
    "<p>Your request was denied. Reference: 12345</p></body></html>"
)
_P1_WAF200 = (200, _P1_WAF200_TEXT, {"Server": "ModSecurity/3.0.14", "X-Sucuri-ID": "12345"})
# Unicode / 全角 "形似错误" 页：错误特征被全角化，真实 ASCII 指示符不存在 → 不得误报
_P1_UNI = (
    200,
    "ＭｏｎｇｏＥｒｒｏｒ ＬＤＡＰ Ｅｘｃｅｐｔｉｏｎ "
    "Ｓｅｒｖｅｒ ｇｅｎｅｒｉｃ ｐａｇｅ ｆｏｒ ｓａｎｉｔｉｚｅｄ ｉｎｐｕｔ",
    {},
)


def _b64u(data: str) -> str:
    return base64.urlsafe_b64encode(data.encode("utf-8")).rstrip(b"=").decode("ascii")


def _jwt_alg_none_token() -> str:
    """alg:none 的 3 段 JWT（离线构造，无需签名库）。JWT 引擎据此判 Critical。"""
    hdr = _b64u(_json.dumps({"alg": "none", "typ": "JWT"}))
    pay = _b64u(_json.dumps({"sub": "1", "admin": True, "role": "admin"}))
    return f"{hdr}.{pay}."


_P1_JWT = (200, "<html><body>token:" + _jwt_alg_none_token() + "</body></html>", {})


def _build_p1_app():
    """P1 对抗靶场：同一端点即"基线画面"，攻击/基线一致 → 长度启发式不误触。"""

    async def _ok(request):
        return web.Response(text="<html><body><h1>OK</h1><p>static</p></body></html>")

    async def _trunc(request):
        """变形：截断响应体到 10 字节（无反射 / 无错误特征）。"""
        return web.Response(body=b"OK" * 5, content_type="text/html")

    async def _blob(request):
        """变形：膨胀到 1MB 的纯静态填充体（无反射、无漏洞特征）。"""
        return web.Response(text="A" * (1024 * 1024), content_type="text/html")

    async def _waf200(request):
        """变形：200 + 内置 ModSecurity 指纹模板，但不回显任何输入。"""
        return web.Response(
            text=_P1_WAF200_TEXT,
            headers={"Server": "ModSecurity/3.0.14", "X-Sucuri-ID": "12345"},
            status=200,
        )

    async def _uni(request):
        """变形：Unicode/全角形似错误文本，但非真实 ASCII 指示符 → 拒绝误报。"""
        return web.Response(text=_P1_UNI[1], content_type="text/html")

    async def _xss_echo(request):
        """真实反射型 XSS（已知漏洞端），用于 FN 门禁基线。"""
        q = request.query.get("q", "")
        return web.Response(text=f"<html><body><h1>Search</h1><div>{q}</div></body></html>")

    async def _nosql(request):
        """真实 NoSQL 注入点（按参数名取，与参数顺序无关）。"""
        q = request.query.get("q", "")
        if any(tok in q for tok in ("$", "{", "}", "[", "]", "(", ")", "'", '"', "||", "==")):
            return web.Response(text="MongoError: Cannot apply $gt operator to field", content_type="application/json")
        return web.Response(text='{"ok":true}', content_type="application/json")

    async def _nosql_waf(request):
        """真实 NoSQL 报错被塞进 ModSecurity 带外 200 页（FN 门禁·真实缺陷候选）。"""
        return web.Response(
            text=_P1_WAF200_TEXT + "\nMongoError: Cannot apply $gt operator to field",
            headers={"Server": "ModSecurity/3.0.14"}, status=200,
        )

    async def _ldap(request):
        """真实 LDAP 注入点。"""
        u = request.query.get("user", "")
        if any(c in u for c in "*()|&\\"):
            return web.Response(text="LDAPException: invalid search filter syntax")
        return web.Response(text="<html><body><h1>Login</h1><p>welcome</p></body></html>")

    async def _ldap_waf(request):
        """真实 LDAP 报错被塞进 ModSecurity 200 页（FN 门禁·真实缺陷候选）。"""
        return web.Response(
            text=_P1_WAF200_TEXT + "\nLDAPException: invalid search filter syntax",
            headers={"Server": "ModSecurity/3.0.14"}, status=200,
        )

    async def _redir_vuln(request):
        """开放重定向：Location 回显解码后的 next（参数顺序无关）。"""
        nxt = request.query.get("next", "")
        if nxt:
            return web.Response(status=302, headers={"Location": nxt}, text="")
        return web.Response(text="<html><body><h1>Home</h1></body></html>")

    async def _graphql(request):
        """真实 GraphQL 端点（内省返回 __typename）。"""
        return web.Response(text='{"data":{"__typename":"Query"}}', content_type="application/json")

    async def _cors_unsafe(request):
        """真实 CORS 通配（ACAO:* 端点），FN 门禁。"""
        return web.Response(
            text="<html><body><h1>CORS</h1></body></html>",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    async def _static_host(request):
        """不反射 Host 的静态页（HostHeader FP）。"""
        return web.Response(text="<html><body><h1>OK</h1><p>static host</p></body></html>")

    app = web.Application(middlewares=[_adv_hit_counter])
    app.router.add_get("/ok", _ok)
    app.router.add_get("/p1/trunc", _trunc)
    app.router.add_get("/p1/blob", _blob)
    app.router.add_get("/p1/waf200", _waf200)
    app.router.add_get("/p1/uni", _uni)
    app.router.add_get("/p1/xss-echo", _xss_echo)
    app.router.add_get("/p1/nosql", _nosql)
    app.router.add_get("/p1/nosql-waf", _nosql_waf)
    app.router.add_get("/p1/ldap", _ldap)
    app.router.add_get("/p1/ldap-waf", _ldap_waf)
    app.router.add_get("/p1/redir-vuln", _redir_vuln)
    app.router.add_get("/p1/graphql", _graphql)
    app.router.add_get("/p1/cors-unsafe", _cors_unsafe)
    app.router.add_get("/p1/static-host", _static_host)
    app.router.add_post("/p1/graphql", _graphql)
    return app


@pytest_asyncio.fixture
async def p1_base():
    _ADV_HITS.clear()
    server = TestServer(_build_p1_app())
    await server.start_server()
    base = f"http://127.0.0.1:{server.port}"
    try:
        yield base
    finally:
        await server.close()


# ============================================================
# 6.1) L4-FP 门禁：截断 / 超长 / WAF变形200 / Unicode全角 → 无证据不得误报
# ============================================================
@pytest.mark.asyncio
async def test_xss_no_fp_on_truncated_10b(p1_base, session):
    """(a) 截断响应(10B)：XSS 无反射、长度<100 不触发可疑 → fail-closed。"""
    eng = XSSEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/trunc?q=x", "q", _P1_TRUNC, "q=x", session, is_static=True)
    assert r is None, f"XSS 在 10B 截断响应误报: {r}"
    _assert_bounded("/p1/trunc", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_xss_no_fp_on_1mb_padding(p1_base, session):
    """(a) 1MB 静态填充：无反射 + 基线同构 → 长度启发不误触，且不崩。"""
    eng = XSSEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/blob?q=x", "q", _P1_HUGE, "q=x", session, is_static=True)
    assert r is None, f"XSS 在 1MB 填充误报: {r}"
    _assert_bounded("/p1/blob", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_nosql_no_fp_on_truncated_10b(p1_base, session):
    """(a) 截断响应：NoSQL 无错误特征、基线同构 → 不误报。"""
    eng = NoSQLEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/trunc?q=x", "q", _P1_TRUNC, "q=x", session, is_static=True)
    assert r is None, f"NoSQL 在 10B 截断响应误报: {r}"
    _assert_bounded("/p1/trunc", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_nosql_no_fp_on_1mb_padding(p1_base, session):
    """(a) 1MB 填充：NoSQL 无错误、基线同构 → 不误报。"""
    eng = NoSQLEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/blob?q=x", "q", _P1_HUGE, "q=x", session, is_static=True)
    assert r is None, f"NoSQL 在 1MB 填充误报: {r}"
    _assert_bounded("/p1/blob", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_nosql_no_fp_on_waf200_block_template(p1_base, session):
    """(a) WAF变形(200+ModSecurity模板，无回显)：NoSQL 走 WAF 分流 → 不误报。"""
    eng = NoSQLEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/waf200?q=x", "q", _P1_WAF200, "q=x", session, is_static=True)
    assert r is None, f"NoSQL 在 ModSecurity 200 模板误报: {r}"
    _assert_bounded("/p1/waf200", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ldap_no_fp_on_truncated_10b(p1_base, session):
    """(a) 截断响应：LDAP 无错误特征、基线同构 → 不误报。"""
    eng = LDAPEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/trunc?user=x", "user", _P1_TRUNC, "user=x", session, is_static=True)
    assert r is None, f"LDAP 在 10B 截断响应误报: {r}"
    _assert_bounded("/p1/trunc", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ldap_no_fp_on_1mb_padding(p1_base, session):
    """(a) 1MB 填充：LDAP 无错误、基线同构 → 不误报。"""
    eng = LDAPEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/blob?user=x", "user", _P1_HUGE, "user=x", session, is_static=True)
    assert r is None, f"LDAP 在 1MB 填充误报: {r}"
    _assert_bounded("/p1/blob", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_xss_no_fp_on_fullwidth_lookalike(p1_base, session):
    """(a) Unicode/全角形似错误页：XSS 无反射 → 不误报。"""
    eng = XSSEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/uni?q=x", "q", _P1_UNI, "q=x", session, is_static=True)
    assert r is None, f"XSS 在全角形似页误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ldap_no_fp_on_fullwidth_lookalike(p1_base, session):
    """(a) Unicode/全角形似 "LDAPException"：真实 ASCII 指示符缺失 → 不误报。"""
    eng = LDAPEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/uni?user=x", "user", _P1_UNI, "user=x", session, is_static=True)
    assert r is None, f"LDAP 在全角形似错误页误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ldap_no_fp_on_waf200_block_template(p1_base, session):
    """(a) WAF变形(200+ModSecurity模板)：LDAP 无错误特征、非长度异常 → 不误报。"""
    eng = LDAPEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/waf200?user=x", "user", _P1_WAF200, "user=x", session, is_static=True)
    assert r is None, f"LDAP 在 ModSecurity 200 模板误报: {r}"
    _assert_bounded("/p1/waf200", 60)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_jwt_no_fp_on_waf_page(p1_base, session):
    """(a) WAF变形页：无任何 JWT 凭证 → JWT 引擎不得凭近似文本误报。"""
    eng = JWTEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/waf200", "x", _P1_WAF200, "", session)
    assert r is None, f"JWT 引擎在无 token 页误报: {r}"
    _assert_bounded("/p1/waf200", 4)
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_cors_no_fp_on_safe_page(p1_base, session):
    """(a) 无 ACAO 头的安全页：CORS 端点发现不得误报。"""
    eng = CORSEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/static-host", "x", _normal(), "", session)
    assert r is None, f"CORS 引擎在无 CORS 头页面误报: {r}"
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_graphql_no_fp_on_non_endpoint(p1_base, session):
    """(a) 非 GraphQL 端点（路径不匹配 + POST 无 __typename）：不误报。"""
    eng = GraphQLEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/static-host", "x", _normal(), "", session)
    assert r is None, f"GraphQL 引擎在非端点误报: {r}"
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_open_redirect_no_fp_on_safe_page(p1_base, session):
    """(a) 安全页（无 Location 头）：开放重定向不得误报。"""
    eng = OpenRedirectEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/static-host?next=/home", "next", _normal(), "next=/home", session)
    assert r is None, f"OpenRedirect 在无 Location 头页面误报: {r}"
    _assert_timebound(t0, 25)


@pytest.mark.asyncio
async def test_ws_fail_closed_no_ws_endpoint(p1_base, session):
    """(a) 目标无 WebSocket 端点：WS 引擎始终 fail-closed，不产生任何告警。"""
    from vulnclaw.engines.websocket_security import WebSocketSecurityEngine
    eng = WebSocketSecurityEngine()
    t0 = time.monotonic()
    findings = await eng.scan(f"{p1_base}/p1/static-host", session)
    assert not findings, f"WebSocket 引擎在无 WS 端点上误报: {findings}"
    _assert_timebound(t0, 40)


@pytest.mark.asyncio
async def test_host_header_no_fp_on_nonreflective(p1_base, session):
    """(a) 不反射 Host 的安全页：Host 头注入不得误报（缩降探测规模防慢测）。"""
    eng = HostHeaderEngine()
    eng.MALICIOUS_HOSTS = ["evil.com"]
    eng.VIRTUAL_HOSTS = []
    t0 = time.monotonic()
    findings = await eng.scan(f"{p1_base}/p1/static-host", session)
    assert not findings, f"HostHeader 引擎在非反射端点误报: {findings}"
    _assert_timebound(t0, 40)


# ============================================================
# 6.2) L4-FN 门禁：变形 / 顺序 / 编码下，真实漏洞必须检出
# ============================================================
@pytest.mark.asyncio
async def test_xss_detected_on_faithful_reflection(p1_base, session):
    """(b) 真实反射：即使被搜索框原样回显，XSS 必须检出（FN 基线）。"""
    eng = XSSEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/xss-echo?q=hello", "q", _normal(), "q=hello", session)
    assert r, f"XSS 未检出真实反射型漏洞（FN）: {r}"
    assert "xss" in str(r.get("type", "")).lower()
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_nosql_detected_under_param_reorder(p1_base, session):
    """(b) 参数顺序调换（目标参数非首个）：NoSQL 仍按参数名检出。"""
    eng = NoSQLEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    # parsed_query 里 q 不是第一个参数 → 检验引擎不依赖"参数位置"
    r = await eng.check("a=1&b=2&q=1", "q", _normal(), "a=1&b=2&q=1", session)
    # 直接打真实端点
    r2 = await eng.check(f"{p1_base}/p1/nosql?a=1&q=1", "q", _normal(), "a=1&q=1", session)
    assert r2, f"NoSQL 未检出真实注入（FN, 参数顺序）: {r2}"
    assert "nosql" in str(r2.get("type", "")).lower()
    _assert_bounded("/p1/nosql", 40)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ldap_detected_under_url_encoding(p1_base, session):
    """(b) URL 编码负载经引擎 build_attack_url 落地后，LDAP 仍检出（FN, 编码路径）。"""
    eng = LDAPEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/ldap?user=admin", "user", _normal(), "user=admin", session)
    assert r, f"LDAP 未检出真实注入（FN）: {r}"
    assert "ldap" in str(r.get("type", "")).lower()
    _assert_bounded("/p1/ldap", 40)
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_jwt_detected_alg_none(p1_base, session):
    """(b) 真实的 alg:none 弱 JWT 出现在响应体 → JWT 引擎必须检出（FN）。"""
    eng = JWTEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/jwt", "x", _P1_JWT, "", session)
    assert r, f"JWT 引擎未检出 alg:none 弱凭证（FN）: {r}"
    _assert_timebound(t0, 20)


# ============================================================
# 6.3) L4-FP 增强：P0 引擎（CMDi/LFI/SQLi/SSTI/SSRF）在变形/安全页下无 FP
#      复用既有 P1 靶场端点（static-host/trunc/blob/waf200/uni），不新增端点。
# ============================================================
@pytest.mark.asyncio
async def test_cmdi_no_fp_on_static_host(p1_base, session):
    """(a) 安全静态页（无命令行特征）：CMDi 不得误报。"""
    eng = CMDIEngine()
    t0 = time.monotonic()
    # 基线必须与本端点真实响应同构（与 /p1/blob、/p1/trunc 用例一致）：
    # 传通用 `_normal()`（400+ 字节合成体）去比 50 字节的 static-host 页，
    # 长度差异会被"响应长度异常"规则判成疑似 → 变成测试夹具自身制造的误报。
    r = await eng.check(
        f"{p1_base}/p1/static-host?cmd=x", "cmd",
        (200, "<html><body><h1>OK</h1><p>static host</p></body></html>", {}),
        "cmd=x", session,
    )
    assert r is None, f"CMDi 在安全页误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_cmdi_no_fp_on_1mb_padding(p1_base, session):
    """(a) 1MB 静态填充：CMDi 无错误特征、基线同构 → 不误报。"""
    eng = CMDIEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/blob?cmd=x", "cmd", _P1_HUGE, "cmd=x", session, is_static=True)
    assert r is None, f"CMDi 在 1MB 填充误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_lfi_no_fp_on_waf200_block_template(p1_base, session):
    """(a) WAF变形(200+ModSecurity模板)：LFI 无错误特征、非长度异常 → 不误报。"""
    eng = LFIEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/waf200?file=x", "file", _P1_WAF200, "file=x", session, is_static=True)
    assert r is None, f"LFI 在 ModSecurity 200 模板误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_sqli_no_fp_on_fullwidth_lookalike(p1_base, session):
    """(a) Unicode/全角形似错误页：SQLi 无反射 → 不误报。"""
    eng = SQLiEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/uni?id=x", "id", _P1_UNI, "id=x", session, is_static=True)
    assert r is None, f"SQLi 在全角形似页误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ssti_no_fp_on_truncated_10b(p1_base, session):
    """(a) 截断响应(10B)：SSTI 无反射、长度<100 不触发可疑 → fail-closed。"""
    eng = SSTIEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/trunc?name=x", "name", _P1_TRUNC, "name=x", session, is_static=True)
    assert r is None, f"SSTI 在 10B 截断响应误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ssrf_no_fp_on_static_host(p1_base, session):
    """(a) 安全静态页（外链 example.com，无内网回显）：SSRF 不得误报。"""
    eng = SSRFEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    r = await eng.check(
        f"{p1_base}/p1/static-host?url=http://169.254.169.254/latest/meta-data", "url",
        _normal(), "url=http://169.254.169.254/latest/meta-data", session,
    )
    assert r is None, f"SSRF 在安全页误报: {r}"
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
async def test_cors_detected_wildcard(p1_base, session):
    """(b) 真实 ACMA:* 端点 → CORS 引擎必须检出（FN）。"""
    eng = CORSEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/cors-unsafe", "x", _normal(), "", session)
    assert r, f"CORS 引擎未检出通配端点（FN）: {r}"
    assert r.get("is_cors_endpoint") is True
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_graphql_detected_endpoint(p1_base, session):
    """(b) 真实 GraphQL 端点 → GraphQL 引擎必须检出（FN）。"""
    eng = GraphQLEngine()
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/graphql", "x", _normal(), "", session)
    assert r, f"GraphQL 引擎未检出端点（FN）: {r}"
    _assert_timebound(t0, 20)


@pytest.mark.asyncio
async def test_open_redirect_detected_encoded_order(p1_base, session):
    """(b) Location 回显解码后的 next、且 next 非首参：开放重定向必须检出（FN）。"""
    eng = OpenRedirectEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/redir-vuln?a=1&next=/home", "next", _normal(), "a=1&next=/home", session)
    assert r, f"OpenRedirect 未检出真实重定向（FN, 编码/顺序）: {r}"
    assert "重定向" in str(r.get("type", ""))
    _assert_bounded("/p1/redir-vuln", 40)
    _assert_timebound(t0, 25)


# ---- 暴露真实引擎缺陷的用例（勿通过改检测逻辑掩盖，标注 xfail 并说明）----
@pytest.mark.asyncio
@pytest.mark.xfail(strict=False, reason="真实缺陷：ModSecurity 指纹优先于真实 NoSQL 注入证据，detect_waf 命中后绕过未果即 return，导致带外出的真实 MongoError 被抑制（FN）。")
async def test_nosql_contaminated_waf_template_still_detected(p1_base, session):
    """(b) NoSQL 报错被塞进 ModSecurity 指纹 200 页仍须检出；当前引擎疑似 FN。"""
    eng = NoSQLEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/nosql-waf?q=1", "q", _P1_WAF200, "q=1", session, is_static=True)
    assert r, f"NoSQL 在 ModSecurity 装饰页漏检（疑似真实 FN）: {r}"
    assert "nosql" in str(r.get("type", "")).lower()
    _assert_timebound(t0, 30)


@pytest.mark.asyncio
@pytest.mark.xfail(strict=False, reason="真实缺陷：LDAP 真实报错被 ModSecurity 指纹压制，detect_waf→try_waf_bypass 未果后 return，导致 FN。")
async def test_ldap_contaminated_waf_template_still_detected(p1_base, session):
    """(b) LDAP 报错被塞进 ModSecurity 指纹 200 页仍须检出；当前引擎疑似 FN。"""
    eng = LDAPEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    r = await eng.check(f"{p1_base}/p1/ldap-waf?user=admin", "user", _P1_WAF200, "user=admin", session, is_static=True)
    assert r, f"LDAP 在 ModSecurity 装饰页漏检（疑似真实 FN）: {r}"
    assert "ldap" in str(r.get("type", "")).lower()
    _assert_timebound(t0, 30)
