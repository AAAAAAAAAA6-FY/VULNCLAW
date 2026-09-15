# -*- coding: utf-8 -*-
"""工作流11：跨版本回归实验室（三档版本断言矩阵）

对"版本判定类"引擎建立 易受/修复/边界 三档断言矩阵，防止引擎版本区间
逻辑回归时误报/漏报影响真实检测：

- 易受版本（vulnerable）：必须检出 TP（false negative 门禁）
- 修复版本（patched）：必须不检出（false positive 门禁）
- 边界版本（boundary）：按规格断言（区间端点两侧，避免 off-by-one）

复刻 tests/test_engines_core.py 的 lab 模式：内存 aiohttp app + TestServer +
真实引擎调用，不依赖 Docker/Vulhub，可在任意环境确定性回归。
"""
import pytest
import pytest_asyncio
from aiohttp import web

pytestmark = pytest.mark.asyncio

# ============================================================
# lab：三档版本靶场（一台服务按路径提供不同版本指纹）
# ============================================================
def _build_version_lab():
    app = web.Application()

    async def _apache_vuln(request):
        return web.Response(text="ok", headers={"Server": "Apache/2.4.49"})

    async def _apache_boundary(request):
        return web.Response(text="ok", headers={"Server": "Apache/2.4.50"})

    async def _apache_patched(request):
        return web.Response(text="ok", headers={"Server": "Apache/2.4.52"})

    async def _nginx_vuln(request):
        return web.Response(text="ok", headers={"Server": "nginx/1.18.0"})

    async def _nginx_patched(request):
        return web.Response(text="ok", headers={"Server": "nginx/1.21.0"})

    async def _php_vuln(request):
        return web.Response(text="ok", headers={"Server": "PHP/7.1.28"})

    async def _php_patched(request):
        return web.Response(text="ok", headers={"Server": "PHP/7.4.30"})

    async def _jetty_vuln(request):
        return web.Response(text="ok", headers={"Server": "Jetty/9.4.36.v20211214"})

    async def _jetty_patched(request):
        return web.Response(text="ok", headers={"Server": "Jetty/9.4.45.v20220203"})

    async def _jq_vuln(request):
        return web.Response(
            text='<html><body><script src="/static/jquery-3.5.0.min.js"></script></body></html>',
            content_type="text/html",
        )

    async def _jq_boundary(request):
        return web.Response(
            text='<html><body><script src="/static/jquery-3.4.1.min.js"></script></body></html>',
            content_type="text/html",
        )

    async def _jq_patched(request):
        return web.Response(
            text='<html><body><script src="/static/jquery-3.6.0.min.js"></script></body></html>',
            content_type="text/html",
        )

    async def _clean(request):
        return web.Response(
            text="<html><body>just content</body></html>", content_type="text/html",
            headers={"Server": "cloudflare"},
        )

    # ---- 扩展框架（引擎 BACKEND_RULES / FRAMEWORK_FINGERPRINTS 已支持）----
    async def _aspnet_vuln(request):
        return web.Response(text="ok", headers={"Server": "ASP.NET/4.8"})

    async def _aspnet_patched(request):
        return web.Response(text="ok", headers={"Server": "ASP.NET/4.8.1"})

    async def _openssl_vuln(request):
        return web.Response(text="ok", headers={"Server": "OpenSSL/1.0.1"})

    async def _openssl_patched(request):
        return web.Response(text="ok", headers={"Server": "OpenSSL/3.0.0"})

    async def _django_vuln(request):
        return web.Response(
            text='<html><body>django.core.exceptions.ImproperlyConfigured traceback here</body></html>'
        )

    async def _express_vuln(request):
        return web.Response(text="<html><body>powered by express</body></html>")

    for path, handler in (
        ("/apache/vuln", _apache_vuln),
        ("/apache/boundary", _apache_boundary),
        ("/apache/patched", _apache_patched),
        ("/nginx/vuln", _nginx_vuln),
        ("/nginx/patched", _nginx_patched),
        ("/php/vuln", _php_vuln),
        ("/php/patched", _php_patched),
        ("/jetty/vuln", _jetty_vuln),
        ("/jetty/patched", _jetty_patched),
        ("/jq/vuln", _jq_vuln),
        ("/jq/boundary", _jq_boundary),
        ("/jq/patched", _jq_patched),
        ("/clean", _clean),
        ("/aspnet/vuln", _aspnet_vuln),
        ("/aspnet/patched", _aspnet_patched),
        ("/openssl/vuln", _openssl_vuln),
        ("/openssl/patched", _openssl_patched),
        ("/django/vuln", _django_vuln),
        ("/express/vuln", _express_vuln),
    ):
        app.router.add_get(path, handler)

    return app


@pytest_asyncio.fixture
async def lab():
    app = _build_version_lab()
    from aiohttp.test_utils import TestServer

    server = TestServer(app)
    await server.start_server(host="127.0.0.1", port=None)
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    from aiohttp import ClientSession

    async with ClientSession() as s:
        yield s


async def _scan_backend(url: str, session) -> list:
    from vulnclaw.config.settings import settings as _st
    from vulnclaw.engines.logic_leak_engines_2 import BackendComponentFingerprintEngine

    old = _st.component_cve_check
    _st.component_cve_check = True
    try:
        eng = BackendComponentFingerprintEngine()
        return await eng.scan(url, session)
    finally:
        _st.component_cve_check = old


async def _scan_jslib(url: str, session) -> list:
    from vulnclaw.config.settings import settings as _st
    from vulnclaw.engines.logic_leak_engines_2 import JsLibraryCveEngine

    old = _st.component_cve_check
    _st.component_cve_check = True
    try:
        eng = JsLibraryCveEngine()
        return await eng.scan(url, session)
    finally:
        _st.component_cve_check = old


def _types(findings: list) -> list:
    return [f.get("type", "") for f in findings]


def _any_component(findings: list) -> bool:
    return any("组件漏洞" in t for t in _types(findings))


def _has_version(findings: list, marker: str) -> bool:
    """findings 里有版本指纹命中（type 自带组件+版本号）。"""
    return any(marker in t for t in _types(findings))


# ============================================================
# A0. 扩展框架（ASP.NET / OpenSSL 版本 CVE；Django / Express 框架指纹）
#     仅覆盖 BackendComponentFingerprintEngine 已支持的框架，避免编造版本区间。
# ============================================================
@pytest.mark.asyncio
async def test_aspnet_4_8_vulnerable_tp(lab, session):
    """ASP.NET 4.8 ∈ (4,0,0)-(4,8,0) → 必须检出（FN 门禁）。"""
    findings = await _scan_backend(f"{lab}/aspnet/vuln", session)
    assert any("ASP.NET" in t for t in _types(findings)), f"ASP.NET 4.8 未检出: {findings}"


@pytest.mark.asyncio
async def test_aspnet_patched_no_fp(lab, session):
    """ASP.NET 4.8.1 超出区间 → 不得检出（FP 门禁）。"""
    findings = await _scan_backend(f"{lab}/aspnet/patched", session)
    assert not any("ASP.NET" in t for t in _types(findings)), f"ASP.NET 4.8.1 误报: {findings}"


@pytest.mark.asyncio
async def test_openssl_1_0_1_vulnerable_tp(lab, session):
    """OpenSSL 1.0.1 ∈ (1,0,1)-(1,0,2) → 必须检出（FN 门禁）。"""
    findings = await _scan_backend(f"{lab}/openssl/vuln", session)
    assert any("OpenSSL" in t for t in _types(findings)), f"OpenSSL 1.0.1 未检出: {findings}"


@pytest.mark.asyncio
async def test_openssl_patched_no_fp(lab, session):
    """OpenSSL 3.0.0 超出区间 → 不得检出（FP 门禁）。"""
    findings = await _scan_backend(f"{lab}/openssl/patched", session)
    assert not any("OpenSSL" in t for t in _types(findings)), f"OpenSSL 3.0.0 误报: {findings}"


@pytest.mark.asyncio
async def test_django_framework_fingerprint(lab, session):
    """Django csrftoken 指纹 → 必须识别（Info 级，非 CVE 版本）。"""
    findings = await _scan_backend(f"{lab}/django/vuln", session)
    assert any("Django" in t for t in _types(findings)), f"Django 指纹未检出: {findings}"


@pytest.mark.asyncio
async def test_express_framework_fingerprint(lab, session):
    """Express 'powered by express' 指纹 → 必须识别。"""
    findings = await _scan_backend(f"{lab}/express/vuln", session)
    assert any("Express" in t for t in _types(findings)), f"Express 指纹未检出: {findings}"


# ============================================================
# A. Apache / CVE-2021-41773（2.4.49 <= v <= 2.4.50 易受）
# ============================================================
@pytest.mark.asyncio
async def test_apache_2_4_49_vulnerable_tp(lab, session):
    """易受版本 Apache/2.4.49 必须检出（FN 门禁）。"""
    findings = await _scan_backend(f"{lab}/apache/vuln", session)
    assert _has_version(findings, "2.4.49"), f"Apache 2.4.49 未检出: {findings}"


@pytest.mark.asyncio
async def test_apache_2_4_50_boundary_tp(lab, session):
    """边界版本 Apache/2.4.50（区间上端点）必须检出——防 off-by-one。"""
    findings = await _scan_backend(f"{lab}/apache/boundary", session)
    assert _has_version(findings, "2.4.50"), f"Apache 2.4.50 未检出: {findings}"


@pytest.mark.asyncio
async def test_apache_2_4_52_patched_fp(lab, session):
    """修复版本 Apache/2.4.52 不得检出（FP 门禁）。"""
    findings = await _scan_backend(f"{lab}/apache/patched", session)
    assert not _any_component(findings), f"Apache 2.4.52 误报: {findings}"


# ============================================================
# B. 其余后端组件（Nginx/PHP/Jetty）易受 vs 修复
# ============================================================
@pytest.mark.asyncio
async def test_nginx_1_18_0_vulnerable_tp(lab, session):
    """Nginx 1.18.0（CVE-2021-23017, 0.6.18~1.20.0）必须检出。"""
    findings = await _scan_backend(f"{lab}/nginx/vuln", session)
    assert _has_version(findings, "1.18.0"), f"Nginx 1.18.0 未检出: {findings}"


@pytest.mark.asyncio
async def test_nginx_1_21_0_patched_fp(lab, session):
    """Nginx 1.21.0（修复版）不得检出。"""
    findings = await _scan_backend(f"{lab}/nginx/patched", session)
    assert not _any_component(findings), f"Nginx 1.21.0 误报: {findings}"


@pytest.mark.asyncio
async def test_php_7_1_28_vulnerable_tp(lab, session):
    """PHP 7.1.28（CVE-2019-11043, 7.1.0~7.1.28 上端点）必须检出。"""
    findings = await _scan_backend(f"{lab}/php/vuln", session)
    assert _has_version(findings, "7.1.28"), f"PHP 7.1.28 未检出: {findings}"


@pytest.mark.asyncio
async def test_php_7_4_30_patched_fp(lab, session):
    """PHP 7.4.30（修复版）不得检出。"""
    findings = await _scan_backend(f"{lab}/php/patched", session)
    assert not _any_component(findings), f"PHP 7.4.30 误报: {findings}"


@pytest.mark.asyncio
async def test_jetty_vulnerable_vs_patched(lab, session):
    """Jetty 9.4.36 检出 / 9.4.45 不检出（CVE-2021-28164, 9.4.0~9.4.37）。"""
    vuln = await _scan_backend(f"{lab}/jetty/vuln", session)
    patched = await _scan_backend(f"{lab}/jetty/patched", session)
    assert _has_version(vuln, "9.4.36"), f"Jetty 9.4.36 未检出: {vuln}"
    assert not _any_component(patched), f"Jetty 9.4.45 误报: {patched}"


# ============================================================
# C. 前端组件（js_library_cve / jQuery CVE-2020-11022/23, <=3.5.0）
# ============================================================
@pytest.mark.asyncio
async def test_jquery_3_5_0_vulnerable_tp(lab, session):
    """jQuery 3.5.0（受影响区上端点）必须检出。"""
    findings = await _scan_jslib(f"{lab}/jq/vuln", session)
    assert _has_version(findings, "jQuery 3.5.0"), f"jQuery 3.5.0 未检出: {findings}"


@pytest.mark.asyncio
async def test_jquery_3_4_1_boundary_tp(lab, session):
    """jQuery 3.4.1（区间下界一侧）仍 ≤3.5.0 必须检出。"""
    findings = await _scan_jslib(f"{lab}/jq/boundary", session)
    assert _has_version(findings, "jQuery 3.4.1"), f"jQuery 3.4.1 未检出: {findings}"


@pytest.mark.asyncio
async def test_jquery_3_6_0_patched_fp(lab, session):
    """jQuery 3.6.0（修复版）不得检出（FP 门禁）。"""
    findings = await _scan_jslib(f"{lab}/jq/patched", session)
    assert not _any_component(findings), f"jQuery 3.6.0 误报: {findings}"


# ============================================================
# D. 安全端点：未版本化指纹不得报组件漏洞
# ============================================================
@pytest.mark.asyncio
async def test_clean_server_header_no_fp(lab, session):
    """Server: cloudflare（未版本化，不在 BACKEND_RULES）不得报后端组件。"""
    findings = await _scan_backend(f"{lab}/clean", session)
    assert not _any_component(findings), f"/clean 误报: {findings}"