"""引擎核心行为测试 + 本地靶场 Benchmark（不依赖外网 / 不依赖 AI）。

靶场 = 本地 aiohttp 服务，内置 4 个真实漏洞端点（XSS / SQLi / LFI / CMDI）
+ 1 个安全端点（输入净化）。

覆盖三件事：
  1. 引擎装配完整性：>=25 个引擎、name 唯一、可反查；
  2. 检出率（true positive）：核心攻击引擎在漏洞端点上必须产出 finding；
  3. 误报控制（false positive）：安全端点上不得产出 finding。

运行：python -m pytest tests/test_engines_core.py -v
"""
import re

import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

from vulnclaw.core.scanner import get_all_engines, get_engine_by_name


# ============================================================
# 本地靶场（真实行为的最小模拟，不调用任何外部工具）
# ============================================================
_SSTI_RE = re.compile(r"\{\{\s*(\d+)\s*\*\s*(\d+)\s*\}\}")


def _ssti_eval(text: str) -> str:
    m = _SSTI_RE.search(text)
    if m:
        return text.replace(m.group(0), str(int(m.group(1)) * int(m.group(2))))
    return text


def _build_lab_app():
    async def _index(request):
        return web.Response(text="<html><body><h1>VULNCLAW Lab</h1>" + "<p>default</p>" * 40 + "</body></html>")

    # 反射型 XSS：无过滤原样回显
    async def _xss(request):
        q = request.query.get("q", "")
        return web.Response(text=f"<html><body><h1>Search</h1><div>{q}</div><p>result page</p></body></html>")

    # 报错型 SQLi：单引号触发 SQL 语法错误页
    async def _search(request):
        i = request.query.get("id", "")
        if "'" in i:
            return web.Response(
                text=f"<html><body><h1>Error</h1><pre>SQL syntax error near '{i}' at line 1</pre></body></html>"
            )
        return web.Response(
            text="<html><body><h1>Results</h1>" + f"<p>id={i}</p>" + "<p>row</p>" * 50 + "</body></html>"
        )

    # LFI：读取 /etc/passwd 返回真实内容特征
    async def _download(request):
        f = request.query.get("file", "")
        if "etc/passwd" in f:
            return web.Response(
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            )
        return web.Response(text="<html><body><h1>404 Not Found</h1></body></html>", status=404)

    # CMDI：命令执行回显（uid= 特征）
    async def _exec(request):
        c = request.query.get("cmd", "")
        if "id" in c or "whoami" in c:
            return web.Response(text="uid=0(root) gid=0(root) groups=0(root)\n")
        return web.Response(text="<html><body><h1>Command</h1><p>no output</p></body></html>")

    # 安全端点：模拟 WAF / 输出净化——任何输入都不进入响应（返回固定页面）
    async def _safe(request):
        return web.Response(
            text="<html><body><h1>Safe</h1><div>input blocked by sanitizer</div><p>ok</p></body></html>"
        )

    # SSTI：模板表达式被服务端求值后回显（{{7*7}} -> 49）
    async def _ssti(request):
        name = request.query.get("name", "")
        out = _ssti_eval(name)
        return web.Response(text=f"<html><body><h1>SSTI</h1><div>{out}</div></body></html>")

    # NoSQL：出现 $ / { } [ ] 等运算符特征时回显 Mongo 错误
    async def _nosql(request):
        q = request.query.get("q", "")
        if any(tok in q for tok in ("$", "{", "}", "[", "]", "(", ")", "'", '"', "||", "==")):
            return web.Response(text="MongoError: Cannot apply $gt operator to field (SyntaxError)")
        return web.Response(text="<html><body><h1>Results</h1><p>ok</p></body></html>")

    # LDAP：出现 LDAP 过滤特殊字符时回显 LDAP 异常
    async def _ldap(request):
        u = request.query.get("user", "")
        if any(c in u for c in "*()|&\\"):
            return web.Response(text="LDAPException: invalid search filter syntax")
        return web.Response(text="<html><body><h1>Login</h1><p>welcome</p></body></html>")

    # 开放重定向：next 参数原样进入 Location 头
    async def _redirect(request):
        nxt = request.query.get("next", "")
        if nxt:
            return web.Response(status=302, headers={"Location": nxt}, text="")
        return web.Response(text="<html><body><h1>Home</h1></body></html>")

    # CORS：返回通配符 ACAO 头（CORS 端点）
    async def _cors(request):
        return web.Response(
            text="<html><body><h1>CORS</h1></body></html>",
            headers={"Access-Control-Allow-Origin": "*"},
        )

    # 反序列化：任意请求回显 Java 反序列化错误特征
    async def _deser(request):
        return web.Response(
            text="java.io.NotSerializableException: com.example.User at com.example.Deserializer.deserialize"
        )

    # 信息泄露：暴露 .env 敏感配置
    async def _dotenv(request):
        return web.Response(text="DB_PASSWORD=secret123\nAPI_KEY=ak-xxxx\n")

    app = web.Application()
    app.router.add_get("/", _index)
    app.router.add_get("/xss", _xss)
    app.router.add_get("/search", _search)
    app.router.add_get("/download", _download)
    app.router.add_get("/exec", _exec)
    app.router.add_get("/safe", _safe)
    app.router.add_get("/ssti", _ssti)
    app.router.add_get("/nosql", _nosql)
    app.router.add_get("/ldap", _ldap)
    app.router.add_get("/redirect", _redirect)
    app.router.add_get("/cors", _cors)
    app.router.add_get("/deser", _deser)
    app.router.add_get("/.env", _dotenv)
    return app


@pytest_asyncio.fixture
async def lab_base():
    app = _build_lab_app()
    server = TestServer(app)
    await server.start_server(host="127.0.0.1", port=None)
    try:
        yield f"http://127.0.0.1:{server.port}"
    finally:
        await server.close()


@pytest_asyncio.fixture
async def session():
    async with ClientSession() as s:
        yield s


SAFE_PAGE = "<html><body><h1>Safe</h1><div>input blocked by sanitizer</div><p>ok</p></body></html>"


def _normal_resp(text=SAFE_PAGE):
    return (200, text, {})


# ============================================================
# 1. 引擎装配完整性
# ============================================================
def test_engine_discovery_integrity():
    engines = get_all_engines()
    assert len(engines) >= 25, f"引擎数量过少: {len(engines)}"
    names = [e.name for e in engines]
    assert len(names) == len(set(names)), "存在重复引擎 name"
    for e in engines[:10]:
        assert get_engine_by_name(e.name) is not None, f"get_engine_by_name 无法反查: {e.name}"


# ============================================================
# 2. 检出（true positive）
# ============================================================
@pytest.mark.asyncio
async def test_xss_detected(lab_base, session):
    from vulnclaw.engines.web_engines import XSSEngine

    eng = XSSEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/xss?q=hello"
    result = await eng.check(url, "q", _normal_resp(), "q=hello", session)
    assert result, "XSS 引擎未检出反射型 XSS"
    assert "xss" in str(result.get("type", "")).lower(), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_sqli_detected_error_based(lab_base, session):
    from vulnclaw.engines.web_engines import SQLiEngine

    eng = SQLiEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/search?id=1"
    result = await eng.check(url, "id", _normal_resp(), "id=1", session)
    assert result, "SQLi 引擎未检出报错注入"
    assert "sql" in str(result.get("type", "")).lower(), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_lfi_detected(lab_base, session):
    from vulnclaw.engines.web_engines import LFIEngine

    eng = LFIEngine()
    # Windows 上 get_payloads 会把 windows payload 前置，加大额度覆盖到 linux payload
    eng.max_payloads = 80
    url = f"{lab_base}/download?file=x"
    result = await eng.check(url, "file", _normal_resp(), "file=x", session)
    assert result, "LFI 引擎未检出文件读取"
    assert result.get("file_read") or "lfi" in str(result.get("type", "")).lower(), (
        f"finding 异常: {result}"
    )


@pytest.mark.asyncio
async def test_cmdi_detected(lab_base, session):
    from vulnclaw.engines.web_engines import CMDIEngine

    eng = CMDIEngine()
    eng.max_payloads = 12
    url = f"{lab_base}/exec?cmd=x"
    result = await eng.check(url, "cmd", _normal_resp(), "cmd=x", session)
    assert result, "CMDI 引擎未检出命令执行"
    assert result.get("cmd_exec") or "命令注入" in str(result.get("type", "")) or "cmdi" in str(
        result.get("type", "")
    ).lower(), f"finding 异常: {result}"


# ============================================================
# 3. 误报控制（false positive）
# ============================================================
@pytest.mark.asyncio
async def test_xss_no_false_positive_on_sanitized(lab_base, session):
    from vulnclaw.engines.web_engines import XSSEngine

    eng = XSSEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/safe?q=hello"
    result = await eng.check(url, "q", _normal_resp(), "q=hello", session)
    assert result is None, f"XSS 引擎在净化端点上误报: {result}"


@pytest.mark.asyncio
async def test_sqli_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.web_engines import SQLiEngine

    eng = SQLiEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/safe?q=hello"
    result = await eng.check(url, "q", _normal_resp(), "q=hello", session)
    assert result is None, f"SQLi 引擎在干净端点上误报: {result}"


# ============================================================
# 4. 更多引擎检出（true positive）—— 直接调用各引擎 check()/scan()
# ============================================================
@pytest.mark.asyncio
async def test_ssti_detected(lab_base, session):
    from vulnclaw.engines.web_engines import SSTIEngine

    eng = SSTIEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/ssti?name=hello"
    result = await eng.check(url, "name", _normal_resp(), "name=hello", session)
    assert result, "SSTI 引擎未检出模板注入"
    assert "ssti" in str(result.get("type", "")).lower(), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_nosql_detected(lab_base, session):
    from vulnclaw.engines.web_engines import NoSQLEngine

    eng = NoSQLEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/nosql?q=1"
    result = await eng.check(url, "q", _normal_resp(), "q=1", session)
    assert result, "NoSQL 引擎未检出注入"
    assert "nosql" in str(result.get("type", "")).lower(), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_ldap_detected(lab_base, session):
    from vulnclaw.engines.input_engines import LDAPEngine

    eng = LDAPEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/ldap?user=admin"
    result = await eng.check(url, "user", _normal_resp(), "user=admin", session)
    assert result, "LDAP 引擎未检出注入"
    assert "ldap" in str(result.get("type", "")).lower(), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_open_redirect_detected(lab_base, session):
    from vulnclaw.engines.http_engines import OpenRedirectEngine

    eng = OpenRedirectEngine()
    eng.max_payloads = 12
    url = f"{lab_base}/redirect?next=home"
    result = await eng.check(url, "next", _normal_resp(), "next=home", session)
    assert result, "OpenRedirect 引擎未检出重定向"
    assert "重定向" in str(result.get("type", "")), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_cors_detected(lab_base, session):
    from vulnclaw.engines.input_engines import CORSEngine

    eng = CORSEngine()
    url = f"{lab_base}/cors"
    result = await eng.check(url, "x", _normal_resp(), "", session)
    assert result, "CORS 引擎未检出端点"
    assert result.get("is_cors_endpoint") is True, f"非 CORS 端点: {result}"


@pytest.mark.asyncio
async def test_deserialization_detected(lab_base, session):
    from vulnclaw.engines.deserialization import DeserializationEngine

    eng = DeserializationEngine()
    url = f"{lab_base}/deser?data=x"
    result = await eng.check(url, "data", _normal_resp(), "data=x", session)
    assert result, "反序列化引擎未检出"
    assert "反序列化" in str(result.get("type", "")), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_info_leak_detected(lab_base, session):
    from vulnclaw.engines.input_engines import InfoLeakEngine

    eng = InfoLeakEngine()
    findings = await eng.scan(lab_base, session, max_paths=150)
    assert findings, "信息泄露引擎未检出 .env"
    assert any("env" in str(f.get("type", "")).lower() for f in findings), f"未找到 .env 泄露: {findings}"


@pytest.mark.asyncio
async def test_security_headers_detected(lab_base, session):
    from vulnclaw.engines.http_engines import SecurityHeadersEngine

    eng = SecurityHeadersEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "安全头引擎未检出缺失安全头"


# ============================================================
# 5. 更多引擎误报控制（false positive）
# ============================================================
@pytest.mark.asyncio
async def test_ssti_no_false_positive_on_sanitized(lab_base, session):
    from vulnclaw.engines.web_engines import SSTIEngine

    eng = SSTIEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/safe?name=hello"
    result = await eng.check(url, "name", _normal_resp(), "name=hello", session)
    assert result is None, f"SSTI 引擎在净化端点上误报: {result}"


@pytest.mark.asyncio
async def test_open_redirect_no_false_positive_on_static(lab_base, session):
    from vulnclaw.engines.http_engines import OpenRedirectEngine

    eng = OpenRedirectEngine()
    eng.max_payloads = 12
    url = f"{lab_base}/safe?next=home"
    result = await eng.check(url, "next", _normal_resp(), "next=home", session)
    assert result is None, f"OpenRedirect 引擎在静态端点上误报: {result}"


@pytest.mark.asyncio
async def test_nosql_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.web_engines import NoSQLEngine

    eng = NoSQLEngine()
    eng.max_payloads = 8
    url = f"{lab_base}/safe?q=1"
    result = await eng.check(url, "q", _normal_resp(), "q=1", session)
    assert result is None, f"NoSQL 引擎在干净端点上误报: {result}"
