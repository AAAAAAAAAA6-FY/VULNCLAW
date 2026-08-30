"""引擎核心行为测试 + 本地靶场 Benchmark（不依赖外网 / 不依赖 AI）。

靶场 = 本地 aiohttp 服务，内置 4 个真实漏洞端点（XSS / SQLi / LFI / CMDI）
+ 1 个安全端点（输入净化）。

覆盖三件事：
  1. 引擎装配完整性：>=25 个引擎、name 唯一、可反查；
  2. 检出率（true positive）：核心攻击引擎在漏洞端点上必须产出 finding；
  3. 误报控制（false positive）：安全端点上不得产出 finding。

运行：python -m pytest tests/test_engines_core.py -v
"""
import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer

from vulnclaw.core.scanner import get_all_engines, get_engine_by_name


# ============================================================
# 本地靶场（真实行为的最小模拟，不调用任何外部工具）
# ============================================================
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

    app = web.Application()
    app.router.add_get("/", _index)
    app.router.add_get("/xss", _xss)
    app.router.add_get("/search", _search)
    app.router.add_get("/download", _download)
    app.router.add_get("/exec", _exec)
    app.router.add_get("/safe", _safe)
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
