# -*- coding: utf-8 -*-
"""工作流3：Fastjson / Log4Shell 真实检出专项（确定性内存靶场回归）。

把 framework_zero_day_engines 里两个 0day 引擎的**带内判定**锁成可回归用例：

- Log4ShellEngine：注入 ${java:version} 等 Lookup，漏洞端回显"解析值"（字面量消失、
  出现 `Java 1.8.0` / `Linux` 等解析特征），已修复端原样不解析 → 不得误报。
- FastjsonDeserializationEngine：注入 {"@type":...}，漏洞端回显 fastjson 错误特征
  （com.alibaba.fastjson / syntax error / autotype），已修复端返回干净 JSON → 不得误报。

不依赖 Docker / Vulhub / 真实 OOB：OOB 盲打被 autouse fixture 禁用，纯验证带内判定链
（OOB 实锤由工作流1 离线闭环覆盖）。靶场用内存 aiohttp + TestServer，任意环境可跑。
"""
import pytest
import pytest_asyncio
from aiohttp import web

from vulnclaw.engines.framework_zero_day_engines import (
    FastjsonDeserializationEngine,
    Log4ShellEngine,
)


@pytest.fixture(autouse=True)
def _disable_oob(monkeypatch):
    """工作流3 只验证带内判定：禁用 OOB 盲打（避免依赖 interactsh 离线状态）。"""
    import vulnclaw.engines.framework_zero_day_engines as _m

    async def _no_oob(**_kwargs):
        return None

    monkeypatch.setattr(_m, "_run_oob_scan", _no_oob)


def _build_lab():
    app = web.Application()

    async def log4_vuln(request):
        msg = request.query.get("msg", "")
        if msg == "${java:version}":
            return web.Response(text="<html>version=Java 1.8.0_292</html>")
        if msg == "${sys:os.name}":
            return web.Response(text="<html>os=Linux</html>")
        return web.Response(text="<html>ok</html>")

    async def log4_patched(request):
        # 已修复：不解析 Lookup，字面量原样回显
        return web.Response(text="<html>ok</html>")

    async def fj_vuln(request):
        data = request.query.get("data", "")
        if "@type" in data or "JdbcRowSetImpl" in data:
            return web.Response(
                text='{"error":"com.alibaba.fastjson.JSONException: syntax error, '
                     'autoType not support"}'
            )
        return web.Response(text='{"code":0}')

    async def fj_patched(request):
        # 已修复：正常业务响应，绝不泄露 fastjson 内部错误特征
        return web.Response(text='{"code":0}')

    app.router.add_get("/log4/vuln", log4_vuln)
    app.router.add_get("/log4/patched", log4_patched)
    app.router.add_get("/fj/vuln", fj_vuln)
    app.router.add_get("/fj/patched", fj_patched)
    return app


@pytest_asyncio.fixture
async def lab():
    from aiohttp.test_utils import TestServer

    server = TestServer(_build_lab())
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


# ============================================================
# Log4Shell（CVE-2021-44228）：带内 Lookup 解析值回显
# ============================================================
@pytest.mark.asyncio
async def test_log4shell_lookup_echo_tp(lab, session):
    """漏洞端：注入 ${java:version} 回显 'Java 1.8.0...' 必须检出（FN 门禁）。"""
    eng = Log4ShellEngine()
    normal = (200, "<html>ok</html>", {})
    res = await eng.check(f"{lab}/log4/vuln?msg=x", "msg", normal, "msg=x", session)
    assert res, "Log4Shell 带内 Lookup 回显未检出（FN）"
    assert res.get("severity") == "Critical"
    assert "Log4j2" in res.get("type", "")


@pytest.mark.asyncio
async def test_log4shell_no_fp_on_patched(lab, session):
    """已修复端：不解析 Lookup → 不得报漏洞（FP 门禁）。"""
    eng = Log4ShellEngine()
    normal = (200, "<html>ok</html>", {})
    res = await eng.check(f"{lab}/log4/patched?msg=x", "msg", normal, "msg=x", session)
    assert not res, f"Log4Shell 对已修复端误报: {res}"


# ============================================================
# Fastjson（autoType 反序列化）：带内错误特征回显
# ============================================================
@pytest.mark.asyncio
async def test_fastjson_error_echo_tp(lab, session):
    """漏洞端：注入 {"@type":"com.sun.rowset.JdbcRowSetImpl"} 回显 fastjson 报错必须检出。"""
    eng = FastjsonDeserializationEngine()
    normal = (200, '{"code":0}', {})
    res = await eng.check(f"{lab}/fj/vuln?data=x", "data", normal, "data=x", session)
    assert res, "Fastjson 带内报错回显未检出（FN）"
    assert res.get("severity") == "Critical"
    assert "Fastjson" in res.get("type", "")


@pytest.mark.asyncio
async def test_fastjson_no_fp_on_patched(lab, session):
    """已修复端：返回正常业务 JSON → 不得报漏洞（FP 门禁）。"""
    eng = FastjsonDeserializationEngine()
    normal = (200, '{"code":0}', {})
    res = await eng.check(f"{lab}/fj/patched?data=x", "data", normal, "data=x", session)
    assert not res, f"Fastjson 对已修复端误报: {res}"
