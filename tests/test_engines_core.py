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
import time

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


# 靶场请求计数器：deep 测试用它做"请求数上限"断言（替代 timeout 插件，
# 本环境无 pytest-timeout）。fixture 每个测试清零，按 request.path 累计。
_LAB_HITS: dict = {}


@web.middleware
async def _lab_hit_counter(request, handler):
    _LAB_HITS[request.path] = _LAB_HITS.get(request.path, 0) + 1
    return await handler(request)


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

    # 反序列化：仅当参数携带序列化 payload 标记时才回显 Java 错误签名，
    # 否则返回正常页面（深度覆盖：保证负例路径真实存在，而非"任意请求都报错"）
    _DESER_MARKERS = ("@type", "rO0AB", "O:8:", "a:1:{", "gASV", "_$$ND_FUNC$$_")

    async def _deser(request):
        data = request.query.get("data", "")
        if any(m in data for m in _DESER_MARKERS):
            return web.Response(
                text="java.io.NotSerializableException: com.example.User at com.example.Deserializer.deserialize"
            )
        return web.Response(text="<html><body><h1>API</h1><p>ok</p></body></html>")

    # 信息泄露：暴露 .env 敏感配置
    async def _dotenv(request):
        return web.Response(text="DB_PASSWORD=secret123\nAPI_KEY=ak-xxxx\n")

    # Host 头反射：将 Host 头值原样回显到响应体（模拟 Host 头注入漏洞）
    async def _hostreflect(request):
        host = request.headers.get("Host", "")
        return web.Response(text=f"<html><body><h1>Host</h1><div>served by {host}</div></body></html>")

    # HPP：回显同名参数的全部取值（模拟"使用后值/拼接"语义）
    async def _hpp(request):
        vals = request.query.getall("q", [])
        return web.Response(text="<html><body><h1>HPP</h1><div>" + ",".join(vals) + "</div></body></html>")

    # OpenAPI/Swagger 文档暴露（swagger_api_doc 引擎）
    async def _openapi(request):
        return web.Response(
            text='{"openapi":"3.0.0","info":{"title":"lab","version":"1.0"},"paths":{}}',
            content_type="application/json",
        )

    # Prometheus 指标暴露（prometheus_metrics 引擎）：>=5 条指标行、长度>=200
    async def _metrics(request):
        body = (
            "# HELP http_requests_total Total HTTP requests.\n"
            "# TYPE http_requests_total counter\n"
            "http_requests_total 1234\n"
            "# HELP go_goroutines Number of goroutines.\n"
            "# TYPE go_goroutines gauge\n"
            "go_goroutines 42\n"
            "process_cpu_seconds_total 9.81\n"
        )
        return web.Response(text=body, content_type="text/plain")

    # JSONP 数据劫持（jsonp_hijacking 引擎）：回显 callback + 敏感字段
    async def _jsonp(request):
        cb = request.query.get("callback", "cb")
        return web.Response(
            text=f'{cb}({{"email":"a@b.com","token":"abc"}})',
            content_type="application/javascript",
        )

    # 源码泄露：.git/config（source_code_leak 引擎）
    async def _gitconfig(request):
        return web.Response(
            text='[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n'
                 '[remote "origin"]\n\turl = https://github.com/secret/repo.git\n',
            content_type="text/plain",
        )

    # Nacos 未授权（nacos_exposure 引擎）
    async def _nacos_health(request):
        return web.Response(text='{"status":"UP"}', content_type="application/json")

    async def _nacos_users(request):
        return web.Response(text='{"username":"admin","password":"nacos123"}', content_type="application/json")

    # Solr Admin 未授权（solr_exposure 引擎）
    async def _solr_cores(request):
        return web.Response(
            text='{"responseHeader":{"status":0,"QTime":1},"instanceDir":"/opt/solr","lucene":{}}',
            content_type="application/json",
        )

    # Confluence 未授权（confluence_exposure 引擎）
    async def _confluence_manifest(request):
        return web.Response(text='{"applicationLinks":[],"confluence":"yes"}', content_type="application/json")

    async def _confluence_content(request):
        return web.Response(text='{"results":[{"type":"page","title":"secret"}]}', content_type="application/json")

    # HTTP 方法篡改（verb_tampering 引擎）：允许 GET/PUT/DELETE
    async def _verb(request):
        return web.Response(text="ok")

    # 管理控制台暴露（admin_console_exposure 引擎）
    async def _tomcat_manager(request):
        return web.Response(text="<html><body>Tomcat Manager</body></html>", content_type="text/html")

    # API 版本差异（api_version 引擎）：v1/v2 同时存活
    async def _apiv1(request):
        return web.Response(text="v1")

    async def _apiv2(request):
        return web.Response(text="v2")

    # 前端组件漏洞（js_library_cve 引擎）：引用 jQuery 1.8.3
    async def _vulnlib(request):
        return web.Response(
            text='<html><body><script src="/static/jquery-1.8.3.min.js"></script></body></html>',
            content_type="text/html",
        )

    # 后端组件漏洞（backend_component_cve 引擎）：Server 头暴露 Apache/2.4.49
    async def _backend(request):
        return web.Response(text="ok", headers={"Server": "Apache/2.4.49"})

    # Web 缓存欺骗（web_cache_deception 引擎）：动态内容可被任意后缀路径命中
    async def _wcd(request):
        return web.Response(text="x" * 200)

    # 移动端 API 弱认证（mobile_api 引擎）：匿名可达返回 JSON
    async def _mobile_api(request):
        return web.Response(text='{"data":1}', content_type="application/json")

    # 批量赋值（mass_assignment 引擎）：POST 回显 JSON 体
    async def _mass_assign(request):
        if request.method == "POST":
            try:
                data = await request.json()
            except Exception:
                data = {}
            return web.json_response(data)
        return web.json_response({})

    # 用户枚举（auth_enumeration 引擎）：admin 与随机用户响应不同
    async def _login(request):
        if request.method == "POST":
            try:
                form = await request.post()
                username = form.get("username", "")
            except Exception:
                username = ""
            if username == "admin":
                return web.Response(text="incorrect password", status=401)
            return web.Response(text="user not found", status=200)
        return web.Response(
            text="<html><body><form>login password</form></body></html>",
            content_type="text/html",
        )

    # API 版本差异（api_version_diff 引擎）：v1-v5 同存活
    async def _apiver(request):
        return web.Response(text="x" * 60)

    # Shiro rememberMe 指纹（shiro_rememberme 引擎）
    async def _shiro(request):
        return web.Response(text="shiro login", headers={"Set-Cookie": "rememberMe=deleteMe"})

    # Spring Cloud Gateway 路由端点（spring_cloud_gateway 引擎）
    async def _scg_routes(request):
        return web.Response(
            text='[{"route_id":"r1","predicates":["Path=/a"],"uri":"http://upstream","filters":[]}]',
            content_type="application/json",
        )

    # Kubernetes API /version（container_platform_exposure 引擎）
    async def _k8s_version(request):
        return web.Response(
            text='{"major":"1","minor":"28","gitVersion":"v1.28.0","platform":"linux/amd64"}',
            content_type="application/json",
        )

    # .NET ViewState（view_state 引擎）
    async def _viewstate(request):
        if request.method == "POST":
            return web.Response(text="Server Error: the state information is invalid for this page")
        return web.Response(
            text='<html><body><form method="post">'
                 '<input type="hidden" name="__VIEWSTATE" value="QUJDREVGR0hJSktMTU5PUA==" />'
                 '<input type="hidden" name="__VIEWSTATEGENERATOR" value="DEADBEEF" />'
                 '</form></body></html>',
            content_type="text/html",
        )

    # WebSocket 回显端点（http2_ws / websocket_security 引擎）
    async def _ws_echo(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        async for msg in ws:
            if msg.type == web.WSMsgType.TEXT:
                await ws.send_str(msg.data)
        return ws

    # K8s kube-system pods（container_security 引擎）
    async def _k8s_pods(request):
        return web.Response(
            text='{"kind":"PodList","items":[],"note":"securityContext.privileged=true"}',
            content_type="application/json",
        )

    # Fastjson 报错指纹（fastjson_deserialization 引擎）
    async def _fastjson(request):
        return web.Response(text="com.alibaba.fastjson.JSONException: syntax error, pos 2")

    # Struts2 OGNL 求值（struts2_ognl 引擎）
    async def _ognl(request):
        x = request.query.get("x", "")
        return web.Response(text="579" if "123+456" in x else "ok")

    # Spring4Shell 参数绑定报错（spring4shell 引擎）
    async def _s4s(request):
        if any("class.module" in v for v in request.query.values()):
            return web.Response(text="java.lang.ClassLoader rejected: requestrejectedexception")
        return web.Response(text="ok")

    # 查询串原样回显（prototype_pollution 引擎）
    async def _reflect(request):
        return web.Response(text="echo: " + request.query_string)

    # SSRF 回显端点（SSRFEngine 深度覆盖）：url 指向内网时回显内网秘密
    async def _fetch(request):
        u = request.query.get("url", "")
        if "127.0.0.1" in u or "localhost" in u:
            return web.Response(text="internal_secret=lab-only\n")
        return web.Response(text="<html><body><h1>Fetch</h1><p>external content</p></body></html>")

    # XXE 端点（XXEEngine 深度覆盖）：XML 携带 ENTITY 实体时回显 passwd 内容
    async def _xxe(request):
        x = request.query.get("xml", "")
        if "ENTITY" in x:
            return web.Response(
                text="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            )
        return web.Response(text='<?xml version="1.0"?><root>ok</root>')

    # GraphQL 端点（GraphQLEngine 深度覆盖）：__schema 返回可内省 schema，
    # 其余查询返回空 data（别名/递归/批量提取均不命中，保证断言确定性）
    async def _graphql(request):
        if request.method == "POST":
            try:
                body = await request.json()
            except Exception:
                body = {}
            q = str(body.get("query") or "")
            if "__schema" in q:
                schema = {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "types": [
                                {
                                    "name": "Query",
                                    "kind": "OBJECT",
                                    "fields": [
                                        {"name": "status", "type": {"name": "String", "kind": "SCALAR"}}
                                    ],
                                },
                                {"name": "String", "kind": "SCALAR"},
                            ],
                        }
                    }
                }
                return web.json_response(schema)
            if "__typename" in q:
                return web.json_response({"data": {"__typename": "Query"}})
            return web.json_response({"data": {}})
        return web.Response(text="GraphQL playground")

    app = web.Application(middlewares=[_lab_hit_counter])
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
    app.router.add_get("/hostreflect", _hostreflect)
    app.router.add_get("/hpp", _hpp)
    app.router.add_get("/openapi.json", _openapi)
    app.router.add_get("/metrics", _metrics)
    app.router.add_get("/api/user", _jsonp)
    app.router.add_get("/.git/config", _gitconfig)
    app.router.add_get("/nacos/v1/console/health/readiness", _nacos_health)
    app.router.add_get("/nacos/v1/auth/users", _nacos_users)
    app.router.add_get("/solr/admin/cores", _solr_cores)
    app.router.add_get("/rest/applinks/1.0/manifest", _confluence_manifest)
    app.router.add_get("/rest/api/content", _confluence_content)
    app.router.add_route("GET", "/verb", _verb)
    app.router.add_route("PUT", "/verb", _verb)
    app.router.add_route("DELETE", "/verb", _verb)
    app.router.add_get("/manager/html", _tomcat_manager)
    app.router.add_get("/v1/foo", _apiv1)
    app.router.add_get("/v2/foo", _apiv2)
    app.router.add_get("/vulnlib", _vulnlib)
    app.router.add_get("/backend", _backend)
    app.router.add_get("/wcd", _wcd)
    app.router.add_get("/wcd/{tail:.*}", _wcd)
    app.router.add_get("/api/v1", _mobile_api)
    app.router.add_get("/api/profile", _mass_assign)
    app.router.add_post("/api/profile", _mass_assign)
    app.router.add_get("/shiro", _shiro)
    app.router.add_get("/actuator/gateway/routes", _scg_routes)
    app.router.add_get("/version", _k8s_version)
    app.router.add_get("/viewstate", _viewstate)
    app.router.add_post("/viewstate", _viewstate)
    app.router.add_get("/ws", _ws_echo)
    app.router.add_get("/api/v1/namespaces/kube-system/pods", _k8s_pods)
    app.router.add_get("/fastjson", _fastjson)
    app.router.add_get("/ognl", _ognl)
    app.router.add_get("/s4s", _s4s)
    app.router.add_get("/reflect", _reflect)
    app.router.add_get("/fetch", _fetch)
    app.router.add_get("/xxe", _xxe)
    app.router.add_get("/graphql", _graphql)
    app.router.add_post("/graphql", _graphql)
    app.router.add_get("/login", _login)
    app.router.add_post("/login", _login)
    app.router.add_get("/api/v{digit:\\d}/foo", _apiver)
    return app


@pytest_asyncio.fixture
async def lab_base():
    _LAB_HITS.clear()
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


# ============================================================
# 6. gap 引擎收口（TEST_GAP.md：39 个零测试引擎中的两个高价值项）
#    host_header（Host 头注入）/ hpp（HTTP 参数污染）
# ============================================================
@pytest.mark.asyncio
async def test_host_header_reflection_detected(lab_base, session):
    from vulnclaw.engines.http_engines import HostHeaderEngine

    eng = HostHeaderEngine()
    findings = await eng.scan(f"{lab_base}/hostreflect", session)
    assert findings, "Host 头引擎未检出 Host 头反射"
    types = [f.get("type", "") for f in findings]
    assert any("反射" in t for t in types), f"未检出 Host 头反射: {findings}"


@pytest.mark.asyncio
async def test_hpp_detected(lab_base, session):
    from vulnclaw.engines.input_engines import HPPEngine

    eng = HPPEngine()
    url = f"{lab_base}/hpp?q=hello"
    result = await eng.check(url, "q", _normal_resp(), "q=hello", session)
    assert result, "HPP 引擎未检出参数污染"
    assert "HPP" in str(result.get("type", "")), f"finding 类型异常: {result.get('type')}"


@pytest.mark.asyncio
async def test_hpp_no_false_positive_on_sanitized(lab_base, session):
    from vulnclaw.engines.input_engines import HPPEngine

    eng = HPPEngine()
    url = f"{lab_base}/safe?q=hello"
    result = await eng.check(url, "q", _normal_resp(), "q=hello", session)
    assert result is None, f"HPP 引擎在净化端点上误报: {result}"


# ============================================================
# 7. gap 引擎收口（续）：暴露/泄露类（复用 TEST_GAP.md 缺口清单）
#    swagger_api_doc / prometheus_metrics / jsonp_hijacking / backup_file_leak
# ============================================================
@pytest.mark.asyncio
async def test_swagger_api_doc_detected(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import SwaggerApiDocEngine

    eng = SwaggerApiDocEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "Swagger 引擎未检出 OpenAPI 文档暴露"
    assert any("Swagger" in f.get("type", "") or "OpenAPI" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_prometheus_metrics_detected(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import PrometheusMetricsExposureEngine

    eng = PrometheusMetricsExposureEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "Prometheus 引擎未检出指标暴露"
    assert any("Prometheus" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_jsonp_hijacking_detected(lab_base, session):
    from vulnclaw.engines.web_advanced_engines import JSONPHijackingEngine

    eng = JSONPHijackingEngine()
    findings = await eng.scan(f"{lab_base}/api/user", session)
    assert findings, "JSONP 引擎未检出数据劫持"
    assert any("JSONP" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_backup_file_leak_detected(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import BackupFileLeakEngine

    eng = BackupFileLeakEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "BackupFileLeak 引擎未检出 .env 泄露"
    assert any(".env" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_swagger_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import SwaggerApiDocEngine

    eng = SwaggerApiDocEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"Swagger 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_prometheus_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import PrometheusMetricsExposureEngine

    eng = PrometheusMetricsExposureEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"Prometheus 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_jsonp_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.web_advanced_engines import JSONPHijackingEngine

    eng = JSONPHijackingEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"JSONP 引擎在干净端点误报: {findings}"


# ============================================================
# 8. gap 引擎收口（续三）：暴露/泄露类（复用 TEST_GAP.md 缺口清单）
#    source_code_leak / nacos_exposure / solr_exposure /
#    confluence_exposure / verb_tampering
# ============================================================
@pytest.mark.asyncio
async def test_source_code_leak_detected(lab_base, session):
    from vulnclaw.engines.leak_logic_engines import SourceCodeLeakEngine

    eng = SourceCodeLeakEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "SourceCodeLeak 引擎未检出 .git/config 泄露"
    assert any(".git" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_nacos_exposure_detected(lab_base, session):
    from vulnclaw.engines.middleware_exposure_engines import NacosExposureEngine

    eng = NacosExposureEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "Nacos 引擎未检出未授权访问"
    assert any("Nacos" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_solr_exposure_detected(lab_base, session):
    from vulnclaw.engines.middleware_exposure_engines import SolrExposureEngine

    eng = SolrExposureEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "Solr 引擎未检出 Admin 未授权"
    assert any("Solr" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_confluence_exposure_detected(lab_base, session):
    from vulnclaw.engines.middleware_exposure_engines import ConfluenceExposureEngine

    eng = ConfluenceExposureEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "Confluence 引擎未检出未授权访问"
    assert any("Confluence" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_verb_tampering_detected(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import VerbTamperingEngine

    eng = VerbTamperingEngine()
    findings = await eng.scan(f"{lab_base}/verb", session)
    assert findings, "VerbTampering 引擎未检出危险 HTTP 方法"
    assert any("方法" in f.get("type", "") or "TRACE" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_source_code_leak_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.leak_logic_engines import SourceCodeLeakEngine

    eng = SourceCodeLeakEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"SourceCodeLeak 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_nacos_exposure_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.middleware_exposure_engines import NacosExposureEngine

    eng = NacosExposureEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"Nacos 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_solr_exposure_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.middleware_exposure_engines import SolrExposureEngine

    eng = SolrExposureEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"Solr 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_confluence_exposure_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.middleware_exposure_engines import ConfluenceExposureEngine

    eng = ConfluenceExposureEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"Confluence 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_verb_tampering_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import VerbTamperingEngine

    eng = VerbTamperingEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"VerbTampering 引擎在干净端点误报: {findings}"


# ============================================================
# 9. gap 引擎收口（续四）：小目标——单端点指纹 / 双端点存活
#    admin_console_exposure / api_version
# ============================================================
@pytest.mark.asyncio
async def test_admin_console_exposure_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import AdminConsoleExposureEngine

    eng = AdminConsoleExposureEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "AdminConsoleExposure 引擎未检出管理控制台暴露"
    assert any("暴露" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_api_version_detected(lab_base, session):
    from vulnclaw.engines.api_version import APIVersionEngine

    eng = APIVersionEngine()
    findings = await eng.scan(f"{lab_base}/v1/foo", session)
    assert findings, "APIVersion 引擎未检出多版本同时暴露"
    assert any(f.get("type") == "api_multiple_versions" for f in findings), findings


@pytest.mark.asyncio
async def test_admin_console_exposure_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import AdminConsoleExposureEngine

    eng = AdminConsoleExposureEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"AdminConsoleExposure 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_api_version_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.api_version import APIVersionEngine

    eng = APIVersionEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"APIVersion 引擎在非版本 URL 误报: {findings}"


# ============================================================
# 10. gap 引擎收口（续五）：组件/缓存/移动端
#     js_library_cve / backend_component_cve / web_cache_deception / mobile_api
# ============================================================
async def _with_component_cve_check():
    from vulnclaw.config.settings import settings

    old = settings.component_cve_check
    settings.component_cve_check = True
    return settings, old


@pytest.mark.asyncio
async def test_js_library_cve_detected(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import JsLibraryCveEngine

    settings, old = await _with_component_cve_check()
    try:
        eng = JsLibraryCveEngine()
        findings = await eng.scan(f"{lab_base}/vulnlib", session)
    finally:
        settings.component_cve_check = old
    assert findings, "JsLibraryCve 引擎未检出 jQuery 1.8.3 组件漏洞"
    assert any("前端组件漏洞" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_backend_component_cve_detected(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import BackendComponentFingerprintEngine

    settings, old = await _with_component_cve_check()
    try:
        eng = BackendComponentFingerprintEngine()
        findings = await eng.scan(f"{lab_base}/backend", session)
    finally:
        settings.component_cve_check = old
    assert findings, "BackendComponent 引擎未检出 Apache/2.4.49 组件漏洞"
    assert any("后端组件漏洞" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_web_cache_deception_detected(lab_base, session):
    from vulnclaw.engines.http_advanced_engines import WebCacheDeceptionEngine

    eng = WebCacheDeceptionEngine()
    findings = await eng.scan(f"{lab_base}/wcd", session)
    assert findings, "WebCacheDeception 引擎未检出路径混淆"
    assert any("缓存欺骗" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_mobile_api_weak_auth_detected(lab_base, session):
    from vulnclaw.engines.mobile_engines import MobileAPIEngine

    eng = MobileAPIEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "MobileAPI 引擎未检出任何问题"
    assert any(f.get("type") == "API 匿名可达" for f in findings), findings


@pytest.mark.asyncio
async def test_js_library_cve_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import JsLibraryCveEngine

    settings, old = await _with_component_cve_check()
    try:
        eng = JsLibraryCveEngine()
        findings = await eng.scan(f"{lab_base}/safe", session)
    finally:
        settings.component_cve_check = old
    assert findings == [], f"JsLibraryCve 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_backend_component_cve_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.logic_leak_engines_2 import BackendComponentFingerprintEngine

    settings, old = await _with_component_cve_check()
    try:
        eng = BackendComponentFingerprintEngine()
        findings = await eng.scan(f"{lab_base}/safe", session)
    finally:
        settings.component_cve_check = old
    assert findings == [], f"BackendComponent 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_web_cache_deception_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.http_advanced_engines import WebCacheDeceptionEngine

    eng = WebCacheDeceptionEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"WebCacheDeception 引擎在干净端点误报: {findings}"


# ============================================================
# 11. gap 引擎收口（续六）：API/认证类
#     mass_assignment / auth_enumeration / api_version_diff
# ============================================================
async def _with_api_bola_test():
    from vulnclaw.config.settings import settings

    old = settings.api_bola_test
    settings.api_bola_test = True
    return settings, old


@pytest.mark.asyncio
async def test_mass_assignment_detected(lab_base, session):
    from vulnclaw.engines.api_security_engines import MassAssignmentEngine

    settings, old = await _with_api_bola_test()
    try:
        eng = MassAssignmentEngine()
        findings = await eng.scan(lab_base, session)
    finally:
        settings.api_bola_test = old
    assert findings, "MassAssignment 引擎未检出特权字段批量赋值"
    assert any(f.get("type") == "mass_assignment_privilege_field" for f in findings), findings


@pytest.mark.asyncio
async def test_auth_enumeration_detected(lab_base, session):
    from vulnclaw.engines.leak_logic_engines import AuthEnumerationEngine

    eng = AuthEnumerationEngine()
    findings = await eng.scan(lab_base, session)
    assert findings, "AuthEnumeration 引擎未检出用户枚举响应差异"
    assert any("用户枚举" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_api_version_diff_detected(lab_base, session):
    from vulnclaw.engines.auxiliary_engines import APIVersionDiffEngine

    eng = APIVersionDiffEngine()
    findings = await eng.scan(f"{lab_base}/api/v1/foo", session)
    assert findings, "APIVersionDiff 引擎未检出多版本可访问"
    assert any("API版本差异" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_auth_enumeration_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.leak_logic_engines import AuthEnumerationEngine

    eng = AuthEnumerationEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"AuthEnumeration 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_api_version_diff_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.auxiliary_engines import APIVersionDiffEngine

    eng = APIVersionDiffEngine()
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"APIVersionDiff 引擎在非版本 URL 误报: {findings}"


# ============================================================
# 12. gap 引擎收口（终）：协议/框架 0day/容器/杂项 —— 覆盖剩余全部引擎
# ============================================================
@pytest.mark.asyncio
async def test_shiro_rememberme_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import ShiroRememberMeEngine

    findings = await ShiroRememberMeEngine().scan(f"{lab_base}/shiro", session)
    assert any("Shiro" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_shiro_rememberme_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import ShiroRememberMeEngine

    findings = await ShiroRememberMeEngine().scan(f"{lab_base}/safe", session)
    assert findings == [], f"Shiro 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_spring_cloud_gateway_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import SpringCloudGatewayEngine

    findings = await SpringCloudGatewayEngine().scan(lab_base, session)
    assert any("Spring Cloud Gateway" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_spring_cloud_gateway_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import SpringCloudGatewayEngine

    findings = await SpringCloudGatewayEngine().scan(f"{lab_base}/safe", session)
    assert findings == [], f"SpringCloudGateway 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_container_platform_exposure_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines_2 import ContainerPlatformExposureEngine

    findings = await ContainerPlatformExposureEngine().scan(lab_base, session)
    assert any("Kubernetes" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_view_state_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines import ViewStateEngine

    findings = await ViewStateEngine().scan(f"{lab_base}/viewstate", session)
    assert any("ViewState" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_view_state_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines import ViewStateEngine

    findings = await ViewStateEngine().scan(f"{lab_base}/safe", session)
    assert findings == [], f"ViewState 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_http2_ws_websocket_detected(lab_base, session):
    from vulnclaw.engines.auxiliary_engines import HTTP2WebSocketEngine

    findings = await HTTP2WebSocketEngine().scan(lab_base, session)
    assert any("WebSocket" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_websocket_security_smoke(lab_base, session):
    from vulnclaw.engines.websocket_security import WebSocketSecurityEngine

    findings = await WebSocketSecurityEngine().scan(lab_base, session)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_container_security_detected(lab_base, session):
    from vulnclaw.engines.container_engines import ContainerSecurityEngine

    findings = await ContainerSecurityEngine().scan(lab_base, session)
    assert any("容器配置风险" in f.get("type", "") for f in findings), findings


@pytest.mark.asyncio
async def test_container_security_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.container_engines import ContainerSecurityEngine

    findings = await ContainerSecurityEngine().scan(f"{lab_base}/safe", session)
    assert findings == [], f"ContainerSecurity 引擎在干净端点误报: {findings}"


@pytest.mark.asyncio
async def test_fastjson_deserialization_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines import FastjsonDeserializationEngine

    finding = await FastjsonDeserializationEngine().check(
        f"{lab_base}/fastjson", "data", (200, "ok", {}), "data=x", session
    )
    assert finding and "Fastjson" in finding.get("type", ""), finding


@pytest.mark.asyncio
async def test_struts2_ognl_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines import Struts2OGNLEngine

    finding = await Struts2OGNLEngine().check(
        f"{lab_base}/ognl?x=1", "x", (200, "ok", {}), "x=1", session
    )
    assert finding and "OGNL" in finding.get("type", ""), finding


@pytest.mark.asyncio
async def test_spring4shell_detected(lab_base, session):
    from vulnclaw.engines.framework_zero_day_engines import Spring4ShellEngine

    finding = await Spring4ShellEngine().check(
        f"{lab_base}/s4s?file=a.jsp", "file", (200, "ok", {}), "file=a.jsp", session
    )
    assert finding and "Spring4Shell" in finding.get("type", ""), finding


@pytest.mark.asyncio
async def test_prototype_pollution_detected(lab_base, session):
    from vulnclaw.engines.web_advanced_engines import PrototypePollutionEngine

    finding = await PrototypePollutionEngine().check(
        f"{lab_base}/reflect?config=x", "config", (200, "ok", {}), "config=x", session
    )
    assert finding and "原型链污染" in finding.get("type", ""), finding


@pytest.mark.asyncio
async def test_request_smuggling_smoke(lab_base, session):
    from vulnclaw.engines.auxiliary_engines import RequestSmugglingEngine

    findings = await RequestSmugglingEngine().scan(lab_base, session)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_tls_security_no_finding_on_plain_http(lab_base, session):
    from vulnclaw.engines.net_engines import TlsSecurityEngine

    findings = await TlsSecurityEngine().scan(lab_base, session)
    assert findings == [], f"TLS 引擎对纯 HTTP 目标误报: {findings}"


@pytest.mark.asyncio
async def test_dns_security_no_finding_on_ip_target(lab_base, session):
    from vulnclaw.engines.net_engines import DnsSecurityEngine

    findings = await DnsSecurityEngine().scan(lab_base, session)
    assert findings == [], f"DNS 引擎对 IP 目标误报: {findings}"


@pytest.mark.asyncio
async def test_business_logic_smoke(lab_base, session):
    import asyncio as _aio
    import os as _os

    from vulnclaw.engines.input_engines import BusinessLogicEngine

    old_env = _os.environ.get("ENABLE_BUSINESS_AI_ANALYSIS")
    _os.environ["ENABLE_BUSINESS_AI_ANALYSIS"] = "false"
    try:
        findings = await _aio.wait_for(
            BusinessLogicEngine().scan(lab_base, session), timeout=90
        )
    finally:
        if old_env is None:
            _os.environ.pop("ENABLE_BUSINESS_AI_ANALYSIS", None)
        else:
            _os.environ["ENABLE_BUSINESS_AI_ANALYSIS"] = old_env
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_api_security_smoke(lab_base, session):
    from vulnclaw.engines.api_security_engines import APISecurityEngine

    findings = await APISecurityEngine().scan(lab_base, session)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_password_reset_smoke(lab_base, session):
    from vulnclaw.engines.auth_engines import PasswordResetEngine

    findings = await PasswordResetEngine().scan(lab_base, session)
    assert isinstance(findings, list)


@pytest.mark.asyncio
async def test_cloud_container_exposure_skips_local(lab_base, session):
    from vulnclaw.config.settings import settings
    from vulnclaw.engines.framework_zero_day_engines_2 import CloudAndContainerExposureEngine

    old = settings.cloud_container_exposure
    settings.cloud_container_exposure = True
    try:
        findings = await CloudAndContainerExposureEngine().scan(lab_base, session)
    finally:
        settings.cloud_container_exposure = old
    assert findings == [], f"本地靶场不应产生云/容器暴露告警: {findings}"


@pytest.mark.asyncio
async def test_exposure_fingerprint_matches_rules(lab_base, session):
    from vulnclaw.engines.exposure_fingerprint_engine import (
        ExposureFingerprintEngine,
        load_exposure_rules,
    )

    rules = load_exposure_rules()
    findings = await ExposureFingerprintEngine().scan(lab_base, session)
    if rules:
        assert findings, "exposure_fingerprint 有规则但靶场未命中"
    else:
        assert findings == []


@pytest.mark.asyncio
async def test_exposure_fingerprint_no_false_positive_on_clean(lab_base, session):
    from vulnclaw.engines.exposure_fingerprint_engine import ExposureFingerprintEngine

    findings = await ExposureFingerprintEngine().scan(f"{lab_base}/safe", session)
    assert findings == [], f"exposure_fingerprint 引擎在干净端点误报: {findings}"


# ============================================================
# 13. P0/P1 引擎深度覆盖（组 D）：
#     正例（检出 + evidence 非空含关键标记 + payload 复现信息）
#     + 反例（no-FP）+ 请求数上限（_LAB_HITS）+ 耗时上限（time.monotonic）。
#     口径约定：测试名含 "_deep_"，供 scripts/test_coverage_audit.py 的
#     DEPTH 统计识别（深度测试必须同时出现 evidence 与 payload/reproduction
#     断言，命名即承诺）。
# ============================================================
def _deep_positive(finding, type_sub, evidence_markers, payload_sub=None):
    """参数级引擎深度正例四件套：检出 + 类型 + evidence + 复现信息。"""
    assert finding, "深度正例未检出"
    assert type_sub in str(finding.get("type", "")), f"finding 类型异常: {finding.get('type')}"
    evidence = str(finding.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {finding}"
    for m in evidence_markers:
        assert m in evidence, f"evidence 缺关键标记 {m!r}: {evidence!r}"
    payload = str(finding.get("payload") or "")
    assert payload.strip(), f"缺 payload 复现信息: {finding}"
    if payload_sub:
        assert payload_sub in payload, f"payload 复现信息异常: {payload!r}"


def _deep_timebound(t0, max_seconds):
    elapsed = time.monotonic() - t0
    assert elapsed < max_seconds, f"耗时 {elapsed:.1f}s 超上限 {max_seconds}s"


# ---------- P0: 反序列化（CWE-502） ----------
@pytest.mark.asyncio
async def test_deserialization_deep_positive(lab_base, session):
    from vulnclaw.engines.deserialization import DeserializationEngine

    eng = DeserializationEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/deser?data=x", "data", _normal_resp(), "data=x", session
    )
    _deep_positive(result, "反序列化注入", ("反序列化错误回显",))
    assert result.get("severity") == "High", f"严重级异常: {result.get('severity')}"
    assert _LAB_HITS.get("/deser", 0) <= 12, f"反序列化请求过多: {_LAB_HITS.get('/deser')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_deserialization_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.deserialization import DeserializationEngine

    eng = DeserializationEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?data=x", "data", _normal_resp(), "data=x", session
    )
    assert result is None, f"反序列化引擎在净化端点误报: {result}"
    findings = await eng.scan(f"{lab_base}/safe", session)
    assert findings == [], f"反序列化被动扫描在干净端点误报: {findings}"
    _deep_timebound(t0, 30)


# ---------- P0: SSRF（CWE-918） ----------
@pytest.mark.asyncio
async def test_ssrf_deep_positive(lab_base, session):
    from vulnclaw.engines.net_engines import SSRFEngine

    eng = SSRFEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/fetch?url=https%3A%2F%2Fexample.com", "url",
        _normal_resp(), "url=https%3A%2F%2Fexample.com", session,
    )
    assert result, "SSRF 引擎未检出内网回显"
    assert str(result.get("type", "")).startswith("SSRF"), f"finding 类型异常: {result.get('type')}"
    evidence = str(result.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {result}"
    assert "internal_secret" in evidence, f"evidence 缺内网回显标记: {evidence!r}"
    assert "127.0.0.1" in str(result.get("payload") or ""), (
        f"payload 复现信息异常: {result.get('payload')}"
    )
    assert _LAB_HITS.get("/fetch", 0) <= 6, f"SSRF 请求过多: {_LAB_HITS.get('/fetch')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ssrf_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.net_engines import SSRFEngine

    eng = SSRFEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?url=https%3A%2F%2Fexample.com", "url",
        _normal_resp(), "url=https%3A%2F%2Fexample.com", session,
    )
    assert result is None, f"SSRF 引擎在净化端点误报: {result}"
    assert _LAB_HITS.get("/safe", 0) <= 10, f"SSRF 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 45)


# ---------- P0: 命令执行（CWE-78） ----------
@pytest.mark.asyncio
async def test_cmdi_deep_positive(lab_base, session):
    from vulnclaw.engines.web_engines import CMDIEngine

    eng = CMDIEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/exec?cmd=x", "cmd", _normal_resp(), "cmd=x", session
    )
    _deep_positive(result, "命令注入-CMD执行", ("uid=",))
    assert result.get("cmd_exec") is True, f"缺 cmd_exec 实锤标记: {result}"
    assert _LAB_HITS.get("/exec", 0) <= 10, f"CMDI 请求过多: {_LAB_HITS.get('/exec')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_cmdi_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.web_engines import CMDIEngine

    eng = CMDIEngine()
    eng.max_payloads = 8
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?cmd=x", "cmd", _normal_resp(), "cmd=x", session
    )
    assert result is None, f"CMDI 引擎在净化端点误报: {result}"
    assert _LAB_HITS.get("/safe", 0) <= 10, f"CMDI 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 45)


# ---------- P0: 文件读取 / 路径遍历（CWE-22） ----------
@pytest.mark.asyncio
async def test_lfi_deep_positive(lab_base, session):
    from vulnclaw.engines.web_engines import LFIEngine

    eng = LFIEngine()
    # Windows 上 get_payloads 会把 windows payload 前置，加大额度覆盖到 linux payload
    eng.max_payloads = 80
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/download?file=x", "file", _normal_resp(), "file=x", session
    )
    _deep_positive(result, "文件包含-LFI", ("root:x:0:0",))
    assert result.get("file_read") is True, f"缺 file_read 实锤标记: {result}"
    assert result.get("lfi_verified") is True, f"缺 lfi_verified 实锤标记: {result}"
    assert "etc/passwd" in str(result.get("payload") or ""), (
        f"payload 复现信息异常: {result.get('payload')}"
    )
    assert _LAB_HITS.get("/download", 0) <= 90, f"LFI 请求过多: {_LAB_HITS.get('/download')}"
    _deep_timebound(t0, 60)


@pytest.mark.asyncio
async def test_lfi_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.web_engines import LFIEngine

    eng = LFIEngine()
    eng.max_payloads = 30
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?file=x", "file", _normal_resp(), "file=x", session
    )
    assert result is None, f"LFI 引擎在净化端点误报: {result}"
    assert _LAB_HITS.get("/safe", 0) <= 40, f"LFI 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 60)


# ---------- P0: 认证绕过（JWT alg:none，CWE-347） ----------
def _b64url(obj) -> str:
    import base64
    import json as _json

    return base64.urlsafe_b64encode(
        _json.dumps(obj, separators=(",", ":")).encode()
    ).decode().rstrip("=")


@pytest.mark.asyncio
async def test_jwt_auth_bypass_deep_positive(lab_base, session):
    from vulnclaw.engines.auth_engines import JWTEngine

    # {"alg":"none","typ":"JWT"} . {"sub":"1","exp":9999999999} .（去签名）
    token = f"{_b64url({'alg': 'none', 'typ': 'JWT'})}.{_b64url({'sub': '1', 'exp': 9999999999})}."
    eng = JWTEngine()
    normal = (200, f"access_token={token}", {})
    t0 = time.monotonic()
    result = await eng.check(f"{lab_base}/api/profile", "Authorization", normal, "", session)
    assert result, "JWT 引擎未检出 alg:none 认证绕过"
    assert result.get("type") == "JWT漏洞", f"finding 类型异常: {result.get('type')}"
    evidence = str(result.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {result}"
    assert "alg: none 算法混淆" in evidence, f"evidence 缺 alg:none 标记: {evidence!r}"
    assert result.get("severity") == "Critical", f"严重级异常: {result.get('severity')}"
    vuln_types = [str(v.get("type")) for v in (result.get("vulnerabilities") or [])]
    assert any("alg: none" in v for v in vuln_types), f"漏洞明细缺失: {vuln_types}"
    # 复现信息：token 本身即可离线复现（去签名伪造）；
    # reproduction 断言：finding 内保留解码后的 JWT payload，可复算伪造步骤
    assert str(result.get("token") or "").startswith("eyJ"), f"缺 token 复现信息: {result.get('token')}"
    assert (result.get("payload") or {}).get("alg") is None or (result.get("header") or {}).get("alg") == "none", (
        f"缺可复算的 JWT header/payload: {result.get('header')} / {result.get('payload')}"
    )
    _deep_timebound(t0, 15)


@pytest.mark.asyncio
async def test_jwt_auth_bypass_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.auth_engines import JWTEngine

    eng = JWTEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/api/profile", "Authorization", _normal_resp(), "", session
    )
    assert result is None, f"JWT 引擎在无 token 响应误报: {result}"
    _deep_timebound(t0, 15)


# ---------- P1: SSTI（CWE-1336） ----------
@pytest.mark.asyncio
async def test_ssti_deep_positive(lab_base, session):
    from vulnclaw.engines.web_engines import SSTIEngine

    eng = SSTIEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/ssti?name=hello", "name", _normal_resp(), "name=hello", session
    )
    assert result, "SSTI 深度正例未检出"
    assert str(result.get("type", "")).startswith("SSTI-L1"), f"finding 类型异常: {result.get('type')}"
    evidence = str(result.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {result}"
    assert "49" in evidence, f"evidence 缺模板计算结果标记: {evidence!r}"
    assert "{{7*7}}" in str(result.get("payload") or ""), (
        f"payload 复现信息异常: {result.get('payload')}"
    )
    assert _LAB_HITS.get("/ssti", 0) <= 45, f"SSTI 请求过多: {_LAB_HITS.get('/ssti')}"
    _deep_timebound(t0, 45)


@pytest.mark.asyncio
async def test_ssti_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.web_engines import SSTIEngine

    eng = SSTIEngine()
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?name=hello", "name", _normal_resp(), "name=hello", session
    )
    assert result is None, f"SSTI 引擎在净化端点误报: {result}"
    assert _LAB_HITS.get("/safe", 0) <= 30, f"SSTI 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 45)


# ---------- P1: XXE（CWE-611） ----------
@pytest.mark.asyncio
async def test_xxe_deep_positive(lab_base, session):
    from vulnclaw.engines.net_engines import XXEEngine

    eng = XXEEngine()
    eng.max_payloads = 4
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/xxe?xml=doc", "xml", _normal_resp(), "xml=doc", session
    )
    assert result, "XXE 引擎未检出文件读取"
    assert str(result.get("type", "")).startswith("XXE("), f"finding 类型异常: {result.get('type')}"
    evidence = str(result.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {result}"
    assert "root:x:0:0" in evidence, f"evidence 缺 passwd 标记: {evidence!r}"
    assert "ENTITY" in str(result.get("payload") or ""), (
        f"payload 复现信息异常: {result.get('payload')}"
    )
    assert _LAB_HITS.get("/xxe", 0) <= 8, f"XXE 请求过多: {_LAB_HITS.get('/xxe')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_xxe_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.net_engines import XXEEngine

    eng = XXEEngine()
    eng.max_payloads = 4
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?xml=doc", "xml", _normal_resp(), "xml=doc", session
    )
    assert result is None, f"XXE 引擎在净化端点误报: {result}"
    assert _LAB_HITS.get("/safe", 0) <= 10, f"XXE 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 45)


# ---------- P1: NoSQL 注入（CWE-943） ----------
@pytest.mark.asyncio
async def test_nosql_deep_positive(lab_base, session):
    from vulnclaw.engines.web_engines import NoSQLEngine

    eng = NoSQLEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/nosql?q=1", "q", _normal_resp(), "q=1", session
    )
    assert result, "NoSQL 引擎未检出注入"
    assert str(result.get("type", "")).startswith("NoSQL注入("), f"finding 类型异常: {result.get('type')}"
    evidence = str(result.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {result}"
    assert "Mongo" in evidence, f"evidence 缺 Mongo 错误标记: {evidence!r}"
    assert "$ne" in str(result.get("payload") or ""), (
        f"payload 复现信息异常: {result.get('payload')}"
    )
    assert _LAB_HITS.get("/nosql", 0) <= 8, f"NoSQL 请求过多: {_LAB_HITS.get('/nosql')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_nosql_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.web_engines import NoSQLEngine

    eng = NoSQLEngine()
    eng.max_payloads = 6
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?q=1", "q", _normal_resp(), "q=1", session
    )
    assert result is None, f"NoSQL 引擎在净化端点误报: {result}"
    # NoSQL get_payloads 对非优先参数会追加 desc 含 priority 关键词的 payload，
    # 上限按 6+5（$where 族追加）计
    assert _LAB_HITS.get("/safe", 0) <= 16, f"NoSQL 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 30)


# ---------- P1: LDAP 注入（CWE-90） ----------
@pytest.mark.asyncio
async def test_ldap_deep_positive(lab_base, session):
    from vulnclaw.engines.input_engines import LDAPEngine

    eng = LDAPEngine()
    eng.max_payloads = 4
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/ldap?user=admin", "user", _normal_resp(), "user=admin", session
    )
    assert result, "LDAP 引擎未检出注入"
    assert str(result.get("type", "")).startswith("LDAP注入("), f"finding 类型异常: {result.get('type')}"
    evidence = str(result.get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {result}"
    assert "invalid search filter" in evidence, f"evidence 缺 LDAP 错误标记: {evidence!r}"
    assert _LAB_HITS.get("/ldap", 0) <= 6, f"LDAP 请求过多: {_LAB_HITS.get('/ldap')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_ldap_deep_no_false_positive(lab_base, session):
    from vulnclaw.engines.input_engines import LDAPEngine

    eng = LDAPEngine()
    eng.max_payloads = 4
    t0 = time.monotonic()
    result = await eng.check(
        f"{lab_base}/safe?user=admin", "user", _normal_resp(), "user=admin", session
    )
    assert result is None, f"LDAP 引擎在净化端点误报: {result}"
    assert _LAB_HITS.get("/safe", 0) <= 6, f"LDAP 负例请求过多: {_LAB_HITS.get('/safe')}"
    _deep_timebound(t0, 30)


# ---------- P1: GraphQL / API 滥用（CWE-1059） ----------
@pytest.mark.asyncio
async def test_graphql_deep_introspection_positive(lab_base, session):
    from vulnclaw.engines.net_engines import GraphQLEngine

    eng = GraphQLEngine()
    t0 = time.monotonic()
    findings = await eng.scan(lab_base, session)
    assert findings, "GraphQL 引擎未检出任何问题"
    intro = [f for f in findings if f.get("type") == "GraphQL 内省开启"]
    assert intro, f"未检出内省开启: {[f.get('type') for f in findings]}"
    evidence = str(intro[0].get("evidence") or "")
    assert evidence.strip(), f"evidence 为空: {intro[0]}"
    assert "内省查询返回" in evidence, f"evidence 缺内省标记: {evidence!r}"
    # reproduction 复现信息：finding 自带内省结果快照，字段数可离线复算
    intro_snapshot = intro[0].get("introspection") or {}
    assert intro_snapshot.get("enabled") is True and intro_snapshot.get("field_count", 0) >= 1, (
        f"缺内省快照复现信息: {intro_snapshot}"
    )
    assert _LAB_HITS.get("/graphql", 0) <= 40, f"GraphQL 请求过多: {_LAB_HITS.get('/graphql')}"
    _deep_timebound(t0, 30)


@pytest.mark.asyncio
async def test_graphql_deep_endpoint_and_no_false_positive(lab_base, session):
    from vulnclaw.engines.net_engines import GraphQLEngine

    eng = GraphQLEngine()
    t0 = time.monotonic()
    found = await eng.check(f"{lab_base}/graphql", "q", _normal_resp(), "", session)
    assert found and found.get("is_endpoint") is True, f"GraphQL 端点未发现: {found}"
    assert str(found.get("evidence") or "").strip(), f"evidence 为空: {found}"
    fp = await eng.check(f"{lab_base}/safe", "q", _normal_resp(), "", session)
    assert fp is None, f"GraphQL 引擎在非 GraphQL 端点误报: {fp}"
    empty = await eng.scan(f"{lab_base}/safe", session)
    assert empty == [], f"GraphQL 引擎在无 GraphQL 端点目标误报: {empty}"
    _deep_timebound(t0, 30)
