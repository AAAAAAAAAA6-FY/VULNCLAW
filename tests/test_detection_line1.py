"""线1/线2 检出率提升专项用例（对应 复杂漏洞检出率提升方案.md）。

覆盖：
  - 线1 无参端点引擎适配：IDOR 路径ID提取/变形、JWT _jwt_accepted 400 分支、
    WeakCredential Basic 探测、_global_scan_endpoints dict 端点遍历；
  - 线2 引擎 payload 增强：SQLi WAF 绕过布尔对、时间盲注（2s 门限+逆命题合成）、
    SSRF 地址变形 + internal_secret 判定特征。

运行：python -m pytest tests/test_detection_line1.py -v
"""
import asyncio
import base64

import pytest
import pytest_asyncio
from aiohttp import web, ClientSession
from aiohttp.test_utils import TestServer


# ============================================================
# 迷你靶场（复刻 hard_lab 关键判定：WAF 过滤 / 2s 延时 / 地址变形回显 / Basic 认证）
# ============================================================
def _build_hard_lab_app():
    async def _waf_sqli(request):
        v = request.query.get("id", "")
        lv = v.lower()
        if any(k in lv for k in ("union", "--", "/*", "#", " or ")):
            return web.Response(text="<pre>WAF: 关键词被拒</pre>", status=403)
        if "1'1" in v or "1=1" in v.replace("%20", "") or "'or" in lv:
            return web.Response(text="<pre>2 rows returned</pre>")
        if "1'2" in v or "1=2" in v:
            return web.Response(text="<pre>0 rows returned</pre>")
        if "error" in lv:
            return web.Response(text='<pre>near "": syntax error</pre>', status=500)
        return web.Response(text=f"<pre>row: id={v[:1] if v else '?'}</pre>")

    async def _time_blind(request):
        v = request.query.get("id", "")
        if "sleep" in v.lower() or "benchmark" in v.lower():
            await asyncio.sleep(2.0)
            return web.Response(text="<pre>query done in 2.0s</pre>")
        if "1'='1" in v or "1=1" in v:
            await asyncio.sleep(0.05)
            return web.Response(text="<pre>ok</pre>")
        return web.Response(text="<pre>ok</pre>")

    async def _ssrf(request):
        v = request.query.get("url", "")
        lv = v.lower()
        if "127.0.0.1" in lv or "localhost" in lv:
            return web.Response(text="<pre>[blocked] 内网地址被过滤</pre>")
        if any(pat in lv for pat in ("2130706433", "0x7f", "127.1", "adr", "[::1]")):
            return web.Response(text="<pre>[fetch] <b>INTERNAL_SECRET_7f000001</b> len=18</pre>")
        return web.Response(text=f"<pre>[fetch] ok ({len(v)}ch)</pre>")

    async def _admin(request):
        au = request.headers.get("Authorization", "")
        if au.startswith("Basic "):
            try:
                c = base64.b64decode(au.split(" ", 1)[1]).decode()
            except Exception:
                c = ""
            if c == "admin:admin":
                return web.Response(text="<pre>default creds accepted: admin:admin</pre>")
        return web.Response(
            text="<pre>401: unauthorized</pre>", status=401,
            headers={"WWW-Authenticate": 'Basic realm="admin"'},
        )

    app = web.Application()
    app.router.add_get("/waf_sqli", _waf_sqli)
    app.router.add_get("/time_blind", _time_blind)
    app.router.add_get("/ssrf", _ssrf)
    app.router.add_get("/admin/default", _admin)
    return app


@pytest_asyncio.fixture
async def hard_lab():
    app = _build_hard_lab_app()
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


# ============================================================
# 线2.1 SQLi：WAF 绕过布尔对
# ============================================================
@pytest.mark.asyncio
async def test_sqli_waf_bypass_boolean_detected(hard_lab, session):
    from vulnclaw.engines.web_engines import SQLiEngine

    eng = SQLiEngine()
    eng.max_payloads = 12
    url = f"{hard_lab}/waf_sqli?id=1"
    async with ClientSession() as s:
        _st, _txt, _hdrs = await eng._get_fresh_normal_response(url, s)
    assert _txt is not None
    result = await eng.check(url, "id", (_st, _txt, _hdrs), "id=1", session)
    assert result, "SQLi WAF 绕过布尔对未检出 /waf_sqli"
    assert "SQL" in str(result.get("type", ""))


@pytest.mark.asyncio
async def test_sqli_time_blind_detected(hard_lab, session):
    from vulnclaw.engines.web_engines import SQLiEngine

    eng = SQLiEngine()
    eng.max_payloads = 12
    url = f"{hard_lab}/time_blind?id=1"
    async with ClientSession() as s:
        _st, _txt, _hdrs = await eng._get_fresh_normal_response(url, s)
    result = await eng.check(url, "id", (_st, _txt, _hdrs), "id=1", session)
    assert result, "SQLi 时间盲注（2s 门限+无注释 payload）未检出 /time_blind"
    assert "时间盲注" in str(result.get("type", ""))


@pytest.mark.asyncio
async def test_reverse_payload_waf_pairs():
    from vulnclaw.engines.web_engines import SQLiEngine

    eng = SQLiEngine()
    # 线2.1 精确逆 → "1'2"；A/B 成立（2 rows vs 0 rows）
    assert eng._generate_reverse_payload("1'1") == "1'2"
    assert eng._generate_reverse_payload("1'OR 1=1") == "1'OR 1=2"
    assert eng._generate_reverse_payload("1=1") == "1=2"
    # 逆命题仍含 sleep 关键字 → 合成恒真对照
    rp = eng._generate_reverse_payload("1' AND SLEEP(5)")
    assert "SLEEP(0)" in rp
    synth = __import__("re").sub(r"SLEEP\(\d+\)", "1=1", rp, flags=__import__("re").I)
    assert synth == "1' AND 1=1"


# ============================================================
# 线2.2 SSRF：地址变形 + 判定特征
# ============================================================
def test_ssrf_payloads_and_indicator():
    from vulnclaw.engines.net_engines import SSRFEngine

    eng = SSRFEngine()
    obf = [p for p, _ in eng.payloads
           if any(k in p for k in ("2130706433", "0x7f", "127.1", "0177"))]
    assert len(obf) >= 8, f"SSRF 地址变形 payload 不足: {len(obf)}"
    assert "internal_secret" in eng.SSRF_INDICATORS


@pytest.mark.asyncio
async def test_ssrf_addr_obfuscation_detected(hard_lab, session):
    from vulnclaw.engines.net_engines import SSRFEngine

    eng = SSRFEngine()
    url = f"{hard_lab}/ssrf?url=http://example.com"
    normal = (200, "<pre>[fetch] ok (20ch)</pre>", {})
    result = await eng.check(url, "url", normal, "url=http://example.com", session)
    assert result, "SSRF 地址变形未检出 /ssrf"
    assert "SSRF" in str(result.get("type", "")).upper()


# ============================================================
# 线1.4 引擎适配：IDOR / JWT / WeakCredential
# ============================================================
def test_idor_path_id_extraction_and_mutation():
    from vulnclaw.engines.auth_engines import IDOREngine

    eng = IDOREngine()
    assert eng._extract_id_params("/idor/profile/1") == [("id", "1")]
    assert eng._idor_url("/idor/profile/1", "id", "1001") == "/idor/profile/1001"
    # 路径型 ID 的相邻变形（scan 单会话差分线核心）
    assert eng._idor_url("/idor/profile/1", "id", "2") == "/idor/profile/2"


@pytest.mark.asyncio
async def test_jwt_accepted_400_branch(monkeypatch):
    from vulnclaw.engines import auth_engines

    async def _fake_get(ep, session=None, timeout=8, no_retry=True, headers=None):
        au = (headers or {}).get("Authorization", "")
        return (200, "", {}) if "forged" in au else (400, "", {})

    monkeypatch.setattr(auth_engines, "async_get", _fake_get)
    from vulnclaw.engines.auth_engines import JWTEngine

    eng = JWTEngine()
    assert await eng._jwt_accepted("http://x/jwt", "forged", None) is True


@pytest.mark.asyncio
async def test_weak_credential_basic_probe(hard_lab, session):
    from vulnclaw.engines.auth_engines import WeakCredentialEngine

    eng = WeakCredentialEngine()
    findings = await eng.scan(
        f"{hard_lab}/admin/default", session,
        endpoints=[f"{hard_lab}/admin/default"],
    )
    assert any("weak_credential_basic" == f.get("type") for f in findings), \
        "WeakCredential Basic 探测未检出 /admin/default"


# ============================================================
# 线1.2 _global_scan_endpoints dict 端点遍历
# ============================================================
def test_global_scan_endpoints_dict_items():
    from vulnclaw.ai.v100.phases.phases_executor import _global_scan_endpoints

    class _FakeOrch:
        target = "http://127.0.0.1:8091/"
        _recon_brief = {
            "crawled_endpoints": [
                {"url": "http://127.0.0.1:8091/jwt", "params": []},
                "http://127.0.0.1:8091/xss?s=1",
            ]
        }

    out = _global_scan_endpoints(_FakeOrch())
    assert "http://127.0.0.1:8091/jwt" in out, f"dict 型端点被跳过: {out}"
    assert "http://127.0.0.1:8091/xss" in out
