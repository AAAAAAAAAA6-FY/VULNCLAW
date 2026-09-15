# -*- coding: utf-8 -*-
"""评测闭环脚本（scripts/eval_prf.py）专项测试：声明匹配口径 + 组件/IDOR 判定。

为什么要单测这个脚本：
  它是整条声明线的"数字标尺"——标尺自身口径出错（匹配虚高/静默漏配），
  所有"改进前 vs 改进后"的评测结论都会失真。这里把口径钉死为可回归的断言：
  expect 关键词 → 声明 id 必须是**分词 token 精确相等**（v4 口径），
  NA（无声明覆盖）与误配都必须可复现。
"""
import asyncio
import json
import logging
import os
import re
import sys

import pytest

from vulnclaw.core.attack_surface import spec_from_url
from vulnclaw.core.vulnspec import (BUILTIN_SPECS, SpecRunner, from_dict, get_spec,
                                    validate)

# scripts/ 不是可导入包，按文件位置注入后直接 import
_SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)
import eval_prf  # noqa: E402

# eval_prf 模块级 logging.disable(INFO) 是全局副作用，import 后恢复，避免污染其它用例
logging.disable(logging.NOTSET)


def _fake_specs(*ids):
    return [from_dict({"id": i, "name": i, "category": "c", "payloads": ["p"],
                       "detect": {"type": "regex", "patterns": ["x"]}}) for i in ids]


def _toks(spec_id):
    return re.split(r"[_\-]", spec_id.lower())


# ---------------------------------------------------------------- 匹配口径
def test_specs_for_is_exact_token_match_not_prefix():
    """v4 口径：分词 token **精确相等**。短词 "sql" 不得命中 "sqli_time_blind"。"""
    fake = _fake_specs("sql_error", "sqli_time_blind", "nosql_injection")
    got = {s.id for s in eval_prf._specs_for(["sql"], fake)}
    assert got == {"sql_error"}, f"精确匹配应只中 sql_error，实得 {got}"


def test_specs_for_no_substring_misfire():
    """任意子串口径（v1 坑）不复存在："nosql" 不得命中 sql_error。"""
    fake = _fake_specs("sql_error", "nosql_injection")
    got = {s.id for s in eval_prf._specs_for(["nosql"], fake)}
    assert got == {"nosql_injection"}


def test_specs_for_empty_alias_means_na():
    """"信息泄露" 显式映射空列表 → 无声明覆盖（NA），绝不误配到别的声明。"""
    assert eval_prf._specs_for(["信息泄露"], BUILTIN_SPECS) == []


def test_specs_for_deserialization_full_token():
    """反序列化族：alias 用完整 token，能精确命中 java_deserialization。"""
    ids = {s.id for s in eval_prf._specs_for(["反序列化"], BUILTIN_SPECS)}
    assert "java_deserialization" in ids


@pytest.mark.parametrize("word,expect_id", [
    ("XSS", "xss_reflect"),
    ("nosql", "nosql_injection"),
    ("LDAP", "ldap_injection"),
    ("组件", "component_version_disclosure"),
    ("越权", "idor_unauthorized_access"),
    ("开放重定向", "open_redirect"),
])
def test_specs_for_expected_families(word, expect_id):
    ids = {s.id for s in eval_prf._specs_for([word], BUILTIN_SPECS)}
    assert expect_id in ids, f"{word} 应命中 {expect_id}，实得 {ids}"


def test_alias_tokens_are_complete_tokens():
    """_ALIAS 非空值必须是**完整 token**（精确可命中），否则精确口径下会静默漏配。"""
    all_toks = set()
    for d in BUILTIN_SPECS:
        all_toks.update(_toks(d.id))
    redundant = {"unauth", "env"}  # 兼词：无独立声明，保留无害
    for key, toks in eval_prf._ALIAS.items():
        for t in toks:
            assert t in all_toks or t in redundant, f"_ALIAS[{key!r}] 含非完整 token {t!r}"
    # 反序列化必须是完整 token（v3 的 "deserial" 在精确口径下会漏配）
    assert eval_prf._ALIAS["反序列化"] == ["deserialization"]


# ---------------------------------------------------------------- 组件判定
def test_component_hits_vulnerable_vs_fixed():
    decl = get_spec("component_version_disclosure")
    assert decl.detect.component_hits("/*! jQuery v1.7.1 */")[0][0] == "jQuery"
    assert decl.detect.component_hits("/*! jQuery v3.6.0 */") == []  # 已修复版本不报
    assert decl.detect.component_hits("/*! jQuery UI - v1.12.1 */")[0][0] == "jQuery UI"
    assert decl.detect.component_hits("/*! axios v0.21.1 */")[0][0] == "axios"
    assert decl.detect.component_hits("plain page") == []


def test_jquery_ui_signature_does_not_collide_with_jquery():
    """jQuery UI 文本不应被 jQuery 签名误配（两 pattern 必须可区分）。"""
    decl = get_spec("component_version_disclosure")
    libs = {h[0] for h in decl.detect.component_hits("/*! jQuery UI - v1.12.1 */")}
    assert libs == {"jQuery UI"}


def test_component_new_libs_pdf_chartjs():
    """加厚第三批：pdf.js(任意JS执行) / Chart.js(原型污染) 的脆弱-已修复两侧都锁死。"""
    decl = get_spec("component_version_disclosure")
    assert decl.detect.component_hits("/*! pdf.js v2.16.105 */")[0][0] == "pdf.js"
    assert decl.detect.component_hits("/*! Chart.js v2.9.3 */")[0][0] == "Chart.js"
    assert decl.detect.component_hits("/*! pdf.js v4.2.67 */") == []   # 阈值版本起已修复
    assert decl.detect.component_hits("/*! Chart.js v4.4.0 */") == []


def test_component_multi_branch_must_not_over_report():
    """同库多分支：老版本只报本分支 CVE，不得被另一分支阈值二次命中（防错 CVE 假报）。"""
    decl = get_spec("component_version_disclosure")
    hits_3 = [h for h in decl.detect.component_hits("/*! Bootstrap v3.3.7 */") if h[0] == "Bootstrap"]
    assert len(hits_3) == 1 and hits_3[0][1] == "CVE-2019-8331"
    hits_4 = [h for h in decl.detect.component_hits("/*! Bootstrap v4.3.0 */") if h[0] == "Bootstrap"]
    assert len(hits_4) == 1 and hits_4[0][1] == "CVE-2018-14041"
    assert decl.detect.component_hits("/*! Bootstrap v5.3.3 */") == []   # 5.x 两分支均不适用


def test_manifest_short_package_name_boundary():
    """短包名左边界：npm "ws" 不得被子串命中。

    重要教训：负样本**不能用真实存在的包名**。aws-sdk 本身就是真包且确有公告，
    接了 KB 之后它会命中 —— 拿它当"不该命中"的样例会得到完全错误的结论。
    """
    decl = get_spec("dependency_manifest")
    assert decl.detect.component_hits('{"xwsy-not-a-real-pkg":"2.0.0"}') == []
    assert decl.detect.component_hits('{"dependencies":{"ws":"8.16.0"}}')[0][0] == "npm:ws"
    # "已修复"侧用**高于所有已知上界**的版本，别猜"某个版本就算修好"
    assert decl.detect.component_hits('{"dependencies":{"ws":"99.0.0"}}') == []


def test_manifest_new_ecosystems():
    """加厚第三批依赖生态：npm/pip/maven 三条新签名必须命中且阈值正确。"""
    decl = get_spec("dependency_manifest")
    assert decl.detect.component_hits('{"express":"4.16.0"}')[0][0] == "npm:express"
    assert decl.detect.component_hits('{"ejs":"3.1.6"}')[0][0] == "npm:ejs"
    assert decl.detect.component_hits("jinja2==3.1.2")[0][0] == "pip:jinja2"
    assert decl.detect.component_hits("setuptools==65.5.0")[0][0] == "pip:setuptools"
    maven = ('<artifactId>fastjson</artifactId><version>1.2.80</version>')
    assert decl.detect.component_hits(maven)[0][0] == "maven:fastjson"
    # 已修复侧：用**高于所有已知上界**的版本。
    # 注意 jinja2 3.1.3 曾被当成"已修复"（CVE-2024-22195 修复版），但 KB 里有
    # 更新的公告（fixed=3.1.6）→ 它其实仍受影响，不能拿来当"已修复"样本。
    assert decl.detect.component_hits("jinja2==99.0.0") == []
    assert decl.detect.component_hits("setuptools==99.0.0") == []


# ---------------------------------------------------------------- IDOR 多会话
def test_idor_decl_is_valid_multisession():
    decl = get_spec("idor_unauthorized_access")
    assert decl.detect.type == "idor_multisession"
    assert validate(decl) == []


def test_idor_validate_requires_owner_marker():
    bad = from_dict({"id": "i", "name": "i", "category": "c", "payloads": ["probe"],
                     "detect": {"type": "idor_multisession", "extra": {}}})
    assert any("owner_marker" in e for e in validate(bad))


@pytest.mark.asyncio
async def test_idor_multisession_confirms_cross_identity_read():
    """属主与非属主两种身份都读到属主数据 → 越权证实。"""
    decl = get_spec("idor_unauthorized_access")

    async def _req(spec):
        return (200, "<pre>admin: admin@corp.local / role=owner</pre>", {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/user?id=1"))
    assert out and out[0]["type"] == "idor_unauthorized_access"
    assert "IDOR" in out[0]["evidence"]


@pytest.mark.asyncio
async def test_idor_multisession_rejects_when_attacker_denied():
    """非属主被拒（403）→ 不越权，不报（避免把公开数据/正常鉴权当越权）。"""
    decl = get_spec("idor_unauthorized_access")

    async def _req(spec):
        if "attacker" in str(spec.headers.get("Cookie", "")):
            return (403, "forbidden", {})
        return (200, "<pre>admin: admin@corp.local / role=owner</pre>", {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/user?id=1")) == []


@pytest.mark.asyncio
async def test_idor_multisession_rejects_when_owner_data_absent():
    """属主都读不到属主数据（数据不存在/公开）→ 无从证实，不报。"""
    decl = get_spec("idor_unauthorized_access")

    async def _req(spec):
        return (200, "<pre>public info, no owner data</pre>", {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/user?id=1")) == []


# ---------------------------------------------------------------- flow 多请求流程
def test_flow_decl_is_valid():
    assert validate(get_spec("stored_xss")) == []
    assert validate(get_spec("second_order_sqli")) == []
    assert get_spec("stored_xss").detect.type == "flow"


def test_flow_validate_requires_write_and_read():
    bad = from_dict({"id": "f", "name": "f", "category": "c", "payloads": ["p"],
                     "detect": {"type": "flow", "extra": {"flow": {}}}})
    assert any("flow" in e for e in validate(bad))


@pytest.mark.asyncio
async def test_flow_stored_xss_confirms_when_unescaped():
    """写入后回读，payload 未被转义 → 存储型 XSS 证实。"""
    decl = get_spec("stored_xss")

    async def _req(spec):
        if "/guestbook/list" in spec.url:
            return (200, '<div><script>alert(1)</script></div>', {})
        return (200, "stored", {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/guestbook?msg=hello"))
    assert out and out[0]["type"] == "stored_xss"


@pytest.mark.asyncio
async def test_flow_stored_xss_rejects_when_escaped():
    """回读时 payload 已被 HTML 转义 → 不可执行，不报。"""
    decl = get_spec("stored_xss")

    async def _req(spec):
        if "/guestbook/list" in spec.url:
            return (200, '<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>', {})
        return (200, "stored", {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/guestbook?msg=hello")) == []


@pytest.mark.asyncio
async def test_flow_second_order_confirms_on_sql_error():
    """写入的引号被二次拼接进查询 → 回读报 SQL 错 → 二次注入证实。"""
    decl = get_spec("second_order_sqli")

    async def _req(spec):
        if "/notes/search" in spec.url:
            return (500, "SQLite error: SELECT * FROM notes WHERE body=' near syntax error", {})
        return (200, "note saved", {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/notes?note=1"))
    assert out and out[0]["type"] == "second_order_sqli"


@pytest.mark.asyncio
async def test_flow_second_order_rejects_when_clean():
    """回读无异常（参数化）→ 不报。"""
    decl = get_spec("second_order_sqli")

    async def _req(spec):
        return (200, "search ok", {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/notes?note=1")) == []


# ---------------------------------------------------------------- 依赖清单审计（SCA）
def test_component_hits_manifest_scan():
    """依赖清单：从包名+版本提取并对照脆弱阈值（复用 component oracle）。"""
    decl = get_spec("dependency_manifest")
    assert decl.detect.component_hits('{"dependencies":{"lodash":"4.17.20"}}')[0][0] == "npm:lodash"
    assert decl.detect.component_hits("Django==3.2.10\nrequests==2.25.0")[0][0] == "pip:django"
    # lodash 4.17.21 长期被视为"已修复"（CVE-2020-8203 的修复版），但 KB 里有
    # 2025 年的新公告（fixed=4.18.0）→ 以 KB 为准，它**仍受影响**。
    assert decl.detect.component_hits('{"dependencies":{"lodash":"4.17.21"}}')
    # 高于所有已知上界 → 不报
    assert decl.detect.component_hits('{"dependencies":{"lodash":"99.0.0"}}') == []
    assert decl.detect.component_hits("Django==99.0.0") == []


def test_manifest_decl_is_valid():
    assert validate(get_spec("dependency_manifest")) == []


def test_graphql_ignores_our_own_payload_echo():
    """外部实测（httpbin）踩过的假报：回显服务把我们发出去的 payload 原样返回，
    旧判据只搜 `__schema` 字样 → 把"我方载荷的回显"当成"内省开放"。
    修正后只认内省响应的 **JSON 键形态**。"""
    d = get_spec("graphql_introspection")
    echo = '{"args": {"q": "{__schema{types{name}}}"}}'          # 回显，不是内省
    real = '{"data": {"__schema": {"queryType": {"name": "Query"}}}}'  # 真内省响应
    assert not any(re.search(p, echo, re.I) for p in d.detect.patterns)
    assert any(re.search(p, real, re.I) for p in d.detect.patterns)


# ---------------------------------------------------------------- DOM XSS（浏览器执行）
def test_dom_xss_decl_is_valid():
    d = get_spec("dom_xss")
    assert d.detect.type == "dom_xss"
    assert d.detect.extra.get("path") == "/dom-xss"
    assert validate(d) == []


def test_dom_validate_requires_path():
    bad = from_dict({"id": "d", "name": "d", "category": "c", "payloads": ["p"],
                     "detect": {"type": "dom_xss", "extra": {}}})
    assert any("path" in e for e in validate(bad))


# ---------------------------------------------------------------- 业务逻辑（不变量）
def test_biz_decls_are_valid():
    assert validate(get_spec("biz_negative_amount")) == []
    assert validate(get_spec("biz_coupon_reuse")) == []


def test_biz_validate_requires_path_and_mode():
    bad = from_dict({"id": "b", "name": "b", "category": "c", "payloads": ["p"],
                     "detect": {"type": "biz_logic", "extra": {"logic": {}}}})
    assert any("biz_logic" in e for e in validate(bad))


@pytest.mark.asyncio
async def test_biz_violation_confirms_illegal_value_accepted():
    """非法金额（负数/零）被服务端接受 → 业务校验缺失。"""
    decl = get_spec("biz_negative_amount")

    async def _req(spec):
        return (200, '{"status":"created","total":-100}', {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/order?price=100"))
    assert out and out[0]["type"] == "biz_negative_amount"


@pytest.mark.asyncio
async def test_biz_violation_rejects_valid_amount():
    """金额合法（正数）→ 不变量未被破坏，不报。"""
    decl = get_spec("biz_negative_amount")

    async def _req(spec):
        return (200, '{"status":"created","total":100}', {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/order?price=100")) == []


@pytest.mark.asyncio
async def test_biz_repeatable_confirms_double_success():
    """一次性操作连发两次都成功 → 可重复使用。"""
    decl = get_spec("biz_coupon_reuse")

    async def _req(spec):
        return (200, '{"status":"applied","discount":10}', {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/coupon?code=SAVE10"))
    assert out and out[0]["type"] == "biz_coupon_reuse"


@pytest.mark.asyncio
async def test_biz_repeatable_rejects_second_time_denied():
    """第二次被拒（一次性生效）→ 不变量成立，不报。"""
    decl = get_spec("biz_coupon_reuse")
    state = {"n": 0}

    async def _req(spec):
        state["n"] += 1
        if state["n"] >= 2:
            return (200, '{"status":"rejected","reason":"already used"}', {})
        return (200, '{"status":"applied","discount":10}', {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api/coupon?code=SAVE10")) == []


# ---------------------------------------------------------------- 外部测试集 / 真实目标
# 为什么这些用例重要：自建靶场的 100% 只证明"实现没写错"，不证明"真实世界能检出"。
# 外部测试集入口一旦口径出错（把失败当干净、把类别级剧本当端点真值），
# 评测会给出"看似有据、实则无据"的数字——比没有评测更危险。
def test_manifest_load_ok(tmp_path):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({
        "name": "x", "target": "http://127.0.0.1:1/",
        "endpoints": {"/a?q=": {"expect": ["XSS"]}}, "negatives": {"/": "d"},
    }), encoding="utf-8")
    m = eval_prf._load_manifest(str(p))
    assert m["target"] == "http://127.0.0.1:1/" and "/a?q=" in m["endpoints"]


def test_manifest_rejects_category_level_script(tmp_path):
    """类别级剧本（只有 expected_vulns、无端点级真值）必须被拒绝。"""
    p = tmp_path / "dvwa_like.json"
    p.write_text(json.dumps({"target": "http://x/", "endpoints": [{"name": "dvwa"}]}),
                 encoding="utf-8")
    with pytest.raises(SystemExit) as ei:
        eval_prf._load_manifest(str(p))
    assert "类别级剧本" in str(ei.value)


def test_manifest_rejects_missing_target(tmp_path):
    p = tmp_path / "n.json"
    p.write_text(json.dumps({"endpoints": {}}), encoding="utf-8")
    with pytest.raises(SystemExit):
        eval_prf._load_manifest(str(p))


def test_manifest_rejects_unknown_path():
    with pytest.raises(SystemExit):
        eval_prf._load_manifest("no_such_manifest_xyz.json")


@pytest.mark.parametrize("url,local", [
    ("http://127.0.0.1:8090/x", True),
    ("http://localhost:8090/", True),
    ("http://192.168.1.9/", True),
    ("http://10.1.2.3/", True),
    ("http://172.16.0.1/", True),
    ("http://172.32.0.1/", False),   # 172.32 不在私网段，不能被当成自有环境
    ("http://demo.testfire.net/", False),
    ("not-a-url", False),
])
def test_local_target_classification(url, local):
    assert eval_prf._is_loopback_or_local(url) is local


@pytest.mark.asyncio
async def test_manifest_fail_closed_when_preflight_fails(tmp_path, monkeypatch):
    """预检失败必须 fail-closed（返回 2），绝不产出"0 命中=干净"的结论。"""
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"target": "http://demo.testfire.net",
                             "endpoints": {"/a?q=": {"expect": ["XSS"]}}}), encoding="utf-8")

    async def _fake_pre(url):
        return False, "Cannot connect to host 127.0.0.1:8080"

    monkeypatch.setattr(eval_prf, "_preflight", _fake_pre)
    rc = await eval_prf._main(False, "spec", "", [str(p)], False, True, False)
    assert rc == 2


@pytest.mark.asyncio
async def test_live_refuses_external_without_authorization():
    """未声明授权时外部目标必须拒绝（返回 3），且不发任何请求。"""
    assert await eval_prf._run_live("http://demo.testfire.net/", authorized=False) == 3


# ---------------------------------------------------------------- 带外回连 OOB（盲漏洞）
def test_oob_decls_are_valid():
    for sid in ("blind_ssrf", "cmd_blind"):
        d = get_spec(sid)
        assert d.detect.type == "oob" and d.detect.extra.get("path")
        assert validate(d) == []


def test_oob_validate_requires_path():
    bad = from_dict({"id": "o", "name": "o", "category": "c", "payloads": ["p"],
                     "detect": {"type": "oob", "extra": {}}})
    assert any("path" in e for e in validate(bad))


@pytest.mark.asyncio
async def test_oob_fail_closed_without_channel(monkeypatch):
    """未配置回调基址 / 命中通道时必须 **fail-closed：不注入回调地址、不产生结论**。

    注意口径：run() 无论什么 oracle 都会先发一次**基线**请求（取响应做对照），
    所以"fail-closed"指的是**不注入 OOB 回调地址**，而不是"一个请求都不发"。
    """
    from vulnclaw.core import vulnspec  # noqa: F401  (确保配置模块已加载)
    from vulnclaw.config import settings
    decl = from_dict({"id": "oob_x", "name": "x", "category": "c", "payloads": ["p"],
                      "detect": {"type": "oob", "extra": {"path": "/blind"}}})

    for base_url, hits_file in (("", "/tmp/x"), ("http://127.0.0.1:9999", "")):
        monkeypatch.setattr(settings, "oob_base_url", base_url)
        monkeypatch.setattr(settings, "oob_hits_file", hits_file)
        called = []

        async def _req(spec):
            called.append(spec.url)
            return (200, "ok", {})

        out = await SpecRunner(specs=[decl], requester=_req).run(
            spec_from_url("https://x.test/blind?url=1"))
        assert out == []
        assert not any("9999" in u for u in called), "fail-closed 时不得注入回调地址"


@pytest.mark.asyncio
async def test_oob_confirms_when_target_calls_back(tmp_path, monkeypatch):
    """目标侧回连 → 命中（盲漏洞的唯一可靠判据）。"""
    from vulnclaw.config import settings
    hits = tmp_path / "hits.txt"
    monkeypatch.setattr(settings, "oob_base_url", "http://127.0.0.1:9999")
    monkeypatch.setattr(settings, "oob_hits_file", str(hits))
    monkeypatch.setattr(settings, "oob_wait_seconds", 2.0)
    decl = from_dict({"id": "oob_x", "name": "x", "category": "c", "payloads": ["p"],
                      "detect": {"type": "oob", "extra": {"path": "/blind"}}})

    async def _req(spec):
        m = re.search(r"vlc\d+", spec.url)
        if m:  # 模拟"目标侧回连"，把 token 写进命中通道
            hits.write_text(m.group(0) + "\n", encoding="utf-8")
        return (200, "ok", {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/blind?url=1"))
    assert out and out[0]["type"] == "oob_x"


@pytest.mark.asyncio
async def test_oob_rejects_when_no_callback(tmp_path, monkeypatch):
    """无回连 → 不报（响应里没痕迹不等于有漏洞）。"""
    from vulnclaw.config import settings
    monkeypatch.setattr(settings, "oob_base_url", "http://127.0.0.1:9999")
    monkeypatch.setattr(settings, "oob_hits_file", str(tmp_path / "empty.txt"))
    monkeypatch.setattr(settings, "oob_wait_seconds", 1.0)
    decl = from_dict({"id": "oob_x", "name": "x", "category": "c", "payloads": ["p"],
                      "detect": {"type": "oob", "extra": {"path": "/blind"}}})

    async def _req(spec):
        return (200, "ok", {})

    assert await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/blind?url=1")) == []


@pytest.mark.asyncio
async def test_runner_counts_request_errors():
    """请求失败（状态 0）必须计数——否则"网络故障"与"目标干净"在结果里无法区分。"""
    async def _boom(spec):
        return (0, "Network error: Cannot connect to host 127.0.0.1:8080", {})

    r = SpecRunner(specs=[get_spec("xss_reflect")], requester=_boom)
    await r.run(spec_from_url("https://x.test/a?q=1"))
    assert r.request_errors > 0


def _short_time_spec():
    return from_dict({"id": "t_time", "name": "t", "category": "c", "payloads": ["p"],
                      "detect": {"type": "time", "threshold": 0.05}})


def _kb_ready() -> bool:
    """组件 KB 是否可用（由 scripts/build_component_kb.py 生成，产物不入库）。"""
    try:
        from vulnclaw.core.vulnspec.model import _load_component_kb
        from vulnclaw.config import settings
        return bool(_load_component_kb(str(getattr(settings, "component_kb_path", "") or "")))
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------- 组件知识库 KB（OSV）
def test_version_in_range_semantics():
    """OSV 区间语义：[introduced, fixed)；fixed 为空 = 至今未修（无上界）。"""
    from vulnclaw.core.vulnspec.model import _version_in_range
    assert _version_in_range("2.5.12", "2.0.0", "2.5.33")
    assert not _version_in_range("2.5.33", "2.0.0", "2.5.33")   # 上界开区间
    assert _version_in_range("1.0.0", "0", "")                   # 无上界
    assert not _version_in_range("1.0.0", "2.0.0", "")           # 低于下界


@pytest.mark.skipif(not _kb_ready(), reason="KB 未生成（先跑 scripts/build_component_kb.py）")
def test_kb_matches_maven_groupid_artifactid():
    """Maven 包名是 **groupId:artifactId** —— 只取 artifactId 会查不到（实测踩过）。"""
    decl = get_spec("dependency_manifest")
    pom = ('<dependency><groupId>org.apache.struts</groupId>'
           '<artifactId>struts2-core</artifactId><version>2.5.12</version></dependency>')
    libs = {h[0] for h in decl.detect.component_hits(pom)}
    assert any("struts2-core" in l for l in libs), libs


@pytest.mark.skipif(not _kb_ready(), reason="KB 未生成")
def test_kb_catches_newer_cve_than_handwritten_threshold():
    """KB 的新鲜度价值：log4j-core 2.17.1 手写阈值判"已修复"，KB 有更新公告 → 应命中。"""
    decl = get_spec("dependency_manifest")
    pom = ('<dependency><groupId>org.apache.logging.log4j</groupId>'
           '<artifactId>log4j-core</artifactId><version>2.17.1</version></dependency>')
    hits = decl.detect.component_hits(pom)
    assert any("log4j-core" in h[0] for h in hits), hits


@pytest.mark.skipif(not _kb_ready(), reason="KB 未生成")
def test_kb_no_false_positive_for_unknown_package():
    decl = get_spec("dependency_manifest")
    pom = ('<dependency><groupId>com.example</groupId>'
           '<artifactId>totally-not-a-real-pkg-xyz</artifactId><version>9.9.9</version></dependency>')
    libs = {h[0] for h in decl.detect.component_hits(pom)}
    assert not any("totally-not-a-real-pkg-xyz" in l for l in libs), libs


@pytest.mark.asyncio
async def test_time_oracle_rejects_single_spike():
    """时间型 oracle 单次抖动不得判为漏洞（真实网络误报源头，必须复测确认）。"""
    n = {"i": 0}

    async def _req(spec):
        n["i"] += 1
        if n["i"] == 2:          # 1=baseline, 2=首次注入（模拟一次远端抖动）, 3=复测
            await asyncio.sleep(0.09)
        return (200, "ok", {})

    out = await SpecRunner(specs=[_short_time_spec()], requester=_req).run(
        spec_from_url("https://x.test/a?q=1"))
    assert out == []


@pytest.mark.asyncio
async def test_time_oracle_confirms_repeated_delay():
    """延时可复现（真盲注/真 RCE 是确定性的）→ 才判定命中。"""
    n = {"i": 0}

    async def _req(spec):
        n["i"] += 1
        await asyncio.sleep(0.02 if n["i"] == 1 else 0.09)
        return (200, "ok", {})

    out = await SpecRunner(specs=[_short_time_spec()], requester=_req).run(
        spec_from_url("https://x.test/a?q=1"))
    assert out and out[0]["type"] == "t_time"
