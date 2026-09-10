# -*- coding: utf-8 -*-
"""声明式知识库专项测试：模型校验 + 四类 oracle + 执行器预算控制。

全部用注入的 requester 模拟响应（requester 收到 RequestSpec）。
"""
import asyncio

import pytest

from vulnclaw.core.attack_surface import spec_from_url
from vulnclaw.core.vulnspec import SpecRunner, from_dict, get_spec, validate


def _req_for(mapping, default=(200, "ok", {})):
    """按 URL 片段分派响应（用于区分基线请求与注入请求）。"""
    async def _req(spec):
        for needle, resp in mapping.items():
            if needle in spec.url:
                return resp
        return default
    return _req


# ---------------------------------------------------------------- 模型
def test_builtin_specs_are_valid():
    for sid in ("sql_error", "xss_reflect", "sqli_time_blind", "cmd_injection",
                "lfi", "ssrf_internal", "xxe", "ssti", "crlf",
                "open_redirect", "nosql_injection", "ldap_injection",
                "java_deserialization", "dotnet_deserialization", "php_object_injection",
                "python_pickle_injection", "graphql_introspection", "xpath_injection",
                "log4shell", "ssi_injection", "el_injection", "rfi"):
        assert validate(get_spec(sid)) == [], f"{sid} 声明不合法"


def test_validate_reports_missing_fields():
    bad = from_dict({"id": "b", "name": "b", "category": "c",
                     "payloads": [], "detect": {"type": "regex"}})
    errs = validate(bad)
    assert any("payloads" in e for e in errs)
    assert any("patterns" in e for e in errs)


def test_validate_reports_bad_time_threshold():
    bad = from_dict({"id": "t", "name": "t", "category": "c",
                     "payloads": ["x"], "detect": {"type": "time", "threshold": 0}})
    assert any("threshold" in e for e in validate(bad))


def test_applies_to_location_and_param_hints():
    lfi = get_spec("lfi")
    assert lfi.applies_to("query", "file") is True      # 命中 param_hints
    assert lfi.applies_to("query", "q") is False        # 参数名不匹配 -> 不适用
    only_query = from_dict({"id": "x", "name": "x", "category": "c",
                            "payloads": ["p"], "detect": {"type": "regex", "patterns": ["a"]},
                            "locations": ["query"]})
    assert only_query.applies_to("query", "any") is True
    assert only_query.applies_to("body_json", "any") is False


# ---------------------------------------------------------------- oracle
@pytest.mark.asyncio
async def test_regex_oracle_hits():
    runner = SpecRunner(specs=[get_spec("sql_error")],
                        requester=_req_for({"%27": (500, "You have an error in your SQL syntax", {})}))
    out = await runner.run(spec_from_url("https://x.test/search?q=test"))
    assert out and out[0]["type"] == "sql_error"
    assert out[0]["point_location"] == "query"


@pytest.mark.asyncio
async def test_regex_oracle_no_hit_on_clean_response():
    runner = SpecRunner(specs=[get_spec("sql_error")], requester=_req_for({}))
    assert await runner.run(spec_from_url("https://x.test/search?q=test")) == []


@pytest.mark.asyncio
async def test_reflect_oracle_ignores_baseline_echo():
    """基线里已存在的字符串不算反射（避免把正常回显当漏洞）。"""
    decl = from_dict({"id": "r", "name": "r", "category": "c",
                      "payloads": ["<script>alert(1)</script>"],
                      "detect": {"type": "reflect", "extra": {"core": "alert(1)"}}})
    # 基线响应里就已经有 alert(1)（如静态页面自带）-> 不算反射
    runner = SpecRunner(specs=[decl], requester=_req_for({}, default=(200, "alert(1) static", {})))
    assert await runner.run(spec_from_url("https://x.test/p?q=test")) == []

    # 基线没有、注入后出现 -> 命中
    runner2 = SpecRunner(specs=[decl], requester=_req_for(
        {"script": (200, "echo <script>alert(1)</script>", {})}, default=(200, "plain", {})))
    out = await runner2.run(spec_from_url("https://x.test/p?q=test"))
    assert out and out[0]["type"] == "r"


@pytest.mark.asyncio
async def test_time_oracle_hits_on_delay():
    decl = from_dict({"id": "t", "name": "t", "category": "c",
                      "payloads": ["SLEEP"], "detect": {"type": "time", "threshold": 0.05}})

    async def _req(spec):
        if "SLEEP" in spec.url:
            await asyncio.sleep(0.1)
            return (200, "slow", {})
        return (200, "fast", {})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/api?q=1"))
    assert out and out[0]["type"] == "t"


@pytest.mark.asyncio
async def test_diff_oracle_hits_on_big_change():
    decl = from_dict({"id": "d", "name": "d", "category": "c",
                      "payloads": ["P"], "detect": {"type": "diff", "threshold": 0.2}})
    runner = SpecRunner(specs=[decl], requester=_req_for(
        {"P": (200, "totally different response body here with other words", {})},
        default=(200, "same old same old", {})))
    out = await runner.run(spec_from_url("https://x.test/p?q=test"))
    assert out and out[0]["type"] == "d"


# ---------------------------------------------------------------- 执行器
@pytest.mark.asyncio
async def test_budget_caps_requests():
    """预算耗尽后不再发请求（防请求爆炸）。"""
    calls = {"n": 0}

    async def _req(spec):
        calls["n"] += 1
        return (200, "You have an error in your SQL syntax", {})

    runner = SpecRunner(specs=[get_spec("sql_error")], requester=_req)
    out = await runner.run(spec_from_url("https://x.test/search?q=test"), budget=1)
    assert calls["n"] == 1      # 只发了基线
    assert out == []


@pytest.mark.asyncio
async def test_header_oracle_detects_cors_wildcard():
    """响应头 oracle：ACAO 为 * 即命中。"""
    decl = from_dict({"id": "c", "name": "c", "category": "cors",
                      "payloads": ["probe"],
                      "detect": {"type": "header",
                                 "header_name": "Access-Control-Allow-Origin",
                                 "patterns": [r"^\*$"]}})

    async def _req(spec):
        return (200, "{}", {"Access-Control-Allow-Origin": "*"})

    out = await SpecRunner(specs=[decl], requester=_req).run(
        spec_from_url("https://x.test/a?x=1"))
    assert out and out[0]["type"] == "c"


@pytest.mark.asyncio
async def test_header_absent_flags_missing_hardening_header():
    """header_absent：安全头缺失即命中；存在则不报。"""
    decl = from_dict({"id": "m", "name": "m", "category": "hardening",
                      "payloads": ["probe"],
                      "detect": {"type": "header", "header_name": "X-Content-Type-Options",
                                 "header_absent": True}})

    async def _req_missing(spec):
        return (200, "ok", {"Content-Type": "text/html"})

    out = await SpecRunner(specs=[decl], requester=_req_missing).run(
        spec_from_url("https://x.test/a?x=1"))
    assert out and out[0]["type"] == "m"

    async def _req_present(spec):
        return (200, "ok", {"X-Content-Type-Options": "nosniff"})

    assert await SpecRunner(specs=[decl], requester=_req_present).run(
        spec_from_url("https://x.test/a?x=1")) == []


def test_validate_header_rule_requires_patterns_or_absent():
    bad = from_dict({"id": "h", "name": "h", "category": "c", "payloads": ["p"],
                     "detect": {"type": "header", "header_name": "X"}})
    assert any("header" in e for e in validate(bad))


@pytest.mark.asyncio
async def test_payload_injection_into_json_point():
    """声明可作用于 JSON 注入点（同一条声明，无需改代码）。"""
    async def _req(spec):
        if spec.json_obj and "id" in str(spec.json_obj.get("c", "")):
            return (200, '{"output":"uid=0(root) gid=0(root)"}', {})
        return (200, '{"output":"ok"}', {})

    runner = SpecRunner(specs=[get_spec("cmd_injection")], requester=_req)
    spec = spec_from_url("https://x.test/api/cmd", "POST", json_obj={"c": "ls"})
    out = await runner.run(spec)
    assert out and out[0]["type"] == "cmd_injection"
    assert out[0]["parameter"] == "json:c"
    assert out[0]["point_location"] == "body_json"


@pytest.mark.asyncio
async def test_regex_oracle_ssi_el_rfi_hits():
    """新增三条 regex 型声明（SSI / EL / RFI）各命中对应响应特征。"""
    cases = [
        ("ssi_injection", "page", "exec",
         (500, "[an error occurred while processing this directive]", {})),
        ("el_injection", "expr", "getClass",
         (500, "javax.el.ELException: Failed to parse expression", {})),
        ("rfi", "url", "rfi-probe",
         (500, "failed to open stream: http request failed", {})),
    ]
    for sid, param, marker, hit_resp in cases:
        runner = SpecRunner(specs=[get_spec(sid)], requester=_req_for({marker: hit_resp}))
        out = await runner.run(spec_from_url(f"https://x.test/p?{param}=test"))
        assert out and out[0]["type"] == sid, f"{sid} 未命中"
