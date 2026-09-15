# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A2 核心层回归：schema / observations / features（纯确定性，零网络零 LLM）。"""
import json

from vulnclaw.core.business_ir import (
    build_ir_skeleton,
    cluster_paths,
    collect_observations,
    empty_ir,
    infer_domain,
    ir_summary,
    normalize_ir,
    path_template,
    validate_ir,
)
from vulnclaw.core.business_ir.features import classify_param_kind, guess_param_in


def _brief():
    return {
        "target": "http://shop.test",
        "tech_stack": ["nginx", "django"],
        "crawled_endpoints": [
            "http://shop.test/login",
            "http://shop.test/api/orders/123?expand=true",
            "http://shop.test/api/orders/456",
            "/api/cart/add",
        ],
        "js_endpoints": ["http://shop.test/api/user/profile"],
        "url_params": [{"url": "http://shop.test/api/orders/123?expand=true"}],
        "forms": [{"action": "/login", "method": "post", "fields": ["username", "password"]}],
    }


# ============================================================
# schema
# ============================================================
def test_empty_ir_and_validate_ok():
    ir = empty_ir("http://a/")
    assert ir["version"] == "ir-1" and validate_ir(ir) == []
    assert ir_summary(ir)["ok"] is True


def test_validate_ir_catches_structural_errors():
    bad = empty_ir()
    bad["version"] = "ir-0"
    bad["endpoints"] = [
        {"id": "e1", "method": "GET", "path": "/a", "params": []},
        {"id": "e1", "method": "GET", "path": "/b", "params": [
            {"name": "p", "in": "nope", "domain": {"kind": "wat"}}]},
    ]
    bad["transitions"] = [{"via_endpoint": "ghost"}]
    bad["invariants"] = [{"id": "i1", "expr": "not-a-dict"}]
    bad["goals"] = [{"desc": "no id"}]
    joined = " | ".join(validate_ir(bad))
    assert "版本不匹配" in joined and "重复" in joined and "非法" in joined
    assert "引用不存在的端点" in joined and "缺少 id" in joined
    assert validate_ir(None) == ["IR 不是字典"]


def test_normalize_ir_is_deterministic_and_dedupes():
    raw = {
        "target": "http://a/", "version": "ir-1",
        "endpoints": [
            {"id": "b", "method": "post", "path": "/o", "params": [
                {"name": "z", "in": "body"}, {"name": "a", "in": "query"}, {"name": "a"}]},
            {"id": "a", "method": "POST", "path": "/o", "params": [
                {"name": "a", "in": "query"}, {"name": "q", "in": "query"},
                {"name": "w", "in": "query"}]},
            {"id": "x", "method": "GET", "path": ""},
        ],
        "transitions": [{"via_endpoint": "ghost"},
                        {"via_endpoint": "a", "from_state": "s0", "to_state": "s1"}],
        "sources": [{"kind": "llm", "ref": "x"}, {"kind": "llm", "ref": "x"}],
    }
    out = normalize_ir(raw)
    assert len(out["endpoints"]) == 1                      # 同 (method,path) 合并去重
    # 等键合并时保留**参数更全**的那条（第二条有 a/q/w，胜出 → id="a"）
    assert out["endpoints"][0]["id"] == "a"
    assert [p["name"] for p in out["endpoints"][0]["params"]] == ["a", "q", "w"]
    # 悬空引用（ghost）被丢；引用存活端点的转移保留
    assert len(out["transitions"]) == 1 and out["transitions"][0]["via_endpoint"] == "a"
    assert out["sources"] == [{"kind": "llm", "ref": "x"}]
    assert json.dumps(out, sort_keys=True) == json.dumps(normalize_ir(raw), sort_keys=True)


# ============================================================
# observations
# ============================================================
def test_collect_observations_merges_sources_and_dedupes():
    obs = collect_observations(_brief())
    paths = {(e["method"], e["path"]) for e in obs["endpoints"]}
    assert ("GET", "/login") in paths
    assert ("GET", "/api/orders/123") in paths             # query 剥离并计入 params
    assert ("GET", "/api/cart/add") in paths               # 相对路径用 target 补全
    order = next(e for e in obs["endpoints"] if e["path"] == "/api/orders/123")
    assert order["params"] == [{"name": "expand", "in": "query", "samples": ["true"]}]
    assert obs["forms"][0]["fields"] == ["password", "username"]
    assert {s["kind"] for s in obs["sources"]} >= {"crawled_endpoints", "js_endpoints"}


def test_collect_observations_traces_and_garbage():
    obs = collect_observations(
        {"target": "http://a/"},
        traces=[{"method": "post", "url": "http://a/api/x", "status": 403, "body": "denied"},
                {"method": "GET", "url": "::bad::"}, {"nope": 1}, None])
    eps = {e["path"]: e for e in obs["endpoints"]}
    assert eps["/api/x"]["status"] == 403 and eps["/api/x"]["auth_required"] is True
    assert eps["/api/x"]["response_sample"] == "denied"
    assert collect_observations(None, None)["endpoints"] == []
    assert collect_observations({"crawled_endpoints": [None, 1, "http://"]})["endpoints"] == []


# ============================================================
# features
# ============================================================
def test_infer_domain_variants():
    assert infer_domain([]) == {"kind": "str"}
    assert infer_domain([True, False]) == {"kind": "enum", "values": [False, True]}
    assert infer_domain([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]) == {"kind": "int", "lo": 1, "hi": 11}
    assert infer_domain([1, 2]) == {"kind": "enum", "values": [1, 2]}
    assert infer_domain([1.5, 2.5]) == {"kind": "enum", "values": [1.5, 2.5]}
    assert infer_domain([1.5, 2.5, 3.5, 4.5, 5.5, 6.5, 7.5, 8.5, 9.5, 10.5, 11.5]) == \
        {"kind": "float", "lo": 1.5, "hi": 11.5}
    assert infer_domain(["aaa", "bbbb"]) == {"kind": "enum", "values": ["aaa", "bbbb"]}
    assert infer_domain(["x" * 40, "y" * 50]) == {"kind": "str", "max_len": 50}


def test_param_kind_and_location():
    assert classify_param_kind("order_id") == "int"
    assert classify_param_kind("total_amount") == "float"
    assert classify_param_kind("is_admin") == "bool"
    assert classify_param_kind("nickname") == "str"
    assert guess_param_in("id", "POST") == "body"
    assert guess_param_in("12345", "GET") == "path"
    assert guess_param_in("expand", "GET") == "query"


def test_path_template_and_cluster():
    assert path_template("/order/123/pay") == "/order/{id}/pay"
    assert path_template("/u/550e8400-e29b-41d4-a716-446655440000") == "/u/{id}"
    groups = cluster_paths([
        {"method": "get", "path": "/order/1", "params": [{"name": "a"}]},
        {"method": "POST", "path": "/order/2", "params": [{"name": "b"}]},
    ])
    assert len(groups) == 1 and groups[0]["methods"] == ["GET", "POST"]
    assert [p["name"] for p in groups[0]["params"]] == ["a", "b"]


def test_build_ir_skeleton_effects_auth_and_confidence():
    obs = collect_observations(_brief())
    for e in obs["endpoints"]:
        if e["path"] == "/api/user/profile":
            e["auth_required"] = True
    ir = build_ir_skeleton(obs, target="http://shop.test")
    assert validate_ir(ir) == [] and ir["confidence"] == 0.3
    login = next(e for e in ir["endpoints"] if e["path"] == "/login")
    assert login["effects"] == [] and login["idempotent"] is True
    prof = next(e for e in ir["endpoints"] if e["path"] == "/api/user/profile")
    assert prof["auth"]["required"] is True                # 只认 401/403 证据
    assert any(e["name"] == "user" for e in ir["entities"])
