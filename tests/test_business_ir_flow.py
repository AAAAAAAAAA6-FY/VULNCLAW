# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A2 流程层回归：LLM 增强（注入假客户端）/ 校验 / 幂等落盘 / 端到端构建。

hermetic：零网络、零真实 LLM；落盘走 tmp 目录。重点验证**降级**与**幻觉不进 IR**。
"""
import asyncio
import json

import pytest

from vulnclaw.core.business_ir import (
    IR_VERSION,
    attach_ir_to_brief,
    build_business_ir,
    build_ir_skeleton,
    collect_observations,
    empty_ir,
    load_ir,
    merge_fragment,
    refine_ir,
    save_ir,
    validate_and_fix,
    validate_ir,
)
from vulnclaw.core.business_ir import store as ir_store
from vulnclaw.core.business_ir.llm_extractor import extract_json


class _FakeClient:
    """假 LLM 客户端：可注入响应 / 异常 / 延迟（测超时降级）。"""

    def __init__(self, resp=None, exc=None, delay=0.0):
        self.resp, self.exc, self.delay = resp, exc, delay
        self.calls = []

    async def ask(self, prompt, **kw):
        self.calls.append({"prompt": prompt, **kw})
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.exc:
            raise self.exc
        return self.resp


def _brief():
    return {
        "target": "http://shop.test",
        "tech_stack": ["nginx"],
        "crawled_endpoints": [
            "http://shop.test/login",
            "http://shop.test/api/orders/123?expand=true",
        ],
        "js_endpoints": ["http://shop.test/api/user/profile"],
        "forms": [{"action": "/login", "method": "post", "fields": ["username"]}],
    }


def _skeleton():
    return build_ir_skeleton(collect_observations(_brief()), target="http://shop.test")


# ============================================================
# extract_json / merge_fragment
# ============================================================
def test_extract_json_tolerates_wrappers():
    assert extract_json('{"a":1}') == {"a": 1}
    assert extract_json('```json\n{"a": 2}\n```') == {"a": 2}
    assert extract_json('说明文字 {"a":3} 结尾') == {"a": 3}
    assert extract_json("[1,2]") is None
    assert extract_json("") is None and extract_json(None) is None


def test_merge_fragment_drops_hallucinations():
    sk = _skeleton()
    frag = {
        "endpoints": [
            {"path": "/login", "method": "POST", "auth_role": "anonymous",
             "params": [{"name": "username", "meaning": "账号"},
                        {"name": "ghost_param", "domain": {"kind": "int"}}]},
            {"path": "/never-observed", "params": []},
        ],
        "invariants": [
            {"id": "inv_total", "expr": {"coeffs": {"total": 1, "qty": -100}, "const": 0},
             "kind": "arithmetic", "confidence": 0.7},
            {"id": "inv_bad", "expr": {"coeffs": {"x": "abc"}}},
        ],
        "goals": [{"id": "g_admin", "desc": "拿管理员", "requires_facts": ["role=admin"]}],
        "transitions": [{"via_endpoint": "ghost:xx"}, {"via_endpoint": "get:/login"}],
    }
    ir, adopted, dropped = merge_fragment(sk, frag)
    assert adopted >= 3 and dropped >= 3                # 幻觉端点/参数/非法不变量全丢
    assert [i["id"] for i in ir["invariants"]] == ["inv_total"]
    assert [g["id"] for g in ir["goals"]] == ["g_admin"]
    assert ir["confidence"] == 0.6
    assert {"kind": "llm", "ref": "business_ir"} in ir["sources"]
    login = next(e for e in ir["endpoints"]
                 if e["path"] == "/login" and e["method"] == "POST")
    assert login["params"][0]["meaning"] == "账号"
    assert all(p["name"] != "ghost_param" for p in login["params"])
    assert all(t["via_endpoint"] != "ghost:xx" for t in ir["transitions"])
    # 原骨架不被污染（深拷贝）
    assert sk["confidence"] == 0.3 and sk["invariants"] == []


# ============================================================
# refine_ir 降级
# ============================================================
@pytest.mark.asyncio
async def test_refine_ir_degrades_on_every_failure_mode():
    obs, sk = collect_observations(_brief()), _skeleton()
    assert await refine_ir(obs, sk, client=_FakeClient(exc=RuntimeError("boom"))) is sk
    assert await refine_ir(obs, sk, client=_FakeClient(delay=5), timeout=0.01) is sk
    assert await refine_ir(obs, sk, client=_FakeClient(resp="not json at all")) is sk
    assert await refine_ir(obs, sk, enabled=False) is sk
    ok = await refine_ir(obs, sk, client=_FakeClient(
        resp=json.dumps({"goals": [{"id": "g1", "requires_facts": ["a=1"]}]})))
    assert [g["id"] for g in ok["goals"]] == ["g1"]
    assert validate_ir(ok) == []


# ============================================================
# validator
# ============================================================
def test_cross_validate_warnings_and_confidence_discount():
    obs = collect_observations(_brief())
    ir = _skeleton()
    ir["endpoints"].append({"id": "ghost:1", "method": "GET", "path": "/never-seen",
                            "params": [], "auth": {"required": False}, "effects": [],
                            "idempotent": True})
    ir["invariants"] = [{"id": "inv_x", "expr": {"coeffs": {"unknown_var": 1}, "const": 0}}]
    clean, rep = validate_and_fix(ir, obs)
    joined = " | ".join(rep["warnings"])
    assert "未被观测到" in joined and "未建模的参数" in joined
    assert clean["confidence"] < 0.3                     # warning → 置信度打折


def test_validate_and_fix_fail_closed():
    clean, rep = validate_and_fix({"version": "ir-0", "endpoints": "junk"})
    assert rep["ok"] is False and clean["confidence"] == 0.0
    assert validate_and_fix(None)[0] == empty_ir()
    assert IR_VERSION == "ir-1"


# ============================================================
# store：往返 + 幂等
# ============================================================
def test_store_roundtrip_and_idempotence(tmp_path, monkeypatch):
    monkeypatch.setattr(ir_store, "RUNTIME_DIR", tmp_path)
    ir = _skeleton()
    p = save_ir(ir, "http://shop.test")
    assert p
    with open(p, encoding="utf-8") as f:
        assert json.load(f)["version"] == "ir-1"
    with open(p, "rb") as f:
        first = f.read()
    save_ir(ir, "http://shop.test")
    with open(p, "rb") as f:
        assert f.read() == first                          # 幂等：逐字节相同
    assert load_ir("http://shop.test") == ir
    assert load_ir("http://other.test") == {}
    assert save_ir(None) is None and save_ir({}) is None
    assert ir_store.host_of("http://shop.test:8443/x") == "shop.test_8443"
    assert ir_store.host_of("") == "unknown"


# ============================================================
# 端到端
# ============================================================
@pytest.mark.asyncio
async def test_build_business_ir_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setattr(ir_store, "RUNTIME_DIR", tmp_path)
    frag = {
        "endpoints": [{"path": "/api/orders/123", "auth_role": "user",
                       "params": [{"name": "expand",
                                   "domain": {"kind": "enum", "values": [True, False]}}]}],
        "invariants": [{"id": "inv_total",
                        "expr": {"coeffs": {"total": 1, "qty": -100}, "const": 0}}],
        "goals": [{"id": "g_admin", "requires_facts": ["role=admin"]}],
    }
    ir1 = await build_business_ir(_brief(), "http://shop.test",
                                  client=_FakeClient(resp=json.dumps(frag)))
    ir2 = await build_business_ir(_brief(), "http://shop.test",
                                  client=_FakeClient(resp=json.dumps(frag)))
    assert ir1 == ir2                                     # 确定性/幂等
    assert validate_ir(ir1) == []
    assert any(i["id"] == "inv_total" for i in ir1["invariants"])
    assert (tmp_path / "ir" / "shop.test.json").exists()
    brief = {}
    assert attach_ir_to_brief(brief, ir1)["business_ir"] == ir1
    assert attach_ir_to_brief({}, {}) == {}


@pytest.mark.asyncio
async def test_build_business_ir_fail_closed():
    assert await build_business_ir({}, "http://a/", persist=False) == {}
    assert await build_business_ir({"crawled_endpoints": []}, "http://a/", persist=False) == {}
    assert await build_business_ir(None, "", persist=False) == {}
    # LLM 挂掉 → 仍产出确定性骨架（不返回空，也不抛）
    got = await build_business_ir(_brief(), "http://shop.test", persist=False,
                                  client=_FakeClient(exc=RuntimeError("down")))
    assert got["endpoints"] and got["confidence"] <= 0.3
    assert await build_business_ir({"crawled_endpoints": "not-a-list"}, "http://a/",
                                   persist=False) == {}
