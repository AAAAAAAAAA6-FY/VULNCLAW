# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A 池链路闭合：A2（IR 还原）→ A1（符号执行）端到端（hermetic：零网络、零真实 LLM）。

这里锁的是一条**误报红线**：值域只能来自观测样本或 LLM 明确标注，
绝不能"凭参数名像 role 就认定 role=1 可行"——否则 A1 会对任何带这类参数名的
端点批量产出误报。三道闸：A2 不臆造值域 / A1 判 undecidable / 默认不入报告。
"""
import json

import pytest

from vulnclaw.core.business_ir import build_business_ir
from vulnclaw.engines.symbolic_engine import SymbolicLogicEngine


class _Fake:
    def __init__(self, resp):
        self.resp = resp

    async def ask(self, prompt, **kw):
        return self.resp


def _brief():
    return {"target": "http://t", "crawled_endpoints": ["http://t/api/user?role=0"]}


@pytest.mark.asyncio
async def test_name_without_sample_gets_no_domain_and_no_finding():
    """只有参数名、没有取值样本 → A2 不给值域 → A1 判 undecidable → 不产出。"""
    ir = await build_business_ir({"target": "http://t", "crawled_endpoints": ["http://t/api/user"]},
                                 "http://t", use_llm=False, persist=False)
    assert ir["endpoints"]
    assert all(p["domain"] is None for p in ir["endpoints"][0]["params"])
    assert await SymbolicLogicEngine().scan("http://t", None, ir=ir) == []


@pytest.mark.asyncio
async def test_observed_domain_blocks_privilege_goal():
    """观测到 role=0（唯一证据）→ 值域 = {0} → 提权目标不可满足 → 不产出。"""
    ir = await build_business_ir(_brief(), "http://t", use_llm=False, persist=False)
    ep = next(e for e in ir["endpoints"] if e["path"] == "/api/user")
    assert ep["params"][0]["name"] == "role"
    assert ep["params"][0]["domain"] == {"kind": "enum", "values": [0]}
    assert await SymbolicLogicEngine().scan("http://t", None, ir=ir) == []


@pytest.mark.asyncio
async def test_llm_widened_domain_yields_verified_candidate():
    """LLM 把 role 值域标为 {0,1}（有证据支撑）→ A1 可证提权输入存在 → 产出候选。"""
    frag = {"endpoints": [{"path": "/api/user", "method": "GET",
                           "params": [{"name": "role",
                                       "domain": {"kind": "enum", "values": [0, 1]}}]}]}
    ir = await build_business_ir(_brief(), "http://t",
                                 client=_Fake(json.dumps(frag)), persist=False)
    out = await SymbolicLogicEngine().scan("http://t", None, ir=ir)
    assert len(out) == 1
    f = out[0]
    assert f["engine"] == "symbolic_logic" and f["parameter"] == "role"
    assert f["payload"] == "role=1" and f["needs_verification"] is True


@pytest.mark.asyncio
async def test_symbolic_line_builds_ir_lazily_and_attaches_to_brief():
    """A1 产线在 brief 无 IR 时惰性触发 A2，并把结果挂回 brief（供后续 A3 复用）。"""
    from vulnclaw.ai.v100.phases.phases_taskgen import _run_symbolic_line

    class _Stub:
        def __init__(self):
            self.target = "http://t"
            self.session = None
            self._recon_brief = _brief()
            self.added = []

        def _add_finding(self, f):
            self.added.append(f)

    stub = _Stub()
    made = await _run_symbolic_line(stub)
    assert made == 0                                   # 默认不入报告（FP=0）
    assert stub.added == []
    ir = stub._recon_brief.get("business_ir")
    assert isinstance(ir, dict) and ir.get("endpoints")   # IR 已构建并挂回
    assert ir["target"] == "http://t"


@pytest.mark.asyncio
async def test_symbolic_line_fail_closed_on_broken_brief():
    """brief 畸形 / 构建失败 → 产线返回 0 且不抛（绝不阻断 extras）。"""
    from vulnclaw.ai.v100.phases.phases_taskgen import _run_symbolic_line

    class _Stub:
        def __init__(self, brief):
            self.target = "http://t"
            self.session = None
            self._recon_brief = brief

        def _add_finding(self, f):
            raise AssertionError("不应有 finding")

    assert await _run_symbolic_line(_Stub(None)) == 0
    assert await _run_symbolic_line(_Stub({"crawled_endpoints": "not-a-list"})) == 0
