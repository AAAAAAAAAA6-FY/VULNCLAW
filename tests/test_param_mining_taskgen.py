# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP14.1 (D3.5 消费侧) phases_taskgen 参数挖掘消费 单元测试。

覆盖：recon_brief.param_mining 条目 -> engine_bundle 任务入队；
      总开关关闭不发任务；上限 cap；凭据类参数跳过；静态资源 URL 跳过。
"""
import pytest

from vulnclaw.ai.v100.smart_queue import SmartTaskQueue
from vulnclaw.ai.v100.phases import phases_taskgen as m


class _StubFilter:
    def should_skip(self, *args, **kwargs):
        return (False, "")


class _FakeSelf:
    def __init__(self, brief):
        self._recon_brief = brief
        self.target = "http://t/"  # 参数池消费按同源过滤：靶场用 http://t/ 对齐条目
        self.task_queue = SmartTaskQueue()
        self.local_filter = _StubFilter()
        self.batch_processor = None
        self._a32_skipped = 0
        self._rotation_offset = 0

    async def _gen_cve_task(self):
        return None


def _brief_with_mining(items):
    return {
        "status": 200,
        "tech_stack": [],
        "url_params": [],
        "forms": [],
        "apis": [],
        "js_endpoints": [],
        "crawled_endpoints": [],
        "intel": {},
        "param_mining": items,
    }


def _queued_tasks(s):
    return list(s.task_queue._pending_tasks.values())


async def _run(brief):
    s = _FakeSelf(brief)
    await m._generate_tasks(s)
    tasks = _queued_tasks(s)
    pm = [t for t in tasks if t.task_data.get("source") == "param_mining"]
    return s, pm


@pytest.mark.asyncio
async def test_mining_item_generates_bundle_task():
    brief = _brief_with_mining([{
        "url": "http://t/x?s=1", "param": "hidden_q",
        "base_len": 120, "signal": "status_diff:200->500",
    }])
    s, pm = await _run(brief)
    assert len(pm) == 1
    td = pm[0].task_data
    assert td["param"] == "hidden_q"
    assert td["target"] == "http://t/x"  # query 剥离，由 param 注入
    assert td["source"] == "param_mining"
    assert td["mining_signal"]
    assert td["mining_base_len"] == 120
    assert td["priority"] >= 8


@pytest.mark.asyncio
async def test_switch_off_no_mining_tasks(monkeypatch):
    monkeypatch.setattr(m.settings, "scan_param_mining", False)
    brief = _brief_with_mining([{"url": "http://t/y", "param": "q2"}])
    _, pm = await _run(brief)
    assert pm == []


@pytest.mark.asyncio
async def test_max_param_mining_cap(monkeypatch):
    monkeypatch.setattr(m.settings, "max_param_mining", 1)
    brief = _brief_with_mining([
        {"url": "http://t/a", "param": "p1"},
        {"url": "http://t/b", "param": "p2"},
    ])
    _, pm = await _run(brief)
    assert len(pm) == 1


@pytest.mark.asyncio
async def test_credential_param_skipped():
    brief = _brief_with_mining([{"url": "http://t/x", "param": "api_key"}])
    _, pm = await _run(brief)
    assert pm == []


@pytest.mark.asyncio
async def test_static_resource_url_skipped():
    brief = _brief_with_mining([{"url": "http://t/app.js", "param": "cb"}])
    _, pm = await _run(brief)
    assert pm == []


@pytest.mark.asyncio
async def test_malformed_item_skipped():
    brief = _brief_with_mining([
        {"url": "", "param": "p1"},
        {"url": "http://t/x", "param": ""},
        "not-a-dict",
    ])
    _, pm = await _run(brief)
    assert pm == []


@pytest.mark.asyncio
async def test_crawl_triggers_without_mining():
    # 无 param_mining 时主链路任务照常生成（无回归）
    brief = _brief_with_mining([])
    s, pm = await _run(brief)
    assert pm == []
    assert len(s.task_queue._pending_tasks) > 0  # 仍有默认参数任务入队


@pytest.mark.asyncio
async def test_cross_origin_pool_item_dropped():
    """跨靶场隔离：池里非本次目标（异 host / 同 host 异端口）条目一律不发任务。"""
    brief = _brief_with_mining([
        {"url": "http://t/ok", "param": "p1"},            # 同源 -> 保留
        {"url": "http://other/x", "param": "p2"},         # 异 host -> 丢弃
        {"url": "http://t:99/x", "param": "p3"},          # 同 host 异端口 -> 丢弃
    ])
    _, pm = await _run(brief)
    assert len(pm) == 1
    assert pm[0].task_data["target"] == "http://t/ok"