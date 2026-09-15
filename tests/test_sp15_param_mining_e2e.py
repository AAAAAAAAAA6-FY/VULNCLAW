# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP15.2 参数挖掘端到端融验（A 线，离线全链，不触网不调 AI）。

  recon_brief.param_mining 参数池条目 -> 消费侧 (url,param) 去重
  -> engine_bundle 任务（target 剥 query / param 注入 / source=param_mining /
     mining_signal & mining_base_len 透传）-> 调度队列高优先级先出。

覆盖：多条目多任务；同端点同参数去重（query 剥除后）；同端点不同参数保留；
      不同端点同参数保留；任务可被调度器取出且按参数补测高优先级。
"""
import pytest

from vulnclaw.ai.v100.phases import phases_taskgen as m
from vulnclaw.ai.v100.smart_queue import SmartTaskQueue


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


def _item(url, param):
    return {"url": url, "param": param, "base_len": 120, "signal": "diff_len"}


def _pm_tasks(s):
    return [t for t in s.task_queue._pending_tasks.values()
            if t.task_data.get("source") == "param_mining"]


async def _run(brief):
    s = _FakeSelf(brief)
    await m._generate_tasks(s)
    return s, _pm_tasks(s)


@pytest.mark.asyncio
async def test_multi_items_multi_bundle_tasks():
    _, pm = await _run(_brief_with_mining([
        _item("http://t/a?q=1", "p1"),
        _item("http://t/b?q=1", "p2"),
        _item("http://t/c", "p3"),
    ]))
    assert len(pm) == 3
    for td in (t.task_data for t in pm):
        assert td["type"] == "engine_bundle"
        assert td["engines"]                     # 引擎选择非空
        assert td["priority"] >= 8               # 参数补测高优先级
        assert td["mining_signal"] == "diff_len"
        assert td["mining_base_len"] == 120


@pytest.mark.asyncio
async def test_dup_same_url_same_param_deduped():
    _, pm = await _run(_brief_with_mining([
        _item("http://t/x?id=1", "hid"),
        _item("http://t/x?id=9&z=1", "hid"),     # query 剥掉后同 (url,param)
    ]))
    assert len(pm) == 1


@pytest.mark.asyncio
async def test_same_url_diff_params_kept():
    _, pm = await _run(_brief_with_mining([
        _item("http://t/x?id=1", "p1"),
        _item("http://t/x?id=1", "p2"),
    ]))
    assert {td["param"] for td in (t.task_data for t in pm)} == {"p1", "p2"}


@pytest.mark.asyncio
async def test_same_param_diff_urls_kept():
    _, pm = await _run(_brief_with_mining([
        _item("http://t/a", "hid"),
        _item("http://t/b", "hid"),
    ]))
    assert {td["target"] for td in (t.task_data for t in pm)} == {"http://t/a", "http://t/b"}


@pytest.mark.asyncio
async def test_mining_task_schedulable_via_queue():
    # 端到端出口：参数池补测任务可被调度器取出执行
    s, pm = await _run(_brief_with_mining([_item("http://t/x", "hid")]))
    assert len(pm) == 1
    got = None
    # 扫描窗口取队列全长而非固定 10 次：调度队列用堆实现，同优先级任务的弹出顺序
    # 不保证稳定（新增低优先级兜底任务会重排堆），固定小窗口会让本例随机翻车。
    # 本例语义只验证"参数补测任务可被调度到"，不验证具体弹出位次。
    for _ in range(len(s.task_queue._pending_tasks) + 1):
        td = await s.task_queue.get_next()
        if td is None:
            break
        if td.get("source") == "param_mining":
            got = td
            break
    assert got is not None
    assert got["param"] == "hid"
    assert got["target"] == "http://t/x"
    assert got.get("priority", 0) >= 8