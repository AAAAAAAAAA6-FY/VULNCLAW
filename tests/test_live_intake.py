# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP15.3/SP15.5（D4.2/D4.5，A 线）采集→任务实时生成 单元测试。

覆盖（全部离线，不触网不调 AI）：
- 总开关默认关 -> hit 全短路，feed 零摄入（零行为回归）；
- 开 关：带参注入面评分达标 -> engine_bundle 补测任务（source=live:*，priority）;
- 静态资源/无参低分 -> 不出任务（噪声控制）;
- 同 (path,param) 发射去重 + feed 精确去重 -> 同一注入面只补测一次;
- acq_score 打分规则（静态 0 / 带参高分 / 来源加权）。
"""
import pytest

from vulnclaw.core.settings import settings
from vulnclaw.modules import live_intake as li_mod
from vulnclaw.modules.live_intake import LiveIntake
from vulnclaw.modules.request_feed import RequestFeed, RequestRecord, acq_score


def _on() -> None:
    settings.live_intake_enabled = True
    settings.live_intake_min_score = 8
    settings.live_intake_priority = 8


def _off() -> None:
    settings.live_intake_enabled = False


@pytest.fixture(autouse=True)
def _reset_switch():
    _off()
    yield
    _off()


# ---- D4.5 acq_score（SP15.5）----
def _rec(url, params=None, source="crawl"):
    return RequestRecord(url=url, params=dict(params or {}) or {}, source=source)


def test_score_static_resource_zero():
    assert acq_score(_rec("http://t/app.js?cb=1")) == 0
    assert acq_score(_rec("http://t/img/logo.png")) == 0


def test_score_param_url_high():
    assert acq_score(_rec("http://t/x?id=1&page=2", {"id": "1", "page": "2"})) >= 9
    assert acq_score(_rec("http://t/x", {"q": ""})) >= 8


def test_score_source_weight():
    base = _rec("http://t/x", {"q": "1"}, source="crawl")
    brw = _rec("http://t/x", {"q": "1"}, source="browser_render")
    assert acq_score(brw) >= acq_score(base)


# ---- SP15.3 LiveIntake ----
def test_switch_off_zero_behavior():
    li = LiveIntake()
    assert li.hit("http://t/x?q=1", params={"q": "1"}) is None
    assert len(li._feed) == 0           # 未开启时连 feed 都不收（零行为回归）
    assert li.stats()["emitted"] == 0


def test_on_param_endpoint_emits_bundle():
    _on()
    li = LiveIntake()
    tasks = li.hit("http://t/x?id=7", params={"id": "7"}, source="crawl")
    assert tasks and len(tasks) == 1
    td = tasks[0]
    assert td["type"] == "engine_bundle"
    assert td["target"] == "http://t/x"
    assert td["param"] == "id"
    assert td["priority"] >= 8
    assert td["source"].startswith("live:")
    assert td["live_score"] >= 8


def test_on_emit_callback_receives_task():
    _on()
    got = []
    li = LiveIntake(emit=lambda td: got.append(td))
    li.hit("http://t/x?a=1", params={"a": "1"})
    assert len(got) == 1 and got[0]["param"] == "a"


def test_static_resource_not_emitted():
    _on()
    li = LiveIntake()
    assert li.hit("http://t/app.js?cb=1", params={"cb": "1"}) is None
    assert li.hit("http://t/a.png") is None


def test_paramless_endpoint_below_threshold():
    _on()
    li = LiveIntake()
    assert li.hit("http://t/x") is None     # 无参 7 分 < min_score 8


def test_dup_injection_surface_emitted_once():
    _on()
    li = LiveIntake()
    t1 = li.hit("http://t/x?id=1", params={"id": "1"})
    t2 = li.hit("http://t/x?id=2", params={"id": "2"})   # 同 (path,param)
    assert t1 and len(t1) == 1
    assert t2 is None                                    # 发射去重
    assert li.stats()["emitted"] == 1


def test_feed_dedup_blocks_same_url_same_params_re_hit():
    _on()
    li = LiveIntake(feed=RequestFeed())
    assert li.hit("http://t/y?p=1", params={"p": "1"}) is not None
    assert li.hit("http://t/y?p=1", params={"p": "1"}) is None   # feed 精确去重


def test_multi_params_multi_tasks():
    _on()
    li = LiveIntake()
    tasks = li.hit("http://t/z?a=1&b=2", params={"a": "1", "b": "2"})
    assert tasks and len(tasks) == 2
    assert {td["param"] for td in tasks} == {"a", "b"}


# ---- R2-A S1: render / burp 两源全局回注 ----
class TestFeedLiveGlobal:
    def test_off_short_circuits(self):
        _off()
        li_mod.set_live_intake(LiveIntake())
        try:
            assert li_mod.feed_live("http://t/search?q=1",
                                    params={"q": "1"}, source="render") is None
        finally:
            li_mod.set_live_intake(None)

    def test_render_source_goes_pending(self):
        _on()
        li_mod.set_live_intake(LiveIntake())
        try:
            tasks = li_mod.feed_live("http://t.example.com/search?q=1&page=2",
                                     params={"q": "1", "page": "2"}, source="render")
            assert tasks and all(t["source"] == "live:render" for t in tasks)
            assert li_mod.pending_count() == len(tasks)  # 无 emit → 进 pending
            assert li_mod.drain_pending() == tasks
            assert li_mod.pending_count() == 0
        finally:
            li_mod.set_live_intake(None)
            _off()

    def test_burp_source_uses_emit(self):
        _on()
        got = []
        li_mod.set_live_intake(LiveIntake(emit=got.append))
        try:
            tasks = li_mod.feed_live("http://t.example.com/api?id=1",
                                     params={"id": "1"}, source="burp")
            assert tasks and got == tasks          # 有 emit → 直接回调
            assert li_mod.pending_count() == 0     # 不进 pending
            assert all(t["source"] == "live:burp" for t in tasks)
        finally:
            li_mod.set_live_intake(None)
            _off()

    def test_low_score_no_task(self):
        _on()
        li_mod.set_live_intake(LiveIntake())
        try:
            # 静态资源 acq_score=0 → 低于阈值不出任务
            assert li_mod.feed_live("http://t/app.css?x=1",
                                    params={"x": "1"}, source="render") is None
        finally:
            li_mod.set_live_intake(None)
            _off()

    def test_duplicate_injection_face_once(self):
        _on()
        li_mod.set_live_intake(LiveIntake())
        try:
            first = li_mod.feed_live("http://t.example.com/api?uid=1",
                                     params={"uid": "1"}, source="render")
            second = li_mod.feed_live("http://t.example.com/api?uid=2",
                                      params={"uid": "2"}, source="burp")
            assert first and second is None  # 同注入面第二次被 emit 去重滤除
        finally:
            li_mod.drain_pending()
            li_mod.set_live_intake(None)
            _off()

    def test_burp_client_history_feed(self):
        """Burp 流：_feed_live_from_history 逐条回注，非法 URL/脏数据跳过。"""
        _on()
        li_mod.set_live_intake(LiveIntake())
        try:
            from vulnclaw.ai.burp import BurpClient
            c = BurpClient()
            fed = c._feed_live_from_history([
                {"url": "http://t.example.com/api?id=1", "method": "GET"},
                {"url": "http://t.example.com/api?id=2", "method": "GET"},  # 同注入面去重
                {"url": "not-a-url", "method": "GET"},
                None,
            ])
            assert fed == 1 and li_mod.pending_count() == 1
        finally:
            li_mod.drain_pending()
            li_mod.set_live_intake(None)
            _off()