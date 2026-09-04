# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A3.2: 目标画像持久化 + 增量只测变化面 单元测试。

覆盖：指纹稳定性/变化检测；target_unchanged（None/一致/变化/过期）；
      端点级 crawl_asset_unchanged；画像落库 roundtrip。
"""
import pytest

from vulnclaw.core_modules.asset_profile import (
    build_asset_profile,
    crawl_asset_unchanged,
    generic_asset_unchanged,
    load_prev_profile,
    profile_expired,
    save_profile,
    surface_fp,
    target_unchanged,
)
from vulnclaw.core_modules.persistence import IncrementalSaver

_BRIEF = {
    "status": 200,
    "tech_stack": ["nginx", "php"],
    "url_params": ["id", "page"],
    "forms": ["user"],
    "apis": ["/api/x", "/api/y?token=1"],
    "js_endpoints": ["/static/app.js"],
    "crawled_endpoints": [
        {"url": "http://t/a?x=1", "params": ["q", "s"]},
        {"url": "http://t/b", "params": []},
    ],
    "open_ports": [80, 443],
}


def test_surface_fp_stable_and_sensitive():
    assert surface_fp(_BRIEF) == surface_fp(dict(_BRIEF))  # 同输入同指纹
    changed = dict(_BRIEF)
    changed["status"] = 404
    assert surface_fp(changed) != surface_fp(_BRIEF)  # 表面变化 → 指纹变化
    reorder = dict(_BRIEF)
    reorder["tech_stack"] = ["php", "nginx"]  # 顺序无关
    assert surface_fp(reorder) == surface_fp(_BRIEF)


def test_build_profile_assets():
    p = build_asset_profile("http://t/", _BRIEF)
    assert p["target"] == "http://t/"
    assert p["assets"].get("ep::http://t/a")
    assert p["assets"].get("api::/api/y")  # 去 query
    assert p["assets"].get("js::/static/app.js")
    assert p["surface_fp"] == surface_fp(_BRIEF)


def test_target_unchanged_none_or_expired():
    assert target_unchanged(None, _BRIEF, 168.0) is False  # 无画像 → 全量扫
    old = build_asset_profile("http://t/", _BRIEF)
    old["updated_at"] = 1.0  # 1970 → 过期
    assert profile_expired(old, 168.0)
    assert target_unchanged(old, _BRIEF, 168.0) is False  # 过期 → 全量扫


def test_target_unchanged_true_and_false():
    prev = build_asset_profile("http://t/", _BRIEF)
    assert target_unchanged(prev, dict(_BRIEF), 168.0) is True
    changed = dict(_BRIEF)
    changed["crawled_endpoints"] = _BRIEF["crawled_endpoints"] + [
        {"url": "http://t/new", "params": []}
    ]
    assert target_unchanged(prev, changed, 168.0) is False  # 新端点 → 变化面


def test_crawl_asset_unchanged():
    prev = build_asset_profile("http://t/", _BRIEF)["assets"]
    assert crawl_asset_unchanged(prev, "http://t/a?x=1", ["q", "s"]) is True
    assert crawl_asset_unchanged(prev, "http://t/a?x=1", ["q"]) is False  # 参数集变化
    assert crawl_asset_unchanged(prev, "http://t/missing", []) is False  # 新端点
    assert crawl_asset_unchanged({}, "http://t/a", []) is False  # 无画像


def test_generic_asset_unchanged():
    prev = build_asset_profile("http://t/", _BRIEF)["assets"]
    assert generic_asset_unchanged(prev, "api", "/api/x") is True
    assert generic_asset_unchanged(prev, "js", "/static/app.js") is True
    assert generic_asset_unchanged(prev, "api", "/api/new") is False


@pytest.mark.asyncio
async def test_profile_roundtrip(tmp_path):
    saver = IncrementalSaver(base_dir=str(tmp_path))
    profile = build_asset_profile("http://t/", _BRIEF)
    await save_profile("http://t/", profile, saver=saver)
    loaded = load_prev_profile("http://t/", saver=saver)
    assert loaded is not None
    assert loaded["surface_fp"] == profile["surface_fp"]
    assert loaded["assets"] == profile["assets"]
    assert load_prev_profile("http://other/", saver=saver) is None


# ============================================================
# A3.2 回归防护：_generate_tasks 在默认配置（增量关）下必须正常生成任务。
# 回归背景：09a31ff 曾把 asset_profile 的 import 藏在 if 分支内，而调用点
# 无条件执行 → 默认路径 UnboundLocalError → 任务生成整体崩溃 → 0 引擎调用。
# 全量回归因无 taskgen 端到端用例而漏检，本用例补上这道防线。
# ============================================================
import vulnclaw.ai.v100.phases.phases_taskgen as phases_taskgen  # noqa: E402


class _StubQueue:
    def __init__(self):
        self.tasks = []

    async def add_task(self, task, priority=5):
        self.tasks.append(task)


class _StubLocalFilter:
    def should_skip(self, *a, **k):
        return False, ""


class _StubOrch:
    def __init__(self):
        self.target = "http://t/"
        self._recon_brief = {
            "tech_stack": [],
            "url_params": ["id"],
            "forms": [],
            "burp_params": [],
            "apis": ["/api/user"],
            "js_endpoints": ["/ajax/endpoint"],
            "crawled_endpoints": [{"url": "http://t/list?x=1", "params": ["q"]}],
            "open_ports": [],
            "subdomains": [],
        }
        self.task_queue = _StubQueue()
        self.local_filter = _StubLocalFilter()
        self.batch_processor = None
        self._rotation_offset = 0
        self._a32_skipped = 0

    async def _gen_cve_task(self):
        return None


@pytest.mark.asyncio
async def test_taskgen_default_settings_generates_tasks(monkeypatch):
    """默认（增量关）下 _generate_tasks 不得崩溃，且必须产出任务（含全局引擎）。"""
    from vulnclaw.config.settings import settings

    monkeypatch.setattr(settings, "incremental_scan", False)
    orch = _StubOrch()
    await phases_taskgen._generate_tasks(orch)
    # 参数级 bundle + api + js + crawl + 25 个全局引擎 → 远大于 10
    assert len(orch.task_queue.tasks) > 10
    assert orch._a32_skipped == 0  # 增量关 → 不允许跳过任何资产


@pytest.mark.asyncio
async def test_taskgen_incremental_on_no_baseline(monkeypatch):
    """增量开但无历史画像 → 走真实现导入路径，同样不得崩溃。"""
    from vulnclaw.config.settings import settings

    monkeypatch.setattr(settings, "incremental_scan", True)
    orch = _StubOrch()
    await phases_taskgen._generate_tasks(orch)
    assert len(orch.task_queue.tasks) > 10
