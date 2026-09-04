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
