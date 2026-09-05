# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""A3.2: 目标画像增量比对 单元测试（与 test_asset_profile.py 互补）。

test_asset_profile.py 已覆盖基础命中/变化/往返；本文件聚焦差异面：
- surface_fp 确定性（重复调用/空 brief）与非表面字段免疫；
- build_asset_profile 资产指纹表格式（前缀 / 16 位指纹）；
- TTL 边界（恰好 TTL 未过期、刚过 TTL 视为过期，含 target_unchanged 路径）；
- crawl_asset_unchanged 的 query 不敏感 / 参数序无关 / 空参数过滤 / 非法入参；
- generic_asset_unchanged 的 query 不敏感；
- 画像持久化后 target_unchanged 仍正确（增量跳过闭环）。

全部离线纯函数（monkeypatch 时钟），不需要真实扫描/网络。
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
    "subdomains": ["www.t.com"],
}


def test_surface_fp_deterministic_and_empty():
    """相同 brief 多次计算指纹稳定；空/None brief 指纹稳定且与有内容不同。"""
    fp1 = surface_fp(_BRIEF)
    for _ in range(3):
        assert surface_fp(_BRIEF) == fp1
    assert surface_fp(None) == surface_fp({})
    assert surface_fp(_BRIEF) != surface_fp({})


def test_surface_fp_sensitive_only_to_surface_fields():
    """只取影响攻击面的确定性字段：无关字段不影响指纹，表面字段变化则变。"""
    with_intel = dict(_BRIEF)
    with_intel["intel"] = {"whois": "x", "dns": "y"}
    assert surface_fp(with_intel) == surface_fp(_BRIEF)  # 无关字段免疫

    more_sub = dict(_BRIEF)
    more_sub["subdomains"] = ["www.t.com", "api.t.com"]
    assert surface_fp(more_sub) != surface_fp(_BRIEF)

    fewer_params = dict(_BRIEF)
    fewer_params["url_params"] = ["id"]
    assert surface_fp(fewer_params) != surface_fp(_BRIEF)


def test_build_asset_profile_table():
    """画像包含目标/表面指纹/端点级资产指纹表（前缀 + 16 位指纹）。"""
    p = build_asset_profile("http://t/", _BRIEF)
    assert p["target"] == "http://t/"
    assert p["surface_fp"] == surface_fp(_BRIEF)
    assert p["assets"]  # 非空
    for key, fp in p["assets"].items():
        assert key.startswith(("ep::", "api::", "js::"))
        assert isinstance(fp, str) and len(fp) == 16  # sha1[:16]
    assert p["assets"].get("ep::http://t/a")  # 去 query
    assert p["assets"].get("api::/api/y")     # 去 query
    assert p["assets"].get("js::/static/app.js")


def test_build_asset_profile_empty_brief():
    """无 brief：资产表为空，表面指纹为空白视图指纹。"""
    p = build_asset_profile("http://t/", None)
    assert p["assets"] == {}
    assert p["surface_fp"] == surface_fp({})


def test_profile_expired_fresh_not_expired(monkeypatch):
    """新建画像（时钟不动）未过期。"""
    clock = [5000.0]
    monkeypatch.setattr("vulnclaw.core_modules.asset_profile.time.time", lambda: clock[0])
    p = build_asset_profile("http://t/", _BRIEF)
    assert profile_expired(p, 168.0) is False
    clock[0] += 10.0  # 10 秒后仍远未到 TTL
    assert profile_expired(p, 168.0) is False


def test_profile_expired_ttl_boundary(monkeypatch):
    """TTL 边界：elapsed 恰好等于 TTL 未过期（> 判定），刚过 1 秒即过期。"""
    clock = [1000.0]
    monkeypatch.setattr("vulnclaw.core_modules.asset_profile.time.time", lambda: clock[0])
    p = build_asset_profile("http://t/", _BRIEF)
    ttl_h = 168.0
    clock[0] = 1000.0 + ttl_h * 3600.0
    assert profile_expired(p, ttl_h) is False  # 恰好 TTL
    clock[0] = 1000.0 + ttl_h * 3600.0 + 1.0
    assert profile_expired(p, ttl_h) is True   # 刚过 TTL → 过期


def test_profile_expired_edge_cases():
    """缺失/非法 updated_at 一律视为过期。"""
    assert profile_expired(None, 168.0) is True
    assert profile_expired({}, 168.0) is True
    assert profile_expired({"updated_at": 0}, 168.0) is True
    assert profile_expired({"updated_at": -1}, 168.0) is True
    assert profile_expired({"updated_at": None}, 168.0) is True
    assert profile_expired({"updated_at": "garbage"}, 168.0) is True


def test_target_unchanged_true_when_fresh_and_same(monkeypatch):
    """未过期且表面一致 → True（参数级任务可整体跳过）。"""
    clock = [3000.0]
    monkeypatch.setattr("vulnclaw.core_modules.asset_profile.time.time", lambda: clock[0])
    prev = build_asset_profile("http://t/", _BRIEF)
    assert target_unchanged(prev, dict(_BRIEF), 168.0) is True
    assert target_unchanged(prev, dict(_BRIEF), 24.0) is True


def test_target_unchanged_false_on_surface_change(monkeypatch):
    """表面变化 → False（增量重扫该变化面）。"""
    clock = [3000.0]
    monkeypatch.setattr("vulnclaw.core_modules.asset_profile.time.time", lambda: clock[0])
    prev = build_asset_profile("http://t/", _BRIEF)
    changed = dict(_BRIEF)
    changed["subdomains"] = ["www.t.com", "api.t.com"]
    assert target_unchanged(prev, changed, 168.0) is False


def test_target_unchanged_false_on_expiry(monkeypatch):
    """画像过期（刚过 TTL）→ False，即使 brief 未变。"""
    clock = [2000.0]
    monkeypatch.setattr("vulnclaw.core_modules.asset_profile.time.time", lambda: clock[0])
    prev = build_asset_profile("http://t/", _BRIEF)
    ttl_h = 24.0
    clock[0] = 2000.0 + ttl_h * 3600.0
    assert target_unchanged(prev, dict(_BRIEF), ttl_h) is True  # 恰好 TTL 未过期
    clock[0] = 2000.0 + ttl_h * 3600.0 + 0.5
    assert target_unchanged(prev, dict(_BRIEF), ttl_h) is False  # 刚过 → 全量重扫


def test_crawl_asset_unchanged_query_and_order_insensitive():
    """同 URL（query 不影响端点身份）且同参数集 → True；参数序无关。"""
    prev = build_asset_profile("http://t/", _BRIEF)["assets"]
    assert crawl_asset_unchanged(prev, "http://t/a?x=1", ["q", "s"]) is True
    assert crawl_asset_unchanged(prev, "http://t/a", ["q", "s"]) is True   # 去 query 等价
    assert crawl_asset_unchanged(prev, "http://t/a?other=9", ["s", "q"]) is True  # 参数序无关
    assert crawl_asset_unchanged(prev, "http://t/a", ["q"]) is False       # 参数集变化
    assert crawl_asset_unchanged(prev, "http://t/missing", []) is False    # 新端点


def test_crawl_asset_unchanged_param_normalization():
    """指纹计算过滤空参数：["q", ""] 与 ["q"] 等价。"""
    brief = {"crawled_endpoints": [{"url": "http://t/z?k=1", "params": ["q", ""]}]}
    assets = build_asset_profile("http://t/", brief)["assets"]
    assert crawl_asset_unchanged(assets, "http://t/z?k=1", ["q", ""]) is True
    assert crawl_asset_unchanged(assets, "http://t/z", ["q"]) is True
    assert crawl_asset_unchanged(assets, "http://t/z", ["q", "extra"]) is False


def test_crawl_asset_unchanged_invalid_inputs():
    """无画像 / 非法画像 / 空 URL → False（不跳过）。"""
    assert crawl_asset_unchanged(None, "http://t/a", []) is False
    assert crawl_asset_unchanged([], "http://t/a", []) is False
    assert crawl_asset_unchanged({}, "", []) is False


def test_generic_asset_unchanged_query_insensitive():
    """api/js 端点级判定同样去 query。"""
    prev = build_asset_profile("http://t/", _BRIEF)["assets"]
    assert generic_asset_unchanged(prev, "api", "/api/y?token=1") is True
    assert generic_asset_unchanged(prev, "api", "/api/x?v=2") is True
    assert generic_asset_unchanged(prev, "js", "/static/app.js?ver=3") is True
    assert generic_asset_unchanged(prev, "api", "/api/new") is False


@pytest.mark.asyncio
async def test_profile_roundtrip_incremental_skip(tmp_path):
    """画像落库再加载：未变 → 增量跳过；表面变化 → 不可跳过（闭环）。"""
    saver = IncrementalSaver(base_dir=str(tmp_path))
    profile = build_asset_profile("http://t/", _BRIEF)
    await save_profile("http://t/", profile, saver=saver)
    loaded = load_prev_profile("http://t/", saver=saver)
    assert loaded is not None
    assert loaded["surface_fp"] == profile["surface_fp"]
    # 持久化画像 + 未变 brief → 参数级任务可跳过
    assert target_unchanged(loaded, dict(_BRIEF), 168.0) is True
    # 表面变化 → 不可跳过
    changed = dict(_BRIEF)
    changed["open_ports"] = [80, 443, 8080]
    assert target_unchanged(loaded, changed, 168.0) is False
    # 其他目标无画像
    assert load_prev_profile("http://other/", saver=saver) is None
