# -*- coding: utf-8 -*-
"""目标反检测基线单测：SPA 大站基线抬阈值免误判 / 平站保持出厂默认。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

import vulnclaw.core.target_anti_scan_baseline as M
from vulnclaw.engines.auxiliary_engines import AntiScanDetector
from vulnclaw.config.settings import settings

SPA_TEXT = " ".join(f"id={{{{00000000-0000-0000-0000-{i:012d}}}}}" for i in range(140)) + "y" * 9000
PLAIN_TEXT = "<html><body><h1>Home</h1><p>welcome</p></body></html>"


@pytest.fixture
def clear_baseline():
    M._reset_baseline()
    yield
    M._reset_baseline()


async def _serve(app):
    srv = TestServer(app)
    await srv.start_server()
    return srv


@pytest.mark.asyncio
async def test_spa_target_raises_threshold(clear_baseline):
    """SPA 大站：基线应将 uuid/len 阈值抬到峰值x1.5 以上，且不误判自家页面为蜜罐。"""
    async def handler(request):
        return web.Response(text=SPA_TEXT)

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/{path:.*}", handler)
    srv = await _serve(app)
    try:
        base = "http://%s:%s" % (srv.host, srv.port)
        bl = await M.detect_anti_scan_baseline(base, samples=4)
        assert bl.probed
        assert bl.sample_max_uuid >= 140
        assert bl.uuid_threshold >= M.DEF_UUID_TH
        assert bl.uuid_threshold >= int(140 * 1.5), "阈值应随峰值抬升"
        assert bl.sample_max_len >= 9000
        assert bl.min_text >= int(9000 * 1.5)

        # 基线生效：SPA 自家页面不被判蜜罐（出厂默认值会误判）
        ok, _ = AntiScanDetector.is_honeypot(SPA_TEXT, {})
        assert not ok, "基线校准后自家大页面不应被判蜜罐"

        # 注册表可全局读取
        assert M.get_anti_scan_baseline() is bl
    finally:
        await srv.close()


@pytest.mark.asyncio
async def test_plain_target_keeps_defaults(clear_baseline):
    """平站：阈值保持出厂默认（不因小页面抬升）。"""
    async def handler(request):
        return web.Response(text=PLAIN_TEXT)

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/{path:.*}", handler)
    srv = await _serve(app)
    try:
        base = "http://%s:%s" % (srv.host, srv.port)
        bl = await M.detect_anti_scan_baseline(base, samples=4)
        assert bl.probed
        assert bl.uuid_threshold == M.DEF_UUID_TH, "平站保持出厂默认"
        assert bl.min_text == M.DEF_MIN_TEXT
        ok, _ = AntiScanDetector.is_honeypot(PLAIN_TEXT, {})
        assert not ok
    finally:
        await srv.close()


@pytest.mark.asyncio
async def test_manual_config_priority(monkeypatch, clear_baseline):
    """用户显式配置优先于基线：基线学得 uuid≈210，用户设 999，300 个 UUID 的页面不得误判。"""
    monkeypatch.setattr(settings, "anti_scan_uuid_threshold", 999)
    async def handler(request):
        return web.Response(text=SPA_TEXT)

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/{path:.*}", handler)
    srv = await _serve(app)
    try:
        base = "http://%s:%s" % (srv.host, srv.port)
        await M.detect_anti_scan_baseline(base, samples=2)
        mid = " ".join(f"id={{{{00000000-0000-0000-0000-{i:012d}}}}}" for i in range(300))
        ok, _ = AntiScanDetector.is_honeypot(mid, {})
        assert not ok, "用户 999 阈值应优先于基线 210（300 < 999 不判蜜罐）"
        big = " ".join(f"id={{{{00000000-0000-0000-0000-{i:012d}}}}}" for i in range(1500))
        ok2, _ = AntiScanDetector.is_honeypot(big, {})
        assert ok2, "超用户阈值（1500 > 999）仍应判蜜罐"
    finally:
        await srv.close()


@pytest.mark.asyncio
async def test_baseline_counts_placeholders(clear_baseline):
    """占位符峰值也进入基线阈值推导。"""
    async def handler(request):
        return web.Response(text="{{a}}" * 40 + "<p>small</p>" * 10)

    app = web.Application()
    app.router.add_get("/", handler)
    app.router.add_get("/{path:.*}", handler)
    srv = await _serve(app)
    try:
        base = "http://%s:%s" % (srv.host, srv.port)
        bl = await M.detect_anti_scan_baseline(base, samples=2)
        assert bl.probed
        assert bl.placeholder_threshold >= int(40 * 1.4)
    finally:
        await srv.close()
