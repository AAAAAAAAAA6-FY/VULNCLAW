# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""D7.3 引擎级回归 fixture：用 tests/fixtures/engines/*.json 数据驱动，跑真实引擎（mock OOB 通道）。

每个 fixture 描述一个引擎调用的入参与期望结果（not_none / type），保证正例可检出、反例不误报。
"""
import glob
import json
import os

import pytest
import pytest_asyncio

import vulnclaw.engines.framework_zero_day_engines as fwk
from vulnclaw.core.oob_channel import OOBInteraction

FIXTURE_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "engines")


class _FakeChannel:
    def __init__(self, hits):
        self.hits = hits

    async def make_probe(self, scheme):
        return {"token": "t", "url": "https://t.oast/x/", "domain": "oast.x"}

    async def wait_for_interaction(self, token, timeout=None):
        return self.hits


def _install(monkeypatch, channel):
    monkeypatch.setattr("vulnclaw.core.oob_channel.OOBChannel", lambda *a, **k: channel)
    monkeypatch.setattr(fwk, "build_attack_url", lambda *a, **k: "atk://x")
    monkeypatch.setattr(fwk, "async_get", lambda *a, **k: None)
    monkeypatch.setattr(fwk, "enrich_finding", lambda d: d)


@pytest_asyncio.fixture(autouse=True)
async def _clean():
    fwk._OOB_ATTEMPTED.clear()
    yield
    fwk._OOB_ATTEMPTED.clear()


def _load(name):
    with open(os.path.join(FIXTURE_DIR, name), "r", encoding="utf-8") as fh:
        return json.load(fh)


_MIDDLEWARE_PREFIXES = ("nacos_", "solr_", "confluence_")


async def _run_middleware_fixture(monkeypatch, fname, fx):
    """Z4.4: 中间件引擎分支——mock async_get 按 URL 子串路由 canned responses。"""
    from vulnclaw.core.scanner import get_engine_by_name

    engine = get_engine_by_name(fx["engine"])
    assert engine is not None, f"{fname}: 引擎 {fx['engine']} 未注册"
    routes = fx.get("routes", [])

    async def _fake_async_get(url, session=None, headers=None, timeout=None, no_retry=False, **kwargs):
        for r in routes:
            if r["url_contains"] in url:
                return (r.get("status", 200), r.get("body", ""), r.get("headers", {}))
        return (404, "", {})

    monkeypatch.setattr(
        "vulnclaw.engines.middleware_exposure_engines.async_get", _fake_async_get
    )
    res = await engine.scan(fx["kwargs"]["target"], session=None)
    exp = fx["expected"]
    if exp.get("not_none"):
        assert res, f"{fname}: 期望检出却为空"
        if exp.get("type"):
            types = [f.get("type", "") for f in res]
            assert exp["type"] in types, f"{fname}: 类型不符 ({types})"
    else:
        assert not res, f"{fname}: 反例不应检出（低误报铁律）got {[f.get('type', '') for f in res]}"


_FIXTURE_FILES = sorted(os.path.basename(p) for p in glob.glob(os.path.join(FIXTURE_DIR, "*.json")))


@pytest.mark.asyncio
@pytest.mark.parametrize("fname", _FIXTURE_FILES)
async def test_engine_fixture(monkeypatch, fname):
    fx = _load(fname)
    # Z4.4: 中间件引擎 fixture 走 mock async_get 分支
    if fname.startswith(_MIDDLEWARE_PREFIXES):
        await _run_middleware_fixture(monkeypatch, fname, fx)
        return
    kwargs = dict(fx["kwargs"])
    kwargs.setdefault("session", None)
    exp = fx["expected"]
    # 正例给回调、反例无回调
    hits = [OOBInteraction(token="t", protocol="dns", tag="dns", time="", extra={})] \
        if exp.get("not_none") else []
    _install(monkeypatch, _FakeChannel(hits))
    res = await fwk._run_oob_scan(**kwargs)
    if exp.get("not_none"):
        assert res is not None, f"{fname}: 期望检出却为 None"
        if exp.get("type"):
            assert res["type"] == exp["type"], f"{fname}: 类型不符 ({res.get('type')})"
    else:
        assert res is None, f"{fname}: 反例不应检出（低误报铁律）"
