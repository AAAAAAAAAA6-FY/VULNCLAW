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


_FIXTURE_FILES = sorted(os.path.basename(p) for p in glob.glob(os.path.join(FIXTURE_DIR, "*.json")))


@pytest.mark.asyncio
@pytest.mark.parametrize("fname", _FIXTURE_FILES)
async def test_engine_fixture(monkeypatch, fname):
    fx = _load(fname)
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
