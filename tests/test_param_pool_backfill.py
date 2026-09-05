# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""SP15.2 合流桥接：参数池(param_candidates.jsonl) 回灌 recon_brief[param_mining]。

覆盖（离线，不触网）：默认关零回灌（零行为回归）；池合法候选 -> brief 出现
{url,param,base_len,signal} 完整条目；坏行/缺字段过滤；池文件缺失优雅跳过。
"""
import json
import pytest

from vulnclaw.ai.v100.phases import phases_recon as m
from vulnclaw.core.settings import settings


def _write_pool(path, items):
    with open(path, "w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it) + "\n")


@pytest.fixture(autouse=True)
def _reset():
    prev = settings.enable_param_mining
    yield
    settings.enable_param_mining = prev


def _mkbrief():
    return {"status": 200, "url_params": [], "crawled_endpoints": []}


def test_default_off_no_backfill(tmp_path, monkeypatch):
    pool = tmp_path / "param_candidates.jsonl"
    _write_pool(pool, [{"url": "http://t/x", "param": "p1", "base_len": 1, "signal": "diff_len"}])
    monkeypatch.setattr("vulnclaw.modules.recon.param_pool_path", lambda: str(pool))
    brief = _mkbrief()
    m.backfill_param_mining(brief)
    assert "param_mining" not in brief


def test_on_with_pool_backfills_brief(tmp_path, monkeypatch):
    settings.enable_param_mining = True
    pool = tmp_path / "param_candidates.jsonl"
    _write_pool(pool, [
        {"url": "http://t/x?id=1", "param": "hid", "base_len": 120, "signal": "reflected"},
        {"url": "http://t/y", "param": "q2", "base_len": 90, "signal": "diff_len"},
    ])
    monkeypatch.setattr("vulnclaw.modules.recon.param_pool_path", lambda: str(pool))
    brief = _mkbrief()
    m.backfill_param_mining(brief)
    pm = brief.get("param_mining")
    assert pm and len(pm) == 2
    assert {it["param"] for it in pm} == {"hid", "q2"}
    assert all(it["url"] and it["signal"] for it in pm)


def test_bad_lines_filtered(tmp_path, monkeypatch):
    settings.enable_param_mining = True
    pool = tmp_path / "param_candidates.jsonl"
    _write_pool(pool, [
        {"url": "http://t/x", "param": "ok1", "base_len": 10, "signal": "reflected"},
        "not-a-dict",
        {"url": "http://t/y"},                       # 缺 param
        {"param": "p2"},                             # 缺 url
        '{"broken json"',
        {"url": "http://t/z", "param": "ok2", "base_len": 11, "signal": "diff_len"},
    ])
    monkeypatch.setattr("vulnclaw.modules.recon.param_pool_path", lambda: str(pool))
    brief = _mkbrief()
    m.backfill_param_mining(brief)
    pm = brief.get("param_mining") or []
    assert {it["param"] for it in pm} == {"ok1", "ok2"}


def test_missing_pool_graceful(tmp_path, monkeypatch):
    settings.enable_param_mining = True
    monkeypatch.setattr("vulnclaw.modules.recon.param_pool_path",
                        lambda: str(tmp_path / "no_such.jsonl"))
    brief = _mkbrief()
    m.backfill_param_mining(brief)                  # 不抛
    assert "param_mining" not in brief