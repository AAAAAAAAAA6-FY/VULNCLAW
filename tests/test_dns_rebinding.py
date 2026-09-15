# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""DNS Rebinding 引擎单元测试（离线 mock `_resolve_a`，不做真实外网查询）。

覆盖 2 正 2 反：
  a. TOCTOU 两轮解析 IP 翻转（公网 -> 内网）        -> High finding
  b. 单查询返回公网+私网混合网段                   -> Medium finding
  c. TTL=3600 单公网 IP 两轮稳定                    -> 不产出（fail-closed）
  d. 解析异常 / 无记录                              -> 不产出（fail-closed）
"""
import asyncio

import pytest
import pytest_asyncio

from vulnclaw.engines.net_engines import DnsRebindingEngine


def _make_resolver(host, stream):
    """按调用顺序依次产出 (ips, ttl)；耗尽后抛异常以模拟二次解析失败/无记录。"""
    it = iter(stream)

    def fake(self, _host):
        try:
            return next(it)
        except StopIteration:
            raise RuntimeError("DNS second resolve NXDOMAIN (mock)")

    return fake


def _patch_resolver(monkeypatch, host, stream):
    monkeypatch.setattr(DnsRebindingEngine, "_resolve_a", _make_resolver(host, stream))
    # 竞争窗口间隔很大时也不必真等：压到 0 加速（间隔逻辑本身由独立用例覆盖）
    monkeypatch.setattr(DnsRebindingEngine, "_race_interval", staticmethod(lambda ttl: 0.01))


async def _run(target, monkeypatch, resolver):
    engine = DnsRebindingEngine()
    _patch_resolver(monkeypatch, target, resolver)
    return await engine.scan(target, session=None)


@pytest.mark.asyncio
async def test_a_toctou_ip_flip_produces_high(monkeypatch):
    # 第一次 1.2.3.4（公网），第二次 127.0.0.1（内网），TTL=5 —— TOCTOU 翻转
    res = await _run(
        "https://rebind.example.com/",
        monkeypatch,
        [(["1.2.3.4"], 5), (["127.0.0.1"], 5)],
    )
    assert len(res) == 1
    f = res[0]
    assert f["severity"] == "High"
    assert f["confidence"] == "high"
    assert "DNS rebinding 风险" in f["evidence"]
    assert "1.2.3.4" in f["evidence"] and "127.0.0.1" in f["evidence"]


@pytest.mark.asyncio
async def test_b_mixed_network_medium(monkeypatch):
    # 单查询同时返回公网 + 私网 IP，TTL=1 —— 混合网段特征
    res = await _run(
        "https://mixed.example.com/",
        monkeypatch,
        [(["1.2.3.4", "192.168.1.10"], 1)],
    )
    assert len(res) == 1
    f = res[0]
    assert f["severity"] == "Medium"
    assert f["confidence"] == "medium"
    assert "DNS rebinding 风险" in f["evidence"]
    assert "192.168.1.10" in f["evidence"]


@pytest.mark.asyncio
async def test_c_stable_single_ip_no_finding(monkeypatch):
    # TTL=3600 单公网 IP，两轮解析一致 —— 正常配置，fail-closed 不产出
    res = await _run(
        "https://stable.example.com/",
        monkeypatch,
        [(["93.184.216.34"], 3600), (["93.184.216.34"], 3600)],
    )
    assert res == []


@pytest.mark.asyncio
async def test_d_resolve_exception_no_finding(monkeypatch):
    # 解析失败 / 无记录 —— fail-closed 不产出
    res = await _run(
        "https://nonexistent.example.com/",
        monkeypatch,
        [],
    )
    assert res == []


@pytest.mark.asyncio
async def test_d2_low_ttl_stable_ips_fail_closed(monkeypatch):
    # 仅低 TTL（<60）但两轮 IP 稳定 —— 特征不足，宁漏不误报
    res = await _run(
        "https://edge.example.com/",
        monkeypatch,
        [(["192.0.2.7"], 5), (["192.0.2.7"], 5)],
    )
    assert res == []


def test_race_interval_bounds():
    # 中间间隔逻辑纯函数：TTL≤0 -> 最小；TTL 大 -> 截到 2s
    assert DnsRebindingEngine._race_interval(0) == DnsRebindingEngine.MIN_RACE_INTERVAL
    assert DnsRebindingEngine._race_interval(1) == 1.0
    assert DnsRebindingEngine._race_interval(5) == 2.0
    assert DnsRebindingEngine._race_interval(3600) == 2.0
    assert DnsRebindingEngine._race_interval(None) == DnsRebindingEngine.RACE_INTERVAL


def test_extract_host_rejects_ip_and_empty():
    assert DnsRebindingEngine._extract_host("") == ""
    assert DnsRebindingEngine._extract_host("http://1.2.3.4:8080/x") == ""
    assert DnsRebindingEngine._extract_host("https://rebind.example.com:443/") == "rebind.example.com"


def test_check_returns_none():
    # 参数级入口恒返回 None（DNS 与 URL 参数无关）
    engine = DnsRebindingEngine()
    assert asyncio.run(engine.check("https://a.b/", "p", (200, "", {}), "", None)) is None