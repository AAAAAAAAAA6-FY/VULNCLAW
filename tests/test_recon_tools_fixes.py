# -*- coding: utf-8 -*-
"""批量摸底修复的单元测试（ffuf stdout 回退 / katana 解析 / ToolGov 降级消噪 / OOB 缺失短路 / nuclei 超时配置）。"""
import asyncio

from vulnclaw.modules.vuln_scanner.directory_ffuf import _parse_ffuf_stdout_rows
from vulnclaw.core.tool_governance import ToolGovernance
from vulnclaw.core import oob_channel
from vulnclaw.config.settings import settings


# ---------------- 1. ffuf stdout 表格回退解析 ----------------
def test_ffuf_stdout_rows_parses_table():
    sample = """
:: Progress: [4/4] :: Job [1/1] :: 0 req/sec :: Errors: 0 ::
admin                    [Status: 200, Size: 276794, Words: 6093, Lines: 543, Duration: 685ms]
https://www.audible.com/robots.txt  [Status: 200, Size: 21771, Words: 609, Lines: 543, Duration: 729ms]
/api/v2/catalog          [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 211ms]
notfound                 [Status: 404, Size: 19, Words: 2, Lines: 1, Duration: 10ms]
"""
    rows = _parse_ffuf_stdout_rows(sample)
    assert ("admin", 200) in rows
    assert ("https://www.audible.com/robots.txt", 200) in rows
    assert ("/api/v2/catalog", 302) in rows
    assert ("notfound", 404) in rows
    assert len(rows) == 4


def test_ffuf_stdout_rows_empty():
    assert _parse_ffuf_stdout_rows("") == []
    assert _parse_ffuf_stdout_rows(None) == []
    assert _parse_ffuf_stdout_rows("no table here") == []


# ---------------- 2. ToolGov 降级期失败不刷屏 ----------------
def test_toolgov_degraded_warns_once_then_silent(tmp_path, monkeypatch):
    gov = ToolGovernance()
    monkeypatch.setattr(gov, "health_file", tmp_path / "health.json")
    monkeypatch.setattr(gov, "usage_file", tmp_path / "tool_usage.jsonl")
    warned = []
    monkeypatch.setattr(oob_channel.logger, "warning", lambda msg, *a, **k: warned.append(msg))
    for _ in range(10):
        gov.record_result("katana", success=False, error="boom")
    assert len(warned) == 1
    assert not gov.is_healthy("katana")


def test_toolgov_success_recovers(tmp_path, monkeypatch):
    gov = ToolGovernance()
    monkeypatch.setattr(gov, "health_file", tmp_path / "health.json")
    monkeypatch.setattr(gov, "usage_file", tmp_path / "tool_usage.jsonl")
    for _ in range(3):
        gov.record_result("x", success=False)
    assert not gov.is_healthy("x")
    gov.record_result("x", success=True)
    assert gov.is_healthy("x")
    assert gov.health_snapshot("x")["consecutive_failures"] == 0


# ---------------- 3. OOB：interactsh-client 缺失时真实方法立即短路 ----------------
def test_oob_skips_itsh_when_binary_missing(monkeypatch):
    from vulnclaw.core.oob_channel import OOBChannel
    got = {}

    def fake_resolve(name):
        got["asked"] = name
        return None  # 二进制缺失

    async def never_run(*a, **k):
        got["run_tool_called"] = True
        raise AssertionError("二进制缺失时绝不应调用 run_tool（否则会走 8s 注册）")

    async def fake_dnslog(self):
        return None

    monkeypatch.setattr(oob_channel, "is_channel_down", lambda: False)
    monkeypatch.setattr(oob_channel, "resolve_tool_path", fake_resolve)
    monkeypatch.setattr(oob_channel, "run_tool", never_run)
    monkeypatch.setattr(OOBChannel, "_request_dnslog_domain", fake_dnslog)
    # 全通道失败会真实触发 mark_channel_down（300s 熔断），污染字母序后续 z24 测试 → 一并屏蔽
    monkeypatch.setattr(oob_channel, "mark_channel_down", lambda *a, **k: None)

    ch = OOBChannel(provider="auto")
    out = asyncio.run(ch.request_domain())
    assert out is None
    assert got["asked"] == "interactsh-client"
    assert not got.get("run_tool_called")
    assert not got.get("itsh_called")

# ---------------- 4. nuclei 超时配置 ----------------
def test_settings_nuclei_run_timeout_default():
    assert settings.nuclei_run_timeout == 240
