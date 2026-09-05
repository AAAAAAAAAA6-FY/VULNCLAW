# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

# tests/test_sp24_agent_race.py
"""A2.4 竞争协作（同一高价值漏洞派 2 个不同策略子 Agent，取先确认者）单元测试。

覆盖：开关默认关 / 候选提取与高价值排序 / 双节点派生 / 无参数回退单节点 /
取先确认者（先完成者胜、后到者弃权计损耗）/ 异常弃权 / coordinate 集成竞速。
零外网依赖：全部本地协程 + monkeypatch，不启动扫描。
"""
import asyncio

import pytest

from vulnclaw.ai.dispatcher import AgentCoordinator, AgentNode
from vulnclaw.config.settings import settings


# ---------------------------------------------------------------------------
# 1) 开关
# ---------------------------------------------------------------------------
def test_race_disabled_by_default():
    assert getattr(settings, "enable_agent_race", False) is False


def test_race_enabled_flag(monkeypatch):
    monkeypatch.setattr(settings, "enable_agent_race", True)
    assert AgentCoordinator("http://t", None)._race_enabled() is True


# ---------------------------------------------------------------------------
# 2) 候选提取
# ---------------------------------------------------------------------------
def _coord():
    return AgentCoordinator("http://t", None)


def test_race_candidates_from_endpoints():
    c = _coord()
    c.snapshot.blackboard.publish("endpoints", ["http://t/a?id=1&file=x", "http://t/b"])
    cands = c._race_candidates("exploit", max_n=10)
    assert "id" in cands and "file" in cands
    # 高价值关键字（file/id）排在普通参数前；file 与 id 同级保持稳定序
    high = {p for p in cands if any(k in p.lower() for k in ("file", "id"))}
    for p in cands:
        if p not in high:
            assert all(cands.index(high_i) < cands.index(p) for high_i in high)


def test_race_candidates_limit():
    c = _coord()
    c.snapshot.blackboard.publish("endpoints", ["http://t/a?a=1&b=2&c=3"])
    assert len(c._race_candidates("exploit", max_n=2)) <= 2


def test_race_candidates_empty():
    assert _coord()._race_candidates("exploit") == []


# ---------------------------------------------------------------------------
# 3) 派生
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_spawn_race_two_nodes_different_focus():
    c = _coord()
    c.snapshot.blackboard.publish("endpoints", ["http://t/a?file=x&id=1"])
    nodes = await c._spawn_race("exploit")
    assert len(nodes) == 2
    addrs = [n.addr for n in nodes]
    assert addrs == ["exploit", "exploit.race2"]
    focuses = {n.focus for n in nodes}
    assert len(focuses) == 2


@pytest.mark.asyncio
async def test_spawn_race_no_params_fallback_single():
    c = _coord()
    nodes = await c._spawn_race("exploit")
    assert len(nodes) == 1
    assert nodes[0].addr == "exploit"


# ---------------------------------------------------------------------------
# 4) 取先确认者
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_collect_race_empty():
    winners, losers = await _coord()._collect_race([])
    assert winners == [] and losers == 0


@pytest.mark.asyncio
async def test_collect_race_first_winner_cancels_rest():
    async def slow():
        await asyncio.sleep(0.05)
        return [{"type": "sqli", "severity": "high"}]

    async def fast():
        return [{"type": "xss", "severity": "medium"}]

    t1 = asyncio.create_task(fast())
    t2 = asyncio.create_task(slow())
    winners, losers = await _coord()._collect_race([t1, t2])
    assert len(winners) == 1
    assert winners[0]["type"] == "xss"  # 先确认者胜
    assert losers == 1                  # 后到者弃权
    await asyncio.sleep(0)  # 让 cancel 传播到任务
    assert t2.cancelled()


@pytest.mark.asyncio
async def test_collect_race_exception_counts_loser():
    async def boom():
        raise RuntimeError("boom")

    async def ok():
        return [{"type": "xss"}]

    winners, losers = await _coord()._collect_race(
        [asyncio.create_task(boom()), asyncio.create_task(ok())])
    assert len(winners) == 1
    assert losers == 1


# ---------------------------------------------------------------------------
# 5) coordinate 集成：开开关后 exploit 走 race，取先确认者
# ---------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_coordinate_race_integration(monkeypatch):
    monkeypatch.setattr(settings, "enable_agent_race", True)
    c = _coord()
    c.snapshot.blackboard.publish("endpoints", ["http://t/a?file=x&id=1"])

    async def fake_run(self, target, session):
        if self.addr == "recon":
            return [{"type": "info", "url": target}]
        if self.addr == "exploit.race2":
            await asyncio.sleep(0.05)
            return [{"type": "rce", "severity": "critical", "addr": self.addr}]
        return []

    monkeypatch.setattr(AgentNode, "run", fake_run)
    out = await c.coordinate(["recon", "exploit"])
    types = {f.get("type") for f in out["findings"]}
    assert "rce" in types
    assert out["race"] is not None
    assert out["race"]["enabled"] is True
    assert out["race"]["losers"] == 1
