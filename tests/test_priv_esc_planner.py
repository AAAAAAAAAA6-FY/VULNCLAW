# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""C2.2: 受控提权路径规划器测试。

覆盖：FakeChannel 命令记录；deny 模式枚举执行但 attempt 拒绝且命令不落地；
      allow 模式 attempt 执行且结果可被 AttackGraph.from_chains 消费；plan JSON 往返。
"""
import json

import pytest

from vulnclaw.deepsec.priv_esc_planner import PrivEscPlanner


class _FakeChannel:
    def __init__(self, outputs=None, default=""):
        self.commands = []
        self.outputs = outputs or {}
        self.default = default

    async def execute_command(self, cmd, context=None):
        self.commands.append(cmd)
        return self.outputs.get(cmd, self.default)


class _FakeGuard:
    def __init__(self, allow=False):
        self.allow = allow
        self.audit = []

    def require_approval(self, op, detail=""):
        self.audit.append(detail)
        return self.allow


_ENUM_OUTPUTS = {
    "uname -s": "Linux",
    "uname -a": "Linux host 5.15.0 x86_64",
    "id": "uid=1000(user) gid=1000(user) groups=1000(user),994(docker)",
    "sudo -l": "User user may run the following commands on host:\n    (ALL) NOPASSWD: ALL",
    "find / -perm -4000 -type f 2>/dev/null": (
        "-rwsr-xr-x 1 root root 4320 /usr/bin/passwd\n"
        "-rwsr-xr-x 1 root root 222 /usr/bin/su"
    ),
    "groups": "user docker",
    "cat /etc/crontab 2>/dev/null": "17 * * * * root run-parts /etc/cron.hourly",
    "env": "PATH=/usr/bin:/bin HOME=/home/user",
    "ip a 2>/dev/null || ifconfig": "1: lo: <LOOPBACK>",
}


@pytest.mark.asyncio
async def test_deny_mode_enumerates_but_attempts_skipped():
    """deny 模式：枚举执行，attempt 全部被审批拒绝，命令不落地。"""
    channel = _FakeChannel(_ENUM_OUTPUTS)
    guard = _FakeGuard(allow=False)
    p = PrivEscPlanner(channel=channel, guard=guard, target="http://t/x", finding_id="f-low")
    results = await p.enumerate()
    assert results, "枚举应产出结果"
    plan = p.plan()
    attempts = [s for s in plan if s["kind"] == "attempt"]
    assert attempts, "命中候选应生成 attempt 步骤"
    # 枚举命令已落地
    assert "sudo -l" in channel.commands
    # attempt 验证命令未落地（deny → 命令不执行）
    for a in attempts:
        assert a["cmd"] not in channel.commands, f"deny 模式下 {a['cmd']} 不应执行"
    res = await p.execute()
    # 审批被调用（每条 attempt 一次，发生在 execute 阶段）
    assert len(guard.audit) >= len(attempts)
    assert res["success"] is False
    assert any("denied" in str(h.get("strategy", "")) for h in res["chain"])
    # 审计环有 privilege_escalation 记录
    assert all("privilege_escalation" in str(d) or d for d in guard.audit)


@pytest.mark.asyncio
async def test_allow_mode_attempts_execute_and_feed_attack_graph():
    """allow 模式：attempt 执行、产出 success，结果可被 AttackGraph.from_chains 消费。"""
    outputs = dict(_ENUM_OUTPUTS)
    outputs.update({
        "sudo -n true": "true",
        "docker ps": "CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS   PORTS   NAMES\nabcdef123456   nginx     nginx -g  2s ago   Up 2s           80/tcp   web",
        "ls -l /usr/bin/passwd": "-rwsr-xr-x 1 root root 4320 /usr/bin/passwd",
        "cat /etc/cron.hourly": "run-parts",
    })
    channel = _FakeChannel(outputs)
    guard = _FakeGuard(allow=True)
    p = PrivEscPlanner(channel=channel, guard=guard, target="http://t/x", finding_id="f-low")
    await p.enumerate()
    res = await p.execute()
    assert res["success"] is True
    # 审批放行 → attempt 命令落地
    assert "sudo -n true" in channel.commands
    assert "docker ps" in channel.commands
    # AttackGraph 双端消费（E1.4）
    from vulnclaw.core.attack_graph import AttackGraph

    g = AttackGraph.from_chains([res], target="http://t/x")
    j = g.to_json()
    assert j["stats"]["vulns"] >= 1
    assert j["stats"]["gates"] >= 1
    assert j["stats"]["edges"] >= 1


def test_plan_json_roundtrip():
    """plan/enum 结果可 JSON 往返（E1.4 / 持久化）。"""
    plan = PrivEscPlanner(target="http://t/x", finding_id="f-low")
    text = plan.to_json()
    data = json.loads(text)
    assert data["target"] == "http://t/x"
    restored = PrivEscPlanner.from_json(text)
    assert restored.plan() == plan.plan()
    assert restored.target == "http://t/x"


@pytest.mark.asyncio
async def test_enum_platform_auto_windows():
    """auto 探测到 Windows → 使用 Windows 枚举命令表。"""
    channel = _FakeChannel({"uname -s": "Windows"}, default="")
    guard = _FakeGuard(allow=False)
    p = PrivEscPlanner(channel=channel, guard=guard, target="http://t/x")
    results = await p.enumerate()
    cmds = [r["cmd"] for r in results]
    assert "whoami /all" in cmds
    assert "net user" in cmds