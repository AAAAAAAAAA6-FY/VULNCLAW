# SPDX-License-Identifier: AGPL-3.0-or-later
# This file is part of VULNCLAW / pentest_platform.

"""回归测试：_stream_verify_batch 验证窗口并发丢失 finding 的修复。

真实故障（本地靶场真扫复现）：
- 21:58:08 批次 #4 开始验证（临时替换 _pending_verify = batch）
- 21:58:10 新 finding（SQLi）被 phases_executor append 到临时替换的 batch list
- 21:58:13 批次 #4 finally 仅重建 saved_pending → 新 append 条目被静默丢弃
- 结果：SQLi 从未验证、不进报告 → 评测场 recall 跌破红线

修复：finally 重建 _pending_verify 时合并临时 list 上验证期间新增的条目。
"""
from __future__ import annotations

import asyncio

import pytest

try:
    from vulnclaw.ai.v100.orchestrator import V100Orchestrator
except (ImportError, AttributeError) as exc:  # pragma: no cover - 缺依赖时跳过
    pytest.skip(f"V100Orchestrator 无法导入: {exc}", allow_module_level=True)


def _make_orchestrator() -> V100Orchestrator:
    """用 __new__ 轻量构建：只挂载 _stream_verify_batch 需要的属性和方法。"""
    orch = object.__new__(V100Orchestrator)
    orch._pending_verify = []
    orch._pending_verify_lock = asyncio.Lock()
    orch._stream_touched_keys = set()
    return orch


def _finding(fid: int, ftype: str = "x") -> dict:
    return {"type": ftype, "url": f"http://t/{fid}", "parameter": f"p{fid}", "method": "GET"}


class TestStreamVerifyWindowLoss:
    """验证窗口并发：新 append 的 finding 不得在批次完成后丢失。"""

    def test_append_during_verify_not_lost(self):
        """修复核心：验证期间 append 的新条目，批次 finally 后仍在 _pending_verify。"""
        orch = _make_orchestrator()
        batch = [_finding(1)]
        orch._pending_verify = list(batch)

        async def fake_verify_all():
            # 模拟验证窗口内 phases_executor append 新 finding（含 SQLi 场景）
            orch._pending_verify.append(_finding(2, "sqli"))

        orch._verify_all_findings = fake_verify_all

        async def run():
            await orch._stream_verify_batch(batch)

        asyncio.run(run())

        assert any(v.get("type") == "sqli" for v in orch._pending_verify)
        assert len(orch._pending_verify) >= 2

    def test_batch_and_transient_dedup(self):
        """批次内 + 验证期间新增，合并后无双份。"""
        orch = _make_orchestrator()
        batch = [_finding(1)]
        orch._pending_verify = list(batch)

        async def fake_verify_all():
            orch._pending_verify.append(_finding(1))  # 与 batch 同 key → 应去重
            orch._pending_verify.append(_finding(3, "file_upload"))

        orch._verify_all_findings = fake_verify_all

        async def run():
            await orch._stream_verify_batch(batch)

        asyncio.run(run())

        keys = [orch._finding_verify_key(v) for v in orch._pending_verify]
        assert keys.count(orch._finding_verify_key(_finding(1))) == 1
        assert keys.count(orch._finding_verify_key(_finding(3, "file_upload"))) == 1

    def test_empty_batch_no_crash(self):
        """空批次场景（理论上不会发生）也应安全返回。"""
        orch = _make_orchestrator()
        orch._pending_verify = []

        async def fake_verify_all():
            pass

        orch._verify_all_findings = fake_verify_all

        async def run():
            await orch._stream_verify_batch([])

        asyncio.run(run())

    def test_touched_marking_consistent(self):
        """批次处理完成后 touched 集合恢复一致，收尾不再重复处理。"""
        orch = _make_orchestrator()
        batch = [_finding(7)]
        orch._pending_verify = list(batch)

        async def fake_verify_all():
            pass

        orch._verify_all_findings = fake_verify_all

        async def run():
            await orch._stream_verify_batch(batch)

        asyncio.run(run())

        # 批次 keys 已合入 touched：收尾 _verify_all_findings 会跳过它们
        assert orch._finding_verify_key(_finding(7)) in orch._stream_touched_keys
