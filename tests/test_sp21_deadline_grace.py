# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP21.2 动态补测任务宽限窗口（A 线，真扫观察项收口）。

问题：param_mining 回灌 / live_intake 实时任务在 attack 阶段中后期才入队，
固定墙钟 deadline（attack_node_budget=130s）一到就被 fail_all_pending 误杀
（B 侧真扫联调记录 task_22 撞预算判败的根因）。

修复：fail_all_pending 支持 protect=True 保留动态补测任务，deadline enforcer
给宽限窗口（attack_dynamic_grace_s 默认 45s）执行完；无受保护任务时零回归。
"""
import asyncio

import pytest

from vulnclaw.ai.v100.smart_queue import (
    SmartTaskQueue,
    is_protected_task,
)


def _task(engine="xss", source=None, param=None):
    td = {"type": "engine_bundle", "engines": [engine], "target": "http://t/x", "priority": 8}
    if source:
        td["source"] = source
    if param:
        td["param"] = param
        td["target"] = "http://t/x?q=1"
    return td


class TestIsProtectedTask:
    def test_param_mining_protected(self):
        assert is_protected_task(_task(source="param_mining")) is True

    def test_live_source_protected(self):
        assert is_protected_task(_task(source="live:crawler")) is True
        assert is_protected_task(_task(source="live:feed")) is True

    def test_plain_task_not_protected(self):
        assert is_protected_task(_task()) is False
        assert is_protected_task(_task(source="engine_check")) is False

    def test_non_dict_not_protected(self):
        assert is_protected_task(None) is False
        assert is_protected_task("task") is False


class TestFailAllPendingProtect:
    def test_protect_keeps_dynamic_tasks(self):
        async def _main():
            q = SmartTaskQueue()
            await q.add_task(_task(source="param_mining", param="q"))
            await q.add_task(_task(source="live:crawler", param="r"))
            await q.add_task(_task(engine="sqli", param="s"))
            n = await q.fail_all_pending(reason="test", protect=True)
            assert n == 1  # 只有普通任务被判败
            assert await q.protected_pending_count() == 2
            # 受保护任务仍可被 worker 取出执行
            seen = []
            for _ in range(2):
                full = await q.get_next_full()
                assert full is not None
                seen.append(full[1].get("source"))
            assert sorted(seen) == ["live:crawler", "param_mining"]
        asyncio.run(_main())

    def test_unprotected_clears_everything(self):
        async def _main():
            q = SmartTaskQueue()
            await q.add_task(_task(source="param_mining", param="q"))
            await q.add_task(_task())
            n = await q.fail_all_pending(reason="test", protect=False)
            assert n == 2
            assert await q.protected_pending_count() == 0
            assert q.get_pending_count() == 0
            assert await q.get_next_full() is None
        asyncio.run(_main())

    def test_legacy_behavior_without_dynamic(self):
        """无受保护任务时 protect=True 与旧版完全一致（零回归）。"""
        async def _main():
            q = SmartTaskQueue()
            for i in range(3):
                await q.add_task(_task(engine=f"e{i}"))
            n = await q.fail_all_pending(reason="test", protect=True)
            assert n == 3
            assert q.get_pending_count() == 0
        asyncio.run(_main())

    def test_protected_pending_count_zero_when_empty(self):
        async def _main():
            q = SmartTaskQueue()
            assert await q.protected_pending_count() == 0
        asyncio.run(_main())

    def test_grace_window_full_flow(self):
        """enforcer 时序模拟：宽限窗口内动态任务执行完，宽限结束后清空。"""
        async def _main():
            q = SmartTaskQueue()
            await q.add_task(_task(source="param_mining", param="q"))
            await q.add_task(_task())
            await q.fail_all_pending(reason="budget over", protect=True)
            # 宽限窗口：worker 取出动态任务并完成
            tid, _ = await q.get_next_full()
            await q.complete_task(tid, success=True)
            assert await q.protected_pending_count() == 0
            # 宽限结束：无剩余任务可清
            n = await q.fail_all_pending(reason="grace over", protect=False)
            assert n == 0
            assert await q.is_drained() is True
        asyncio.run(_main())


@pytest.mark.parametrize("source", ["param_mining", "live:crawler", "live:feed"])
def test_dynamic_sources_protected_param(source):
    assert is_protected_task(_task(source=source)) is True