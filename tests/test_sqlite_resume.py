# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
"""P5-1: SQLite 断点续扫单元测试（A4.6 落地验证）。

覆盖：
- Schema / 阶段检查点 / task_done（细粒度续扫）/ findings / agent_memory
- resume_info 决策（version / finished / expired / no_checkpoint）
- 模拟 kill -9 后重启：检查点可恢复 findings / 已扫三元组 / agent 记忆
- 阶段跳过判定逻辑（与 V100Orchestrator._STAGES 对齐）
"""
import time

import pytest

from vulnclaw.ai.v100.orchestrator import V100Orchestrator
from vulnclaw.core_modules.sqlite_persistence import (
    CHECKPOINT_EXPIRE_DAYS,
    CHECKPOINT_VERSION,
    SqliteCheckpointStore,
    db_path_for_target,
    safe_target_key,
)


def _new_store(tmp_path, name="scan.db"):
    return SqliteCheckpointStore(str(tmp_path / name), scan_id="s1", target="http://t")


def test_schema_and_meta(tmp_path):
    s = _new_store(tmp_path)
    s.set_meta("k", {"a": 1})
    assert s.get_meta("k") == {"a": 1}
    assert s.get_meta("missing", 42) == 42
    s.close()


def test_stage_checkpoints(tmp_path):
    s = _new_store(tmp_path)
    s.init_scan("s1", "http://t")
    assert s.get_completed_stage_index() == -1
    for i, n in enumerate(["recon", "taskgen", "scan"]):
        s.save_stage_start(i, n)
        s.save_stage_done(i, n, payload={"x": i})
    assert s.get_completed_stage_index() == 2
    stages = s.list_stages()
    assert [st["name"] for st in stages] == ["recon", "taskgen", "scan"]
    assert all(st["status"] == "done" for st in stages)
    assert s.list_stages()[1]["payload"] == {"x": 1}
    s.close()


def test_task_done_roundtrip(tmp_path):
    s = _new_store(tmp_path)
    s.mark_task_done("sqli", "http://t?id=1", "id")
    s.mark_task_done("sqli", "http://t?id=1", "id")  # 幂等
    s.mark_task_done("xss", "http://t", "q")
    assert s.is_task_done("sqli", "http://t?id=1", "id")
    assert not s.is_task_done("sqli", "http://t?id=1", "other")
    assert s.load_done_tasks() == {
        ("sqli", "http://t?id=1", "id"),
        ("xss", "http://t", "q"),
    }
    s.close()


def test_finding_roundtrip_and_dedup(tmp_path):
    s = _new_store(tmp_path)
    f1 = {"url": "u", "parameter": "p", "type": "sqli", "method": "GET", "evidence": "e" * 100}
    f2 = dict(f1)  # 同 key（evidence 前 80 字相同）→ 同 fid → 去重
    f3 = {"url": "u2", "parameter": "p", "type": "xss", "method": "GET", "evidence": "x"}
    s.add_finding(f1)
    s.add_finding(f2)
    s.add_finding(f3)
    loaded = s.load_findings()
    assert len(loaded) == 2  # f1/f2 合并
    s.close()


def test_agent_memory_roundtrip(tmp_path):
    s = _new_store(tmp_path)
    mem = {"experiences": [{"target": "t", "tool": "sqli", "success": True}]}
    s.save_agent_memory("shared_knowledge", mem)
    assert s.load_agent_memory("shared_knowledge") == mem
    assert s.load_agent_memory("missing") is None
    s.close()


def test_resume_info_fresh_no_checkpoint(tmp_path):
    # 新建库但未 init_scan → version 缺失 → 不应恢复
    s = _new_store(tmp_path)
    info = s.resume_info()
    assert info["should_resume"] is False
    assert info["reason"] == "version_mismatch"
    s.close()


def test_resume_info_version_mismatch(tmp_path):
    s = _new_store(tmp_path)
    s.set_meta("version", CHECKPOINT_VERSION + 99)
    s.save_stage_done(1, "recon")
    info = s.resume_info()
    assert info["should_resume"] is False
    assert info["reason"] == "version_mismatch"
    s.close()


def test_resume_info_finished_blocks_resume(tmp_path):
    s = _new_store(tmp_path)
    s.init_scan("s1", "http://t")
    s.save_stage_done(0, "recon")
    s.mark_finished()
    info = s.resume_info()
    assert info["should_resume"] is False
    assert info["finished"] is True
    s.close()


def test_resume_info_expired_blocks_resume(tmp_path):
    s = _new_store(tmp_path)
    s.init_scan("s1", "http://t")
    s.save_stage_done(0, "recon")
    # 把 updated_at 推到过期之外
    s.set_meta("updated_at", time.time() - (CHECKPOINT_EXPIRE_DAYS + 1) * 86400)
    info = s.resume_info()
    assert info["should_resume"] is False
    assert info["expired"] is True
    s.close()


def test_resume_info_should_resume(tmp_path):
    s = _new_store(tmp_path)
    s.init_scan("s1", "http://t")
    s.save_stage_done(0, "recon")
    s.save_stage_done(1, "taskgen")
    info = s.resume_info()
    assert info["should_resume"] is True
    assert info["stage_index"] == 1
    s.close()


def test_breakpoint_recovery_simulation(tmp_path):
    """模拟 kill -9：进程死前已落盘，重启后从断点恢复。"""
    db = tmp_path / "scan.db"

    # ---- 第一次运行（被 kill -9 打断在 scan 阶段之后）----
    s1 = SqliteCheckpointStore(str(db), scan_id="s1", target="http://t")
    s1.init_scan("s1", "http://t")
    for i, n in enumerate(["recon", "taskgen", "scan"]):
        s1.save_stage_start(i, n)
        s1.save_stage_done(i, n)
    s1.add_finding({"url": "u", "parameter": "p", "type": "sqli", "method": "GET", "evidence": "e" * 100})
    s1.mark_task_done("sqli", "http://t?id=1", "id")
    s1.mark_task_done("xss", "http://t", "q")
    s1.save_agent_memory("shared_knowledge", {"experiences": [{"target": "t", "tool": "sqli"}]})
    s1.close()

    # ---- 重启（新进程/新连接，同一 db）----
    s2 = SqliteCheckpointStore(str(db), scan_id="s2", target="http://t")
    info = s2.resume_info()
    assert info["should_resume"] is True
    assert info["stage_index"] == 2  # 已完成到 scan

    # findings 恢复
    loaded_findings = s2.load_findings()
    assert len(loaded_findings) == 1
    assert loaded_findings[0]["type"] == "sqli"

    # 已扫三元组恢复（续扫主循环据此跳过）
    done = s2.load_done_tasks()
    assert ("sqli", "http://t?id=1", "id") in done
    assert ("xss", "http://t", "q") in done

    # agent 记忆恢复（A4.6：含 agent 记忆）
    mem = s2.load_agent_memory("shared_knowledge")
    assert mem == {"experiences": [{"target": "t", "tool": "sqli"}]}

    # 续跑剩余阶段并正常结束
    for i, n in enumerate(["chain_router", "react_deep_dive", "agent_coordinator", "extras", "verify", "report"]):
        s2.save_stage_start(3 + i, n)
        s2.save_stage_done(3 + i, n)
    s2.mark_finished()
    s2.close()

    # 再次重启：已 finished → 不再恢复
    s3 = SqliteCheckpointStore(str(db))
    assert s3.resume_info()["should_resume"] is False
    s3.close()


def test_stage_skip_decision_alignment():
    """_stage 的跳过判定（idx <= resume_stage_index）与 _STAGES 顺序一致。"""
    stages = V100Orchestrator._STAGES
    assert stages[0] == "recon" and stages[-1] == "report"
    # 已完成到 scan（index=2）→ 0,1,2 跳过，3.. 重跑
    resume_index = 2
    to_skip = {stages[i] for i in range(len(stages)) if i <= resume_index}
    assert to_skip == {"recon", "taskgen", "scan"}
    assert "chain_router" not in to_skip


def test_db_path_for_target_deterministic(tmp_path):
    p1 = db_path_for_target("http://example.com/a", base_dir=str(tmp_path))
    p2 = db_path_for_target("http://example.com/a", base_dir=str(tmp_path))
    assert p1 == p2
    assert p1.name == f"{safe_target_key('http://example.com/a')}.db"
    # 同一路径构造存储即建库（确定性落点）
    st = SqliteCheckpointStore(str(p1))
    st.close()
    assert p1.exists()


def test_reset_clears_checkpoint(tmp_path):
    s = _new_store(tmp_path)
    s.init_scan("s1", "http://t")
    s.save_stage_done(0, "recon")
    s.add_finding({"url": "u", "type": "sqli", "method": "GET", "evidence": "e"})
    s.reset()
    assert s.get_completed_stage_index() == -1
    assert s.load_findings() == []
    s.close()
