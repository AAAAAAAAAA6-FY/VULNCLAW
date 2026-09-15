# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""覆盖兜底 + 上传降噪 单元测试。

背景（实测数据，2026-09-11）：
  - coverage.json 显示 8766 靶机 81 个引擎只有 14 个 ran、67 个 never_ran，
    根因是引擎按「参数数 × (top3 + 轮换)」分配，参数少时尾部引擎永远轮不到。
  - 最新 8090 全量报告 326 条 vulnerabilities 中约 243 条（75%）是文件上传
    "可访问/可执行" 逐类型条目，把真实高危淹没。

本文件锁定两处修复：
  1. _generate_tasks 末尾为未覆盖引擎补 coverage_fallback 任务；
  2. FileUploadEngine._collapse_access_findings 按上传点聚合上传类条目。
"""
import pytest

from vulnclaw.ai.v100.smart_queue import SmartTaskQueue
from vulnclaw.ai.v100.phases import phases_taskgen as m
from vulnclaw.engines.input_engines import FileUploadEngine


class _StubFilter:
    def should_skip(self, *args, **kwargs):
        return (False, "")


class _FakeSelf:
    """最小 orchestrator 替身（与 test_param_mining_taskgen 同构）。"""

    def __init__(self, brief):
        self._recon_brief = brief
        self.target = "http://t/"
        self.task_queue = SmartTaskQueue()
        self.local_filter = _StubFilter()
        self.batch_processor = None
        self._a32_skipped = 0
        self._rotation_offset = 0

    async def _gen_cve_task(self):
        return None


def _brief(url_params):
    return {
        "status": 200,
        "tech_stack": [],
        "url_params": list(url_params),
        "forms": [],
        "apis": [],
        "js_endpoints": [],
        "crawled_endpoints": [],
        "intel": {},
        "param_mining": [],
    }


def _engines_of(task_data):
    if task_data.get("engines"):
        return list(task_data["engines"])
    return [task_data["engine"]] if task_data.get("engine") else []


@pytest.mark.asyncio
async def test_single_param_generates_coverage_fallback_for_tail_engines(monkeypatch):
    """参数只有 1 个时 top3+轮换覆盖不完引擎池，兜底任务必须补齐剩余引擎。"""
    # 本例验证"全量补齐"能力，故显式放开限流（默认 20 见下一条测试）
    monkeypatch.setattr(m.settings, "coverage_fallback_max", 0, raising=False)
    s = _FakeSelf(_brief(["id"]))
    await m._generate_tasks(s)

    tasks = [t.task_data for t in s.task_queue._pending_tasks.values()]
    normal, fallback = set(), set()
    for td in tasks:
        bucket = fallback if td.get("coverage_fallback") else normal
        bucket.update(_engines_of(td))

    assert fallback, "未生成覆盖兜底任务：尾部引擎将永远 never_ran（8766 实测 67/81）"
    # 单参数自身只能覆盖个位数引擎，兜底后应覆盖到引擎池主体
    assert len(normal | fallback) >= 40, (
        f"兜底后覆盖引擎仅 {len(normal | fallback)} 个，缺口未补齐"
    )
    # 兜底按块切分，同一引擎不应出现在两个兜底任务里（重复执行是纯浪费）
    seen, dup = set(), set()
    for td in tasks:
        if not td.get("coverage_fallback"):
            continue
        for e in _engines_of(td):
            if e in seen:
                dup.add(e)
            seen.add(e)
    assert not dup, f"兜底任务间引擎重复: {sorted(dup)}"


@pytest.mark.asyncio
async def test_fallback_task_marks_flag_and_keeps_low_priority():
    """兜底任务必须打标 coverage_fallback，且不抢占高优先级引擎的队列位置。"""
    s = _FakeSelf(_brief(["id"]))
    await m._generate_tasks(s)

    tasks = [t for t in s.task_queue._pending_tasks.values()]
    fb = [t for t in tasks if t.task_data.get("coverage_fallback")]
    assert fb, "缺少 coverage_fallback 任务"
    assert all(t.task_data["type"] in ("engine_bundle", "engine_check") for t in fb)
    assert all(t.priority <= 8 for t in fb), "兜底任务优先级不应高于核心引擎"


@pytest.mark.asyncio
async def test_fallback_respects_default_and_explicit_cap(monkeypatch):
    """兜底默认保守（20 个），显式调小后严格生效——防小目标请求量翻倍。"""
    assert m.settings.coverage_fallback_max == 20, (
        f"兜底默认上限应为保守值 20，实际 {m.settings.coverage_fallback_max}"
    )
    monkeypatch.setattr(m.settings, "coverage_fallback_max", 5, raising=False)
    s = _FakeSelf(_brief(["id"]))
    await m._generate_tasks(s)

    tasks = [t.task_data for t in s.task_queue._pending_tasks.values()]
    fb_engines = [e for td in tasks if td.get("coverage_fallback") for e in _engines_of(td)]
    assert fb_engines, "限流后仍应补齐少量最缺的引擎"
    assert len(fb_engines) <= 5, f"限流失效：兜底补了 {len(fb_engines)} 个引擎（上限 5）"


@pytest.mark.asyncio
async def test_fallback_covers_engines_outside_priority_pool(monkeypatch):
    """池外引擎（不在 engine_priority 内）也必须被兜底覆盖。

    实测 8090 目标 66 个 never_ran 主要来自 idor_dual_session / metamorphic /
    sequence_chain 这类不进参数级轮换的引擎，只补 engine_priority 压根降不下来。
    """
    monkeypatch.setattr(m.settings, "coverage_fallback_max", 0, raising=False)
    s = _FakeSelf(_brief(["id"]))

    class _Engine:
        name = "idor_dual_session"

    s.engines = {"idor_dual_session": _Engine()}   # 模拟 orchestrator 全量引擎注册
    await m._generate_tasks(s)

    tasks = [t.task_data for t in s.task_queue._pending_tasks.values()]
    fb = [e for td in tasks if td.get("coverage_fallback") for e in _engines_of(td)]
    assert "idor_dual_session" in fb, "池外引擎未被兜底覆盖，never_ran 降不下来"


def test_upload_access_findings_collapsed_into_one():
    """同一上传点的多条『可访问/可执行(类型)』必须聚合为 1 条，且不吞掉主漏洞条目。"""
    eng = FileUploadEngine()
    base = {
        "url": "http://t/upload",
        "parameter": "file",
        "severity": "Info",
        "evidence": "上传后访问返回 200",
    }
    items = []
    for d in ("PHP文件", "PHTML文件", "ASP文件", "SVG XSS"):
        items.append(dict(base, type=f"文件上传-可访问/可执行({d})", file_type=d))
    # 同类型重复命中（不同绕过路径）应去重，且最高危级要被保留
    items.append(dict(base, type="文件上传-可访问/可执行(PHP文件)",
                      file_type="PHP文件", severity="Critical"))
    items.append(dict(base, type="文件上传漏洞(PHP文件)", severity="High"))

    out = eng._collapse_access_findings(items)

    types = [f["type"] for f in out]
    assert types.count("文件上传-可访问/可执行") == 1, "同上传点未聚合"
    assert "文件上传漏洞(PHP文件)" in types, "主漏洞条目被误合并"

    merged = next(f for f in out if f["type"] == "文件上传-可访问/可执行")
    assert merged["severity"] == "Critical", "聚合后未保留最高危级"
    assert merged["bypass_count"] == 4
    assert set(merged["bypass_types"]) == {"PHP文件", "PHTML文件", "ASP文件", "SVG XSS"}
    assert "4 种绕过方式" in merged["evidence"]


def test_upload_collapse_keeps_distinct_upload_points():
    """不同上传点各自聚合，不跨点合并（否则会丢掉第二个漏洞点）。"""
    eng = FileUploadEngine()
    items = [
        {"url": "http://t/a", "parameter": "file", "severity": "High",
         "type": "文件上传-可访问/可执行(PHP文件)", "file_type": "PHP文件", "evidence": "e"},
        {"url": "http://t/a", "parameter": "file", "severity": "High",
         "type": "文件上传-可访问/可执行(JSP文件)", "file_type": "JSP文件", "evidence": "e"},
        {"url": "http://t/b", "parameter": "file", "severity": "High",
         "type": "文件上传-可访问/可执行(PHP文件)", "file_type": "PHP文件", "evidence": "e"},
        {"url": "http://t/b", "parameter": "file", "severity": "High",
         "type": "文件上传-可访问/可执行(ASP文件)", "file_type": "ASP文件", "evidence": "e"},
    ]
    out = eng._collapse_access_findings(items)
    collapsed = [f for f in out if f["type"] == "文件上传-可访问/可执行"]
    assert len(collapsed) == 2, "不同上传点应各自聚合为 1 条"
    assert {f["url"] for f in collapsed} == {"http://t/a", "http://t/b"}
    assert all(f["bypass_count"] == 2 for f in collapsed)
