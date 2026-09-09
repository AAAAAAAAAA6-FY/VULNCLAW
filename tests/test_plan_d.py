# -*- coding: utf-8 -*-
"""D 方案契约测试：调度护栏 / 引擎目标域硬约束 / 报告证据运营。

覆盖：
  - D2 域硬约束（scope 空 → 仅主域/子域；scope 配置 → 白名单 + 主域）
  - D1 粘滞簿记（达阈值入黑名单）
  - D1 执行入口粘滞跳过（墓碑命中不占 worker）
  - D3 证据链多源合并 + 截断
  - D3 sigma 分档（实锤高优先 / pending_review 降档）
"""
import asyncio
from types import SimpleNamespace

import pytest

from vulnclaw.ai.v100.phases import phases_executor as pe
from vulnclaw.ai.v100.phases import phases_report as pr
from vulnclaw.core.settings import settings


class _FakeSelf:
    """最小钳：D2 依赖 self.target 与 parse_scope()（settings 读取，测试用 monkeypatch）。"""

    def __init__(self, target: str):
        self.target = target
        self._processed_params = set()
        self._sticky_fail_counter = {}
        self._sticky_blacklist = set()
        self._task_pick_ts = {}
        self._dbg_workers = {}


# ---------------- D2: 引擎目标域硬约束 ----------------
def test_engine_target_allowed_scope_empty(monkeypatch):
    """scope 未配置 → 主域/子域放行，外域拒绝（fail-closed）。"""
    monkeypatch.setattr(settings, "allowed_scope", "")
    s = _FakeSelf("https://example.com/")
    ok, _ = pe._engine_task_target_allowed(s, {"target": "https://example.com/x?a=1"})
    assert ok
    ok, _ = pe._engine_task_target_allowed(s, {"target": "https://sub.example.com/y"})
    assert ok
    ok, reason = pe._engine_task_target_allowed(s, {"target": "https://acunetix.com/scan"})
    assert not ok
    assert "acunetix.com" in reason


def test_engine_target_allowed_with_scope(monkeypatch):
    """ALLOWED_SCOPE 配置后：白名单 + 主域 + 通配子域放行，无关域拒绝。"""
    monkeypatch.setattr(settings, "allowed_scope", "example.com, *.audible.com")
    s = _FakeSelf("https://example.com/")
    assert pe._engine_task_target_allowed(s, {"target": "https://a.example.com/z"})[0]
    assert pe._engine_task_target_allowed(s, {"target": "https://x.audible.com/q"})[0]
    assert not pe._engine_task_target_allowed(s, {"target": "https://audible2.com/q"})[0]
    assert not pe._engine_task_target_allowed(s, {"target": "https://notexample.com/"})[0]


def test_engine_target_allowed_no_host_passes():
    """相对路径无 host → 放行（交由请求层拼接判定）。"""
    s = _FakeSelf("https://example.com/")
    assert pe._engine_task_target_allowed(s, {"target": "/static/app.js"})[0]


# ---------------- D1: 粘滞剔除 ----------------
def test_sticky_blacklist_after_two_failures():
    """同键任务累计 2 次失败 → 入墓碑黑名单。"""
    obj = _FakeSelf("https://example.com/")
    task = {"engine": "xss", "target": "https://example.com/x", "param": "p"}
    pe._sticky_mark_failed(obj, task)
    assert not obj._sticky_blacklist
    pe._sticky_mark_failed(obj, task)
    assert obj._sticky_blacklist == {("xss", "https://example.com/x", "p")}


def test_sticky_check_skips_blacklisted(monkeypatch):
    """墓碑命中 → _execute_engine_check 入口直接跳过。"""
    monkeypatch.setattr(settings, "sticky_fail_threshold", 2)
    s = _FakeSelf("https://example.com/")
    s._sticky_blacklist.add(("sqli", "https://example.com/x", "id"))
    res = asyncio.run(pe._execute_engine_check(s, {"engine": "sqli", "target": "https://example.com/x", "param": "id"}))
    assert res is None


# ---------------- D3: 证据运营 ----------------
def test_sigma_buckets():
    """实锤证据高优先分档 / 普通证据低分档。"""
    truth = pr._sigma_score({
        "exploited": True, "burp_verified": True, "cross_confirmed": True,
        "evidence": "resp=1", "ai_verdict": "真实漏洞", "severity": "High",
    })
    assert truth[0] >= 5
    assert "实锤" in truth[1]
    downgrade = pr._sigma_score({"pending_review": True, "severity": "High", "evidence": "x"})
    assert downgrade[0] <= 0
    assert "低" in downgrade[1]


def test_aggregate_evidence_merges_sources():
    """多源证据合并为带前缀的证据链。"""
    chain = pr._build_evidence_chain({
        "evidence": "GET /x 200",
        "nuclei_result": "template-id hit",
        "ai_verdict": "high",
    }, cap_len=4000)
    joined = "\n".join(chain)
    assert "引擎证据" in joined
    assert "Nuclei 原始输出" in joined
    assert "AI 裁决" in joined


def test_aggregate_evidence_truncates():
    """证据链总长按 cap 截断。"""
    big = "A" * 6000
    chain = pr._build_evidence_chain({"evidence": big, "nuclei_result": "b"}, cap_len=100)
    joined = "\n".join(chain)
    assert len(joined) <= 100
