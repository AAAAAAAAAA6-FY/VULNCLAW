# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/bandit.py
"""
SP16.1 上下文多臂老虎机（轻量在线 RL 决策层）

痛点对照：smart_queue 的 priority 由任务创建时静态写入（engine_priority 表），
没有"这个 (目标, 参数, 引擎) 组合到底出不出货"的跨扫描记忆——每轮都从头
推理，缺少前沿 RL 决策层的"肌肉记忆"。

本模块用最轻量的 Thompson 采样（stdlib random.betavariate，零新依赖）：
- 组合键：target|param|engine 三元组（任意缺失位降级为空串）
- 回报：hit（该组合产出 finding，由 orchestrator._add_finding 回注）/
        fail（该组合任务执行失败，由 SmartTaskQueue.complete_task(success=False) 回注）
- 决策：p ~ Beta(hits+1, fails+1)，offset = round((p-0.5)*2*influence)，
        加到基础 priority 上并 clamp 到 1..10
- 无样本组合返回基础值原样（默认关 / 无数据时零行为回归）
- 可选 JSONL 反馈飞轮：feedback 逐条落盘，作为未来正式 RL 策略网络的训练数据

纪律：无 emoji、轻量、异常优雅降级（B heap 规则同源）。
"""
import json
import random
import threading
import time
from pathlib import Path

from vulnclaw.core.logger import logger


def bandit_key(target: str = "", param: str = "", engine: str = "") -> str:
    """组合键：target|param|engine，缺失位降级为空串。"""
    return "|".join([str(target or ""), str(param or ""), str(engine or "")])


def key_from_task(task_data: dict) -> str:
    """从任务 data 提取组合键（engine_bundle 取 engines 首项 / 单引擎取 engine 字段）。"""
    if not isinstance(task_data, dict):
        return ""
    target = task_data.get("target") or task_data.get("url") or ""
    param = task_data.get("param") or ""
    engines = task_data.get("engines")
    engine = engines[0] if isinstance(engines, list) and engines else (task_data.get("engine") or "")
    return bandit_key(target=target, param=param, engine=engine)


def key_from_finding(finding: dict) -> str:
    """从 finding 提取组合键（finding 里参数字段名是 parameter）。"""
    if not isinstance(finding, dict):
        return ""
    target = finding.get("url") or ""
    param = finding.get("parameter") or finding.get("param") or ""
    engine = finding.get("engine") or finding.get("source") or ""
    return bandit_key(target=target, param=param, engine=engine)


class ContextualBandit:
    """上下文多臂老虎机：按组合命中史调整任务优先级（线程安全）。"""

    def __init__(self, influence: int = 2, feed_dir: str = "", enabled: bool = True):
        self._influence = max(1, int(influence))
        self._feed_dir = str(feed_dir or "")
        self.enabled = enabled
        self._stats: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    # ---------- 查询 ----------
    def has_sample(self, key: str) -> bool:
        """该组合是否已有样本（有样本才参与决策，无样本返回 base 原值）。"""
        if not self.enabled or not key:
            return False
        with self._lock:
            return key in self._stats

    def adjust(self, base: int, key: str) -> int:
        """Thompson 采样决策：返回调整后的优先级（clamp 1..10）。"""
        if not self.enabled or not key or not self.has_sample(key):
            return int(base)
        with self._lock:
            st = self._stats[key]
            hits, fails = int(st.get("hits", 0)), int(st.get("fails", 0))
        p = random.betavariate(hits + 1, fails + 1)
        offset = round((p - 0.5) * 2.0 * self._influence)
        return max(1, min(10, int(base) + offset))

    # ---------- 回注 ----------
    def record(self, key: str, hit: bool) -> None:
        """记录一次样本（hit=True 出漏洞 / hit=False 执行失败）。"""
        if not self.enabled or not key:
            return
        field = "hits" if hit else "fails"
        with self._lock:
            st = self._stats.setdefault(key, {"hits": 0, "fails": 0})
            st[field] = int(st.get(field, 0)) + 1
        self._write_feed(key, hit)

    def _write_feed(self, key: str, hit: bool) -> None:
        """反馈飞轮：JSONL 逐条追加（可选；写失败仅 debug，不阻塞）。"""
        if not self._feed_dir:
            return
        try:
            path = Path(self._feed_dir) / "bandit_feedback.jsonl"
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "ts": round(time.time(), 3),
                    "key": key,
                    "hit": bool(hit),
                    **self._stats.get(key, {"hits": 0, "fails": 0}),
                }, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001
            logger.debug("[SP16.1] bandit 反馈落盘失败，跳过", exc_info=True)

    # ---------- 诊断 ----------
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self, top: int = 20) -> dict:
        """按 hits 排序的诊断快照（便于排查高产出/高沉默组合）。"""
        with self._lock:
            rows = []
            for k, st in self._stats.items():
                n = int(st.get("hits", 0)) + int(st.get("fails", 0))
                if n:
                    rows.append({
                        "key": k,
                        "hits": int(st.get("hits", 0)),
                        "fails": int(st.get("fails", 0)),
                        "hit_rate": round(int(st.get("hits", 0)) / max(1, n), 3),
                    })
        rows.sort(key=lambda r: r["hits"], reverse=True)
        return {"total_combos": len(rows), "top": rows[:max(1, int(top))]}


__all__ = ["ContextualBandit", "bandit_key", "key_from_finding", "key_from_task"]