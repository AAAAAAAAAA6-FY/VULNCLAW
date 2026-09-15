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
- SP17.1 可选策略加载：ContextualBandit.from_policy / load_policy 加载
  bandit_policy.json，adjust() 在命中的策略组合上按 action（boost/penalty/hold）
  调整，无策略记录时回退 Thompson 采样（未加载策略时行为与纯 Thompson 完全一致）。

纪律：无 emoji、轻量、异常优雅降级（B heap 规则同源）。
"""
import json
import os
import random
import threading
import time
from pathlib import Path

from vulnclaw.core.logger import logger


def bandit_key(target: str = "", param: str = "", engine: str = "") -> str:
    """组合键：target|param|engine，缺失位降级为空串。"""
    return "|".join([str(target or ""), str(param or ""), str(engine or "")])


def bandit_key_v2(tech: str = "", param: str = "", engine: str = "", family: str = "") -> str:
    """P3-⑤ 跨目标可迁移组合键：v2|tech|param|engine|payload_family。

    为什么需要 v2：v1 键含 target → 每个新目标都是冷启动，学到的经验
    **永不迁移**（跨扫描记忆实质是断的）。v2 去掉 target、换成技术栈与
    payload 族，让"PHP 站点的 sqli 参数用什么 payload 出货"这类知识可复用。
    v1 键与既有统计/策略文件完全不动，二者由调用方按 v2 开关选择。
    """
    return "|".join([
        "v2", str(tech or ""), str(param or ""), str(engine or ""), str(family or ""),
    ])


def key_from_task(task_data: dict, v2: bool = False) -> str:
    """从任务 data 提取组合键（engine_bundle 取 engines 首项 / 单引擎取 engine 字段）。

    v2=True 时用可迁移键（tech_stack + payload_family 代替 target）；
    缺省 False 保持 v1 行为（零回归）。
    """
    if not isinstance(task_data, dict):
        return ""
    param = task_data.get("param") or ""
    engines = task_data.get("engines")
    engine = engines[0] if isinstance(engines, list) and engines else (task_data.get("engine") or "")
    if v2:
        tech = task_data.get("tech") or task_data.get("tech_stack") or ""
        if isinstance(tech, (list, tuple)):
            tech = tech[0] if tech else ""
        return bandit_key_v2(tech=str(tech or ""), param=param, engine=engine,
                             family=str(task_data.get("payload_family") or ""))
    target = task_data.get("target") or task_data.get("url") or ""
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

    def __init__(self, influence: int = 2, feed_dir: str = "", enabled: bool = True,
                 state_path: str = ""):
        self._influence = max(1, int(influence))
        self._feed_dir = str(feed_dir or "")
        self.enabled = enabled
        self._state_path = str(state_path or "")
        self._stats: dict[str, dict[str, int]] = {}
        self._policy_combos: dict[str, str] = {}  # key -> boost|penalty|hold
        self._policy_influence: int = self._influence
        self._lock = threading.Lock()
        if self._state_path:
            self.load_state()

    # ---------- 策略加载（SP17.1 可选） ----------
    @classmethod
    def from_policy(cls, policy_path: str, influence: int = 2, feed_dir: str = "", enabled: bool = True):
        """从策略文件构造（SP17.1）：加载轻量训练策略，命中组合按 action 调整。"""
        bandit = cls(influence=influence, feed_dir=feed_dir, enabled=enabled)
        bandit.load_policy(policy_path)
        return bandit

    def load_policy(self, policy_path: str) -> bool:
        """加载策略文件（bandit_policy.json）。失败优雅降级为纯 Thompson（返回 False）。"""
        try:
            data = json.loads(Path(policy_path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            logger.debug("[SP17.1] bandit 策略加载失败，保持默认 Thompson", exc_info=True)
            return False
        combos = data.get("combos") or {}
        with self._lock:
            self._policy_combos = {
                str(k): str((v or {}).get("action") or "hold")
                for k, v in combos.items() if isinstance(v, dict)
            }
            inf = data.get("calibrated_influence")
            self._policy_influence = max(1, int(inf)) if isinstance(inf, (int, float)) else self._influence
        return True

    # ---------- 查询 ----------
    def has_sample(self, key: str) -> bool:
        """该组合是否已有样本（有样本才参与决策，无样本返回 base 原值）。"""
        if not self.enabled or not key:
            return False
        with self._lock:
            return key in self._stats

    def adjust(self, base: int, key: str) -> int:
        """决策：有策略记录按策略 action 调整，否则回退 Thompson 采样（clamp 1..10）。"""
        if not self.enabled or not key:
            return int(base)
        # 策略优先：命中组合按 action 调整
        if self._policy_combos:
            with self._lock:
                action = self._policy_combos.get(key)
            if action is not None:
                if action == "boost":
                    return max(1, min(10, int(base) + self._policy_influence))
                if action == "penalty":
                    return max(1, min(10, int(base) - self._policy_influence))
                return int(base)  # hold：不调整
        # 回退：Thompson 采样
        if not self.has_sample(key):
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
        if self._state_path:
            self.save_state()

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

    # ---------- 状态持久化（P3-⑤） ----------
    def load_state(self) -> bool:
        """加载跨扫描状态（bandit 统计落盘文件）。失败返回 False（等同冷启动）。"""
        if not self._state_path:
            return False
        try:
            data = json.loads(Path(self._state_path).read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            logger.debug("[P3-⑤] bandit 状态加载失败，按冷启动处理")
            return False
        stats = data.get("stats") or {}
        with self._lock:
            for k, v in stats.items():
                if isinstance(v, dict):
                    self._stats[str(k)] = {
                        "hits": int(v.get("hits", 0)),
                        "fails": int(v.get("fails", 0)),
                    }
        return True

    def save_state(self) -> bool:
        """原子写状态（tmp + os.replace，避免半截文件）。"""
        if not self._state_path:
            return False
        try:
            p = Path(self._state_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(json.dumps({
                "ts": round(time.time(), 3),
                "stats": self.stats(),
            }, ensure_ascii=False), encoding="utf-8")
            os.replace(str(tmp), str(p))
            return True
        except Exception:  # noqa: BLE001
            logger.debug("[P3-⑤] bandit 状态落盘失败，跳过", exc_info=True)
            return False

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