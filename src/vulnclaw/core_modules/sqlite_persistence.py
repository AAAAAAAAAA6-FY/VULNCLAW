# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""P5-1: SQLite 持久化与断点续扫（A4.6 落地）。

替代原 JSON 版 ScanState，提供事务级可靠的扫描断点续扫：
- 阶段检查点（stage 级断点：recon / taskgen / scan / ... / report）
- 已扫 (engine, target, param) 三元组（细粒度续扫，复用 E1 增量集语义）
- 增量 findings（kill -9 不丢，恢复后自动并入报告）
- agent 记忆 / shared_knowledge（A4.6 明确要求「含 agent 记忆」）

DB 落点按 target 确定性：PROJECT_CACHE_DIR/persistence/<safe_target>.db
使用 WAL 日志 + 单连接 + threading.RLock，保证多线程/协程下写入安全。
"""
import json
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import PROJECT_CACHE_DIR

CHECKPOINT_VERSION = 1
CHECKPOINT_EXPIRE_DAYS = 7

_KEY_SEP = "\x00"  # 三元组分隔符（参数值可能含逗号/空格，用不可见分隔）


def safe_target_key(target: str) -> str:
    """把任意 target 规整为文件系统安全、可逆性足够的 key。"""
    return re.sub(r'[^a-zA-Z0-9._-]', '_', target or 'unknown')[:200]


def db_path_for_target(target: str, base_dir: Optional[str] = None) -> Path:
    base = Path(base_dir) if base_dir else (Path(PROJECT_CACHE_DIR) / "persistence")
    base.mkdir(parents=True, exist_ok=True)
    return base / f"{safe_target_key(target)}.db"


class SqliteCheckpointStore:
    """扫描检查点 SQLite 存储（同步、线程安全）。

    由 orchestrator 在事件循环内调用；写操作均为小事务，直接同步执行，
    不阻塞事件循环过久（WAL + NORMAL 同步策略）。
    """

    def __init__(self, db_path: str, scan_id: str = "", target: str = ""):
        self.db_path = str(db_path)
        self._scan_id = scan_id
        self._target = target
        self._lock = threading.RLock()
        self._conn: Optional[sqlite3.Connection] = None
        self._ensure_schema()

    # ============================================================
    # 连接 / Schema
    # ============================================================
    def _connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(self.db_path, timeout=30, check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS meta (
                    key    TEXT PRIMARY KEY,
                    value  TEXT
                );
                CREATE TABLE IF NOT EXISTS stage (
                    stage_index INTEGER PRIMARY KEY,
                    name        TEXT NOT NULL,
                    status      TEXT NOT NULL,
                    started_at  REAL,
                    finished_at REAL,
                    payload     TEXT
                );
                CREATE TABLE IF NOT EXISTS task_done (
                    key     TEXT PRIMARY KEY,
                    engine  TEXT,
                    target  TEXT,
                    param   TEXT
                );
                CREATE TABLE IF NOT EXISTS finding (
                    fid  TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    ts   REAL
                );
                CREATE TABLE IF NOT EXISTS agent_memory (
                    key  TEXT PRIMARY KEY,
                    data TEXT NOT NULL
                );
                """
            )
            conn.commit()

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                try:
                    self._conn.commit()
                    self._conn.close()
                except Exception:  # noqa: BLE001
                    pass
                self._conn = None

    def _touch_locked(self) -> None:
        """在持锁的写事务内刷新 updated_at 时间戳（过期判定用）。"""
        self._connect().execute(
            "INSERT INTO meta(key,value) VALUES('updated_at',?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(time.time()),),
        )

    # ============================================================
    # meta（键值）
    # ============================================================
    def set_meta(self, key: str, value: Any) -> None:
        with self._lock:
            self._connect().execute(
                "INSERT INTO meta(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, json.dumps(value, default=str)),
            )
            self._conn.commit()

    def get_meta(self, key: str, default: Any = None) -> Any:
        with self._lock:
            row = self._connect().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if row is None:
                return default
            try:
                return json.loads(row["value"])
            except Exception:  # noqa: BLE001
                return default

    # ============================================================
    # 阶段检查点（stage 级断点）
    # ============================================================
    def save_stage_start(self, index: int, name: str) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO stage(stage_index,name,status,started_at) VALUES(?,?,?,?) "
                "ON CONFLICT(stage_index) DO UPDATE SET "
                "name=excluded.name, status='running', started_at=excluded.started_at",
                (index, name, "running", time.time()),
            )
            self._touch_locked()
            conn.commit()

    def save_stage_done(self, index: int, name: str, payload: Optional[Dict] = None) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT INTO stage(stage_index,name,status,finished_at,payload) VALUES(?,?,?,?,?) "
                "ON CONFLICT(stage_index) DO UPDATE SET "
                "name=excluded.name, status='done', finished_at=excluded.finished_at, "
                "payload=excluded.payload",
                (index, name, "done", time.time(), json.dumps(payload or {}, default=str)),
            )
            self._touch_locked()
            conn.commit()

    def get_completed_stage_index(self) -> int:
        """已完成的最后阶段下标；无则 -1。"""
        with self._lock:
            row = self._connect().execute(
                "SELECT MAX(stage_index) AS m FROM stage WHERE status='done'"
            ).fetchone()
            return int(row["m"]) if row and row["m"] is not None else -1

    def list_stages(self) -> List[Dict]:
        with self._lock:
            rows = self._connect().execute(
                "SELECT stage_index,name,status,started_at,finished_at,payload FROM stage ORDER BY stage_index"
            ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                raw = d.get("payload")
                try:
                    d["payload"] = json.loads(raw) if raw else {}
                except Exception:  # noqa: BLE001
                    d["payload"] = {}
                out.append(d)
            return out

    # ============================================================
    # task_done（E1 增量集的 SQLite 版，细粒度续扫）
    # ============================================================
    def mark_task_done(self, engine: str, target: str, param: str) -> None:
        key = f"{engine}{_KEY_SEP}{target}{_KEY_SEP}{param}"
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR IGNORE INTO task_done(key,engine,target,param) VALUES(?,?,?,?)",
                (key, engine, target, param),
            )
            self._touch_locked()
            conn.commit()

    def is_task_done(self, engine: str, target: str, param: str) -> bool:
        key = f"{engine}{_KEY_SEP}{target}{_KEY_SEP}{param}"
        with self._lock:
            row = self._connect().execute("SELECT 1 FROM task_done WHERE key=?", (key,)).fetchone()
            return row is not None

    def load_done_tasks(self) -> Set[Tuple[str, str, str]]:
        with self._lock:
            rows = self._connect().execute(
                "SELECT engine,target,param FROM task_done"
            ).fetchall()
            return {(r["engine"], r["target"], r["param"]) for r in rows}

    # ============================================================
    # findings（增量发现，kill -9 不丢）
    # ============================================================
    @staticmethod
    def _finding_id(finding: Dict) -> str:
        return (
            str(finding.get("url", "")) + _KEY_SEP
            + str(finding.get("parameter", "")) + _KEY_SEP
            + str(finding.get("type", "")) + _KEY_SEP
            + str(finding.get("method", "")) + _KEY_SEP
            + str(finding.get("evidence", ""))[:80]
        )

    def add_finding(self, finding: Dict) -> None:
        fid = self._finding_id(finding)
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO finding(fid,data,ts) VALUES(?,?,?)",
                (fid, json.dumps(finding, default=str, ensure_ascii=False), time.time()),
            )
            self._touch_locked()
            conn.commit()

    def load_findings(self) -> List[Dict]:
        with self._lock:
            rows = self._connect().execute("SELECT data FROM finding ORDER BY ts").fetchall()
            out: List[Dict] = []
            for r in rows:
                try:
                    out.append(json.loads(r["data"]))
                except Exception:  # noqa: BLE001
                    pass
            return out

    # ============================================================
    # agent 记忆 / shared_knowledge（A4.6：含 agent 记忆）
    # ============================================================
    def save_agent_memory(self, key: str, data: Any) -> None:
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO agent_memory(key,data) VALUES(?,?)",
                (key, json.dumps(data, default=str, ensure_ascii=False)),
            )
            self._touch_locked()
            conn.commit()

    def load_agent_memory(self, key: str) -> Any:
        with self._lock:
            row = self._connect().execute(
                "SELECT data FROM agent_memory WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                return None
            try:
                return json.loads(row["data"])
            except Exception:  # noqa: BLE001
                return None

    # ============================================================
    # 生命周期
    # ============================================================
    def init_scan(self, scan_id: str, target: str) -> None:
        self.set_meta("version", CHECKPOINT_VERSION)
        self.set_meta("scan_id", scan_id)
        self.set_meta("target", target)
        self.set_meta("started_at", time.time())
        self.set_meta("finished", False)

    def mark_finished(self) -> None:
        self.set_meta("finished", True)
        self.set_meta("finished_at", time.time())

    def is_finished(self) -> bool:
        return bool(self.get_meta("finished", False))

    def reset(self) -> None:
        """清空所有表，开始一次全新扫描（覆盖上一次残留断点）。"""
        with self._lock:
            conn = self._connect()
            for t in ("meta", "stage", "task_done", "finding", "agent_memory"):
                conn.execute(f"DELETE FROM {t}")
            conn.commit()

    def resume_info(self) -> Dict:
        """断点恢复决策信息。

        判定逻辑：
        - version 不匹配 → 不恢复（schema 演进）
        - 已完成阶段 < 0 或无 → 不恢复（全新）
        - 已 finished → 不恢复（上次已正常结束）
        - 超过过期天数未更新 → 不恢复（避免恢复极老的断点）
        """
        version = self.get_meta("version", None)
        if version != CHECKPOINT_VERSION:
            return {"should_resume": False, "reason": "version_mismatch"}
        finished = self.is_finished()
        stage_index = self.get_completed_stage_index()
        updated = self.get_meta("updated_at", self.get_meta("started_at", 0)) or 0
        expired = (time.time() - float(updated)) > CHECKPOINT_EXPIRE_DAYS * 86400
        should = (not finished) and (stage_index >= 0) and (not expired)
        return {
            "should_resume": should,
            "finished": finished,
            "stage_index": stage_index,
            "expired": expired,
            "target": self.get_meta("target", ""),
            "reason": "" if should else ("finished" if finished else ("expired" if expired else "no_checkpoint")),
        }


__all__ = [
    "SqliteCheckpointStore",
    "db_path_for_target",
    "safe_target_key",
    "CHECKPOINT_VERSION",
    "CHECKPOINT_EXPIRE_DAYS",
]
