# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core_modules/cache.py（R3 迁移自 core/cache.py）
import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Optional

from vulnclaw.config.settings import PROJECT_CACHE_DIR
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings


class CacheBackend:
    def get(self, key: str) -> Optional[Any]:
        raise NotImplementedError

    def set(self, key: str, value: Any, ttl: int = 7200):
        raise NotImplementedError

    def delete(self, key: str):
        raise NotImplementedError


class MemoryCache(CacheBackend):
    def __init__(self):
        self._data = {}
        self._expire = {}

    def get(self, key: str) -> Optional[Any]:
        if key in self._expire and self._expire[key] < time.time():
            del self._data[key]
            del self._expire[key]
            return None
        return self._data.get(key)

    def set(self, key: str, value: Any, ttl: int = 7200):
        self._data[key] = value
        self._expire[key] = time.time() + ttl

    def delete(self, key: str):
        if key in self._data:
            del self._data[key]
        if key in self._expire:
            del self._expire[key]


class FileCache(CacheBackend):
    def __init__(self, cache_dir=None):
        if cache_dir is None:
            cache_dir = str(Path(PROJECT_CACHE_DIR) / 'cache')
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def _get_path(self, key: str) -> Path:
        import hashlib
        return self.cache_dir / hashlib.md5(key.encode()).hexdigest()

    def get(self, key: str) -> Optional[Any]:
        path = self._get_path(key)
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                if data.get("expire", 0) > time.time():
                    return data.get("value")
            except BaseException:
                logger.debug("suppressed exception (core audit)")
        return None

    def set(self, key: str, value: Any, ttl: int = 7200):
        path = self._get_path(key)
        data = {"value": value, "expire": time.time() + ttl}
        path.write_text(json.dumps(data), encoding="utf-8")

    def delete(self, key: str):
        path = self._get_path(key)
        if path.exists():
            path.unlink()


class SQLiteCache(CacheBackend):
    """SQLite 持久化缓存（P1-1：标准库 sqlite3，WAL 模式，线程安全）。

    - Key 形如 `ffuf:{target_hash}:{wordlist_mtime}`；
    - value 为 JSON 序列化任意对象；ttl 默认 24h（86400s）；
    - `get_raw()` 不判断 TTL 返回旧值，供"缓存 miss 时增量重试"读取过期记录；
    - `stats()` 提供命中率可观测（命中/未命中/命中率）。
    """
    _class_lock = threading.Lock()
    _instances: Dict[str, "SQLiteCache"] = {}

    def __new__(cls, name="default", db_path=None, ttl=86400):
        with cls._class_lock:
            if name not in cls._instances:
                inst = super().__new__(cls)
                inst.__init__(name, db_path, ttl)
                cls._instances[name] = inst
            return cls._instances[name]

    def __init__(self, name="default", db_path=None, ttl=86400):
        if getattr(self, "_path", None):
            return  # 单例已初始化
        if db_path is None:
            db_path = str(Path(PROJECT_CACHE_DIR) / "cache" / f"{name}.db")
        self._path = db_path
        self._ttl = ttl
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS kv ("
            " key TEXT PRIMARY KEY, value TEXT, expire REAL, created REAL)"
        )
        self._conn.commit()

    def get(self, key: str, default: Any = None) -> Any:
        now = time.time()
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT value, expire FROM kv WHERE key=?", (key,)
                ).fetchone()
            if row is None:
                self._misses += 1
                return default
            value, expire = row
            if expire < now:
                with self._lock:
                    self._conn.execute("DELETE FROM kv WHERE key=?", (key,))
                    self._conn.commit()
                self._misses += 1
                return default
            self._hits += 1
            return json.loads(value)
        except BaseException as e:
            logger.warning(f"[Cache] SQLite get 失败: {e}")
            return default

    def get_raw(self, key: str) -> Optional[Any]:
        """不判断 TTL 返回旧值（供增量重试读取过期记录）。"""
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT value FROM kv WHERE key=?", (key,)
                ).fetchone()
            return json.loads(row[0]) if row else None
        except BaseException:
            return None

    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        try:
            data = json.dumps(value, ensure_ascii=False)
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO kv (key, value, expire, created) VALUES (?,?,?,?)",
                    (key, data, time.time() + (ttl or self._ttl), time.time()),
                )
                self._conn.commit()
        except BaseException as e:
            logger.warning(f"[Cache] SQLite set 失败: {e}")

    def delete(self, key: str):
        try:
            with self._lock:
                self._conn.execute("DELETE FROM kv WHERE key=?", (key,))
                self._conn.commit()
        except BaseException:
            logger.debug("suppressed exception (core audit)")

    def stats(self) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": round(self._hits / total, 4) if total else 0.0,
        }

    def close(self):
        try:
            self._conn.close()
        except BaseException:
            logger.debug("suppressed exception (core audit)")


def get_cache():
    backend = getattr(settings, 'cache_backend', 'memory')
    if backend == "file":
        return FileCache()
    else:
        return MemoryCache()


cache = get_cache()


# ===== P3-2: 注册到 DI 容器（供测试注入 mock）=====
try:
    from vulnclaw.core.container import get_container
    get_container().register("cache", cache)
except Exception:  # noqa: BLE001
    logger.debug("suppressed exception (core audit)")


__all__ = ['CacheBackend', 'MemoryCache', 'FileCache', 'SQLiteCache', 'get_cache', 'cache']
