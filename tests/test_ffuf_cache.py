# -*- coding: utf-8 -*-
"""P1-1 FFUF 增量缓存验收测试：SQLiteCache 行为 + 通用后端选择 + 评测防污染开关。

为什么要钉死这些行为：
  SQLiteCache 是"跨运行复用"的底座——get() 的 TTL 判定、get_raw() 的"过期仍返回"
  （供增量重试）、单例复用，任何一处出错都会让增量模式静默失效或脏读。
  另外：ffuf 缓存不看 CACHE_BACKEND，必须靠 VULNCLAW_FFUF_CACHE=0 旁路，
  否则持久缓存会污染 P/R/F1 评测（eval_prf.py 依赖此开关）。
"""
import os
import time
from pathlib import Path

import pytest

from vulnclaw.core_modules.cache import (FileCache, MemoryCache, SQLiteCache,
                                         get_cache)


@pytest.fixture()
def tmp_db(tmp_path):
    return SQLiteCache(name="test_ffuf", db_path=str(tmp_path / "ffuf.db"), ttl=86400)


class TestSQLiteCache:
    def test_set_get_roundtrip(self, tmp_db):
        tmp_db.set("k1", {"dirs": ["/a", "/b"], "not_found": ["/c"]})
        assert tmp_db.get("k1") == {"dirs": ["/a", "/b"], "not_found": ["/c"]}

    def test_get_missing_returns_default(self, tmp_db):
        assert tmp_db.get("nope") is None
        assert tmp_db.get("nope", default=[]) == []

    def test_expired_is_miss(self, tmp_db):
        tmp_db.set("k", "v", ttl=-1)  # 已过期
        assert tmp_db.get("k") is None

    def test_get_raw_returns_expired(self, tmp_db):
        """get_raw 的契约：不过滤 TTL，供增量重试读取旧记录。"""
        tmp_db.set("k", {"dirs": ["/old"]}, ttl=-1)
        assert tmp_db.get("k") is None
        assert tmp_db.get_raw("k") == {"dirs": ["/old"]}

    def test_delete(self, tmp_db):
        tmp_db.set("k", 1)
        tmp_db.delete("k")
        assert tmp_db.get("k") is None

    def test_overwrite(self, tmp_db):
        tmp_db.set("k", {"dirs": ["/a"]})
        tmp_db.set("k", {"dirs": ["/a", "/b"]})
        assert tmp_db.get("k")["dirs"] == ["/a", "/b"]

    def test_stats_counters(self, tmp_db):
        before = tmp_db.stats()
        tmp_db.set("k", 1)
        tmp_db.get("k")       # hit
        tmp_db.get("miss-x")  # miss
        after = tmp_db.stats()
        assert after["hits"] == before["hits"] + 1
        assert after["misses"] == before["misses"] + 1

    def test_singleton_same_name(self, tmp_path):
        a = SQLiteCache(name="solo", db_path=str(tmp_path / "solo.db"))
        b = SQLiteCache(name="solo", db_path=str(tmp_path / "solo.db"))
        assert a is b


class TestGetCacheBackend:
    def test_default_memory(self, monkeypatch):
        monkeypatch.setattr("vulnclaw.core.settings.settings.cache_backend", "memory")
        assert isinstance(get_cache(), MemoryCache)

    def test_file_backend(self, monkeypatch, tmp_path):
        monkeypatch.setattr("vulnclaw.core.settings.settings.cache_backend", "file")
        c = get_cache()
        assert isinstance(c, FileCache)
        assert isinstance(c.cache_dir, Path)

    def test_sqlite_backend(self, monkeypatch, tmp_path):
        monkeypatch.setattr("vulnclaw.core.settings.settings.cache_backend", "sqlite")
        assert isinstance(get_cache(), SQLiteCache)

    def test_redis_fallback_never_raises(self, monkeypatch):
        """redis 后端不可用（包缺失/服务未起）必须回退 memory，绝不能抛。"""
        monkeypatch.setattr("vulnclaw.core.settings.settings.cache_backend", "redis")
        c = get_cache()  # 不断言具体类型：装了 redis 且服务在跑则 RedisCache，否则 MemoryCache
        assert c is not None
        c.set("probe", {"ok": True}, ttl=5)
        assert isinstance(c.get("probe"), (dict, type(None)))


class TestEvalIsolation:
    def test_eval_prf_forces_ffuf_cache_off(self):
        """评测脚本必须旁路 ffuf 持久缓存，否则 P/R/F1 会被上一轮缓存冒充。"""
        import logging
        import sys

        _SCRIPTS = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
        )
        if _SCRIPTS not in sys.path:
            sys.path.insert(0, _SCRIPTS)
        import eval_prf  # noqa: F402  导入即触发 setdefault
        logging.disable(logging.NOTSET)  # 撤销 eval_prf 的全局日志抑制副作用
        assert os.environ.get("VULNCLAW_FFUF_CACHE") == "0"
