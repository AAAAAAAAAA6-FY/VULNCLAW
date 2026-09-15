# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 4 模块 2：Redis 后端上下文。

替代内存版 DAGContext，支持多节点共享状态。
接口与 DAGContext 完全兼容：set / get / update / get_and_clear / get_all / clear / has。

序列化策略：
- str/int/float/bool: 直接存储
- dict/list: JSON 序列化
- 其他类型: pickle 序列化（base64 编码）

Key 命名：{prefix}:ctx:{key}
"""
import asyncio
import base64
import hashlib
import json
import os
import pickle
import time
from typing import Any, Dict

from vulnclaw.core.logger import logger

# SCAN 每批键数（同时作为 MGET 批次大小，控制单次往返与内存）
_SCAN_BATCH = 500

# WAL 单文件上限（P0-8 补）：降级期写入无限累积会撑爆磁盘 —— 超限后
# 停止记录（宁可丢尾部写入，也不让磁盘写满拖垮整个节点）。
_WAL_MAX_BYTES = 8 * 1024 * 1024


def _fail_stop_default() -> bool:
    """P0-8：Redis 断连是否 fail-stop（默认关，保持单机/无 Redis 可用性）。

    生产多 worker 场景设 REDIS_FAIL_STOP=true：断连即抛错，绝不用节点本地
    内存冒充分布式一致状态。
    """
    try:
        from vulnclaw.config.settings import settings
        return bool(getattr(settings, "redis_fail_stop", False))
    except Exception:  # noqa: BLE001
        return False


_FAIL_STOP = _fail_stop_default()


class RedisContext:
    """Redis 后端共享上下文（与 DAGContext 接口完全兼容）。

    所有方法均为 async，与 DAGContext 签名一致。
    当 Redis 不可用时，自动降级到内存模式。
    """

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379/0",
        prefix: str = "vulnclaw",
    ):
        """初始化 Redis 上下文。

        Args:
            redis_url: Redis 连接 URL。
            prefix: Key 前缀（用于多目标隔离）。
        """
        self._redis_url = redis_url
        self._prefix = f"{prefix}:ctx"
        self._redis = None
        self._fallback_data: Dict[str, Any] = {}  # Redis 不可用时降级
        self._fallback_mode = False
        self._degraded_reason = ""   # P0-8：降级原因（可观测，不静默）
        # P0-8：true = Redis 不可用时 fail-stop（抛错），禁止本地内存冒充分布式状态
        self._fail_stop = bool(_FAIL_STOP)
        self._lock = asyncio.Lock()
        # P0-8 补：降级期 WAL（写入落盘，Redis 恢复后回放）
        self._wal_enabled = False
        self._wal_path = ""
        self._wal_overflow = False  # WAL 超限后停止记录的标志（可观测）

        self._wal_init()
        logger.info(f"📦 [RedisContext] 初始化: url={redis_url} prefix={prefix}")

    async def _connect(self):
        """延迟连接 Redis。"""
        if self._redis is not None:
            return self._redis

        try:
            import redis.asyncio as aioredis
            self._redis = aioredis.from_url(
                self._redis_url,
                decode_responses=False,
                socket_timeout=5,
                socket_connect_timeout=3,
            )
            # 测试连接
            await self._redis.ping()
            logger.info("✅ [RedisContext] Redis 连接成功")
            # P0-8 补：Redis 可用即尝试回放 WAL。覆盖两种场景：
            # ①本实例从降级态恢复 ②进程重启后上次降级残留的 WAL。
            # 仅在 WAL 文件存在时才读盘，正常路径零开销。
            was_degraded = self._fallback_mode
            self._fallback_mode = False
            self._degraded_reason = ""
            if self._wal_path and os.path.exists(self._wal_path):
                try:
                    n = await self.replay_wal()
                    if n:
                        origin = "Redis 已从降级恢复" if was_degraded else "重启残留"
                        logger.info(f"🔄 [RedisContext] WAL 回放 {n} 条（{origin}）")
                except Exception as exc:  # noqa: BLE001
                    logger.warning(f"⚠️ [RedisContext] WAL 回放失败: {exc}")
        except Exception as exc:
            self._fallback_mode = True
            self._redis = None
            self._degraded_reason = f"connect: {type(exc).__name__}: {exc}"
            # P0-8：降级不再是"静默成功"。fail-stop 模式下直接抛错，
            # 禁止把"节点本地内存"当作分布式一致状态（两 worker 会看到不同上下文）。
            if self._fail_stop:
                logger.error(
                    f"🚨 [RedisContext] Redis 不可用且 fail_stop=true → 拒绝降级: {exc}")
                raise RuntimeError(
                    f"Redis 不可用且已开启 fail-stop（redis_fail_stop），拒绝内存降级: {exc}")
            logger.warning(
                f"⚠️ [RedisContext] Redis 不可用，降级到内存模式（**状态仅本节点可见**，"
                f"Redis 恢复后本地写入不会回放）: {exc}")

        return self._redis

    def degraded(self) -> bool:
        """P0-8：是否处于降级模式（调用方可据此标注"结果可能不一致"）。"""
        return bool(self._fallback_mode)

    def degraded_info(self) -> Dict[str, Any]:
        """降级原因与本地键数（用于报告/指标，不让降级伪装成成功）。"""
        return {
            "degraded": bool(self._fallback_mode),
            "reason": self._degraded_reason,
            "local_keys": len(self._fallback_data),
            "fail_stop": bool(self._fail_stop),
        }

    def _make_key(self, key: str) -> str:
        """构建 Redis Key。"""
        return f"{self._prefix}:{key}"

    def _serialize(self, value: Any) -> bytes:
        """序列化值。

        策略：
        - str → 直接编码
        - int/float/bool → JSON
        - dict/list → JSON
        - 其他 → pickle + base64
        """
        if isinstance(value, str):
            return f"s:{value}".encode("utf-8")
        elif isinstance(value, (int, float, bool)):
            return f"j:{json.dumps(value)}".encode("utf-8")
        elif isinstance(value, (dict, list)):
            return f"j:{json.dumps(value, ensure_ascii=False)}".encode("utf-8")
        else:
            try:
                # JSON 优先：绝大多数上下文值可 JSON 化，避免产生 pickle
                return f"j:{json.dumps(value, ensure_ascii=False)}".encode("utf-8")
            except Exception:  # noqa: BLE001 - 不可 JSON 化的类型才走 pickle
                pass
            pickled = pickle.dumps(value)
            b64 = base64.b64encode(pickled)
            return b"p:" + b64

    def _deserialize(self, data: bytes) -> Any:
        """反序列化值。"""
        if data is None:
            return None

        if isinstance(data, str):
            data = data.encode("utf-8")

        prefix = data[:2]
        payload = data[2:]

        if prefix == b"s:":
            return payload.decode("utf-8")
        elif prefix == b"j:":
            return json.loads(payload.decode("utf-8"))
        elif prefix == b"p:":
            from vulnclaw.core.safe_pickle import safe_pickle_loads
            return safe_pickle_loads(base64.b64decode(payload))
        else:
            # 兼容无前缀的旧数据
            try:
                return json.loads(data.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return data.decode("utf-8", errors="replace")

    # --- P0-8 补：降级期 WAL（写入落盘 + 恢复后回放） ---

    def _wal_init(self) -> None:
        """初始化 WAL 开关与路径。

        默认路径 `_runtime_cache/redis_ctx_wal_{prefix哈希前8位}.jsonl`，
        按 prefix 隔离，避免多目标/多租户共用一个 WAL 互相污染。
        """
        try:
            from vulnclaw.config.settings import settings
            self._wal_enabled = bool(getattr(settings, "redis_wal_enabled", True))
            configured = str(getattr(settings, "redis_wal_path", "") or "").strip()
        except Exception:  # noqa: BLE001 - settings 不可用时保守开启
            self._wal_enabled = True
            configured = ""

        if not self._wal_enabled:
            return

        if configured:
            self._wal_path = configured
        else:
            digest = hashlib.md5(self._prefix.encode("utf-8")).hexdigest()[:8]
            self._wal_path = os.path.join(
                "_runtime_cache", f"redis_ctx_wal_{digest}.jsonl")

    def _wal_append(self, op: str, key: str, value: Any = None) -> None:
        """追加一条 WAL 记录（append-only）。

        失败静默：WAL 只是"尽力而为"的补偿手段，绝不能反过来拖垮主流程。
        """
        if not self._wal_enabled or not self._wal_path or self._wal_overflow:
            return
        try:
            parent = os.path.dirname(self._wal_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
            try:
                if os.path.getsize(self._wal_path) > _WAL_MAX_BYTES:
                    self._wal_overflow = True
                    logger.warning(
                        f"⚠️ [RedisContext] WAL 超过 {_WAL_MAX_BYTES} 字节上限，"
                        f"停止记录（降级期后续写入将不可回放）")
                    return
            except OSError:
                pass

            payload = None
            if value is not None:
                # 统一走 _serialize → base64，保证任意类型都能进 JSON
                payload = base64.b64encode(self._serialize(value)).decode("ascii")
            rec = {"op": op, "key": key, "value": payload, "ts": time.time()}
            with open(self._wal_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        except Exception as exc:  # noqa: BLE001 - WAL 失败不得影响业务
            logger.debug(f"[RedisContext] WAL 写入失败（忽略）: {exc}")

    def _fallback_write(self, key: str, value: Any) -> None:
        """降级写入统一入口：本地内存 + WAL（保证恢复后可回放）。"""
        self._fallback_data[key] = value
        self._wal_append("set", key, value)

    def _fallback_delete(self, key: str) -> Any:
        """降级删除统一入口：本地内存 + WAL。"""
        val = self._fallback_data.pop(key, None)
        self._wal_append("delete", key)
        return val

    async def replay_wal(self) -> int:
        """把降级期累积的 WAL 回放到 Redis。

        覆盖两种场景：
        1. Redis 中途恢复（本实例从降级态转回正常）
        2. 进程重启后残留 WAL（上次降级期写入尚未回放）

        保序重放；**全部成功后才清空 WAL**；中途失败则保留 WAL，
        已回放部分靠"后写覆盖前写"的幂等性保证不产生脏数据，下次继续。

        Returns:
            回放成功的记录数（0 = 无 WAL / 已空 / Redis 仍不可用）。
        """
        if not self._wal_path or not os.path.exists(self._wal_path):
            return 0
        if self._redis is None or self._fallback_mode:
            return 0

        try:
            with open(self._wal_path, "r", encoding="utf-8") as fh:
                lines = fh.readlines()
        except OSError as exc:
            logger.debug(f"[RedisContext] WAL 读取失败: {exc}")
            return 0
        if not lines:
            return 0

        applied = 0
        try:
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue  # 坏行跳过（断电时尾部半行残留）
                op = rec.get("op")
                key = rec.get("key")
                if op == "clear":
                    # 回放 clear：删掉本 prefix 下全部键（与 clear() 语义一致）
                    async for raw_keys in self._scan_iter(f"{self._prefix}:*"):
                        if raw_keys:
                            await self._redis.delete(*raw_keys)
                    applied += 1
                    continue
                if not key:
                    continue
                rkey = self._make_key(key)
                raw_val = rec.get("value")
                if op == "delete" or raw_val is None:
                    await self._redis.delete(rkey)
                else:
                    await self._redis.set(rkey, base64.b64decode(raw_val))
                applied += 1
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                f"⚠️ [RedisContext] WAL 回放中断（保留 WAL 待下次重试）: {exc}")
            return applied

        # 全部成功 → 清空 WAL
        try:
            with open(self._wal_path, "w", encoding="utf-8"):
                pass
        except OSError:
            pass
        self._wal_overflow = False
        logger.info(f"♻️ [RedisContext] WAL 回放完成: {applied} 条写入已回灌 Redis")
        return applied

    # --- DAGContext 兼容接口 ---

    async def set(self, key: str, value: Any) -> None:
        """设置键值。"""
        async with self._lock:
            if self._fallback_mode:
                self._fallback_write(key, value)
                return

            await self._connect()
            if self._redis is None:
                self._fallback_write(key, value)
                return

            try:
                serialized = self._serialize(value)
                await self._redis.set(self._make_key(key), serialized)
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] set 失败，降级: {exc}")
                self._fallback_write(key, value)

    async def get(self, key: str, default: Any = None) -> Any:
        """获取键值。"""
        async with self._lock:
            if self._fallback_mode:
                return self._fallback_data.get(key, default)

            await self._connect()
            if self._redis is None:
                return self._fallback_data.get(key, default)

            try:
                data = await self._redis.get(self._make_key(key))
                if data is None:
                    return default
                return self._deserialize(data)
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] get 失败，降级: {exc}")
                return self._fallback_data.get(key, default)

    async def update(self, key: str, value: Any) -> None:
        """更新键值（与 DAGContext.update 语义一致）。

        - list + list → extend
        - dict + dict → merge
        - 其他 → 覆盖
        """
        async with self._lock:
            if self._fallback_mode:
                self._update_in_memory(key, value)
                return

            await self._connect()
            if self._redis is None:
                self._update_in_memory(key, value)
                return

            # 注意：_lock 不可重入，直接操作 Redis，避免嵌套调用 get/set 造成死锁
            try:
                raw = await self._redis.get(self._make_key(key))
                current = self._deserialize(raw) if raw is not None else None
                if current is None:
                    await self._redis.set(self._make_key(key), self._serialize(value))
                elif isinstance(current, list) and isinstance(value, list):
                    current.extend(value)
                    await self._redis.set(self._make_key(key), self._serialize(current))
                elif isinstance(current, dict) and isinstance(value, dict):
                    current.update(value)
                    await self._redis.set(self._make_key(key), self._serialize(current))
                else:
                    await self._redis.set(self._make_key(key), self._serialize(value))
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] update 失败，降级: {exc}")
                self._update_in_memory(key, value)

    def _update_in_memory(self, key: str, value: Any) -> None:
        """内存模式下的 update 逻辑（最终值统一走 _fallback_write 落 WAL）。

        WAL 记的是**合并后的最终值**而非增量操作：回放时按序 set 覆盖即可
        还原最终状态，无需在回放侧重现 extend/merge 语义。
        """
        if key in self._fallback_data:
            current = self._fallback_data[key]
            if isinstance(current, list) and isinstance(value, list):
                current.extend(value)
                merged = current
            elif isinstance(current, dict) and isinstance(value, dict):
                current.update(value)
                merged = current
            else:
                merged = value
        else:
            merged = value
        self._fallback_write(key, merged)

    async def get_and_clear(self, key: str) -> Any:
        """获取并删除键值。"""
        async with self._lock:
            if self._fallback_mode:
                return self._fallback_delete(key)

            await self._connect()
            if self._redis is None:
                return self._fallback_delete(key)

            try:
                raw = await self._redis.get(self._make_key(key))
                await self._redis.delete(self._make_key(key))
                return self._deserialize(raw)
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] get_and_clear 失败: {exc}")
                return self._fallback_delete(key)

    async def get_all(self) -> Dict[str, Any]:
        """获取所有键值对。"""
        async with self._lock:
            if self._fallback_mode:
                return dict(self._fallback_data)

            await self._connect()
            if self._redis is None:
                return dict(self._fallback_data)

            try:
                # P1-12：KEYS 阻塞 Redis 主线程 + 逐 key GET = O(k) 网络往返
                # → SCAN 增量迭代 + MGET 批量取回（往返数 k → ceil(k/batch)）
                result: Dict[str, Any] = {}
                prefix_len = len(self._prefix) + 1
                batch: list = []
                async for raw_keys in self._scan_iter(f"{self._prefix}:*"):
                    batch.extend(raw_keys)
                    while len(batch) >= _SCAN_BATCH:
                        await self._mget_into(result, batch[:_SCAN_BATCH], prefix_len)
                        batch = batch[_SCAN_BATCH:]
                if batch:
                    await self._mget_into(result, batch, prefix_len)
                return result
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] get_all 失败: {exc}")
                return dict(self._fallback_data)

    async def _mget_into(self, out: Dict[str, Any], raw_keys: list, prefix_len: int) -> None:
        """MGET 一批键并写回结果字典（内部辅助，异常交由调用方处理）。"""
        vals = await self._redis.mget(raw_keys)
        for raw_key, raw_val in zip(raw_keys, vals):
            if raw_val is None:
                continue
            key_str = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            out[key_str[prefix_len:]] = self._deserialize(raw_val)

    async def _scan_iter(self, pattern: str):
        """SCAN 增量迭代（异步生成器）；服务端不支持时回退 KEYS 并告警。"""
        try:
            cursor = 0
            while True:
                cursor, batch = await self._redis.scan(
                    cursor=cursor, match=pattern, count=_SCAN_BATCH)
                if batch:
                    yield batch
                if not cursor or cursor == "0":
                    break
        except Exception as exc:  # noqa: BLE001 - 老服务端无 SCAN → 一次性回退
            logger.warning(f"⚠️ [RedisContext] SCAN 不可用，回退 KEYS: {exc}")
            keys = await self._redis.keys(pattern)
            if keys:
                yield keys

    async def clear(self) -> None:
        """清空所有键值。"""
        async with self._lock:
            if self._fallback_mode:
                self._fallback_data.clear()
                self._wal_append("clear", "*")
                return

            await self._connect()
            if self._redis is None:
                self._fallback_data.clear()
                self._wal_append("clear", "*")
                return

            try:
                # P1-12：同样改 SCAN 分批删除，避免 KEYS 阻塞 + 超大 delete 参数
                removed = 0
                async for raw_keys in self._scan_iter(f"{self._prefix}:*"):
                    if raw_keys:
                        await self._redis.delete(*raw_keys)
                        removed += len(raw_keys)
                logger.info(f"🧹 [RedisContext] 清空 {removed} 个键")
            except Exception as exc:
                logger.warning(f"⚠️ [RedisContext] clear 失败: {exc}")
                self._fallback_data.clear()
                self._wal_append("clear", "*")

    async def has(self, key: str) -> bool:
        """检查键是否存在。"""
        async with self._lock:
            if self._fallback_mode:
                return key in self._fallback_data

            await self._connect()
            if self._redis is None:
                return key in self._fallback_data

            try:
                return await self._redis.exists(self._make_key(key)) > 0
            except Exception:
                return key in self._fallback_data
