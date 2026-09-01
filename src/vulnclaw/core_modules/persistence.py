# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core_modules/persistence.py（R3 迁移自 core/persistence.py）
"""
数据持久化模块 - 精简版
修复：Windows 检查点写入失败（增加重试次数 + 指数退避）
"""
import json
import os
import time
import re
import asyncio
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import PROJECT_CACHE_DIR

CHECKPOINT_VERSION = 3
CHECKPOINT_EXPIRE_DAYS = 7
MAX_CHECKPOINTS = 10
MAX_SAVE_RETRIES = 5
SAVE_RETRY_BASE_DELAY = 1

# ============================================================
# 瓶颈5（持久化反压）默认参数：
#   BATCH_MAX_ITEMS    = 64     ：满 64 次"标记脏"立刻触发刷盘
#   BATCH_MAX_WAIT_MS  = 200    ：最多攒 200ms 后也必须刷（哪怕不足 64 次）
# 这组值在"瓶颈3开到10并发 × 每请求 1 次 mark_url_done / set_progress"下，
# 理论上能把磁盘 fsync 频次从 ~100/s 降到 ≤ 5/s。
# ============================================================
BATCH_MAX_ITEMS: int = 64
BATCH_MAX_WAIT_SECONDS: float = 0.2


def _run_io_save_sync(
    state_snapshot: Dict,
    target_file: Path,
) -> None:
    """纯同步 IO 写盘：
    - 与 asyncio 事件循环完全解耦；由 to_thread 丢进默认线程池。
    - 避免 json.dump + open + fssync 阻塞事件循环（Windows 下 fsync 尤其慢）。
    """
    tmp_file = target_file.with_suffix('.tmp')
    # 同步版简单重试（无 asyncio.sleep 指数退避）
    last_exc = None
    for attempt in range(MAX_SAVE_RETRIES):
        try:
            with open(tmp_file, 'w', encoding='utf-8') as f:
                json.dump(state_snapshot, f, ensure_ascii=False, indent=2, default=str)
                f.flush()
                os.fsync(f.fileno())
            try:
                tmp_file.replace(target_file)
            except (PermissionError, OSError):
                # 降级：直接写原文件
                with open(target_file, 'w', encoding='utf-8') as f:
                    with open(tmp_file, 'r', encoding='utf-8') as src:
                        f.write(src.read())
                    f.flush()
                    os.fsync(f.fileno())
                if tmp_file.exists():
                    try:
                        tmp_file.unlink()
                    except BaseException:
                        pass
            return  # 成功
        except Exception as e:
            last_exc = e
            if attempt < MAX_SAVE_RETRIES - 1:
                delay = SAVE_RETRY_BASE_DELAY * (2 ** attempt)
                # 同步 sleep 在 worker 线程里没关系
                time.sleep(delay)
    # 所有重试失败：清理临时文件 + 抛异常（to_thread 会变成 Future 的异常）
    if tmp_file.exists():
        try:
            tmp_file.unlink()
        except BaseException:
            pass
    if last_exc is not None:
        raise last_exc  # type: ignore[misc]


class ScanState:
    """扫描状态管理器 - 修复版（Windows 写入兼容 + 瓶颈5攒批异步落盘）"""

    def __init__(self, state_dir: str = None):
        if state_dir is None:
            state_dir = os.path.join(PROJECT_CACHE_DIR, "state")
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_file = self.state_dir / "state.json"
        self.lock_file = self.state_dir / "state.lock"
        self._state: Dict[str, Any] = {}
        self._loaded = False
        self._dirty = False
        # 写盘锁：保护"真正发起一次落盘"这段临界区，避免并发发起多个写盘任务
        # 但"脏标记 + 计数器"不被这个锁保护 — 它们走独立的 self._state_lock
        self._flush_lock = asyncio.Lock()
        # 状态/脏计数/定时器 轻量锁：保护 self._state 更新 & 自增
        self._state_lock = asyncio.Lock()
        self._dirty_count = 0
        self._last_flush_ts = 0.0
        self._flush_timer_task: Optional[asyncio.Task] = None

    # ============================================================
    # 瓶颈5 攒批异步写盘：
    #   对外 API update / set_progress / mark_url_done / clear / save(force=True)
    #   在内部只做两件事：① 更新内存态 ② _schedule_flush(force=...) 调度。
    #
    #   _schedule_flush 决策：
    #     - force=True            → 立刻同步发起 _do_flush 并 await
    #     - dirty_count >= 64     → 立刻触发一次
    #     - 距离上次 flush >200ms → 已经到期；立刻触发
    #     - 否则：如果尚未启动 timer，则 create_task(async sleep 200ms 后触发一次)
    # ============================================================

    def load(self) -> bool:
        if not self.state_file.exists():
            return False
        try:
            with open(self.state_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            self._state = data
            self._loaded = True
            self._dirty = False
            self._dirty_count = 0
            progress = data.get('progress', 0)
            logger.info(f"📂 加载扫描状态成功，上次进度: {progress}%")
            return True
        except json.JSONDecodeError as e:
            logger.warning(f"⚠️ 状态文件损坏 ({e})，将从头开始")
            try:
                backup = self.state_file.with_suffix('.json.bak')
                self.state_file.rename(backup)
                logger.info(f"📂 已备份损坏的状态文件到: {backup}")
            except BaseException:
                pass
            return False
        except Exception as e:
            logger.warning(f"⚠️ 加载状态失败: {e}，将从头开始")
            return False

    async def _do_flush(self) -> None:
        """真正执行一次落盘（单写者语义）。"""
        # 取快照：在 state_lock 内把 _state 深拷贝/浅拷贝出来，立刻释放锁，
        # 避免 JSON 序列化期间阻塞其他协程的 update。
        async with self._state_lock:
            if not self._dirty:
                return
            snapshot = self._state.copy()
            self._dirty = False
            self._dirty_count = 0

        # flush_lock 保证"并发调度多份 flush"时，真正写盘也是严格串行的
        async with self._flush_lock:
            try:
                # 把同步 fsync 丢进线程池，不阻塞事件循环
                await asyncio.to_thread(_run_io_save_sync, snapshot, self.state_file)
                async with self._state_lock:
                    self._last_flush_ts = time.time()
            except Exception as e:
                logger.error(f"❌ ScanState 异步攒批保存失败: {e}")
                # 写盘失败时恢复 dirty=True & dirty_count，避免下次永不重试
                async with self._state_lock:
                    self._dirty = True
                    self._dirty_count = max(self._dirty_count, 1)

    def _cancel_pending_timer(self) -> None:
        t = self._flush_timer_task
        if t is not None and not t.done():
            t.cancel()
            self._flush_timer_task = None

    async def _run_flush_after(self, delay_seconds: float) -> None:
        """协程：sleep 到攒批窗口后强制 flush 一次。"""
        try:
            await asyncio.sleep(delay_seconds)
        except asyncio.CancelledError:
            return
        await self._do_flush()

    async def _schedule_flush(self, force: bool) -> None:
        """根据攒批策略决定"立刻 flush / 启动 timer / 什么都不做"。"""
        async with self._state_lock:
            # 只有在 force=True 的情况下，非 dirty 才会跳过；
            # 其他路径非 dirty 直接跳过。
            if not self._dirty:
                self._cancel_pending_timer()
                return

            now = time.time()
            if force or self._dirty_count >= BATCH_MAX_ITEMS or (now - self._last_flush_ts) >= BATCH_MAX_WAIT_SECONDS:
                # 立刻触发：取消 timer 并立即 do_flush
                self._cancel_pending_timer()
                need_immediate = True
            else:
                need_immediate = False
                # 启动或复用一个 timer：精确在 (200ms - 已等待时间) 后触发
                wait_for = max(0.0, BATCH_MAX_WAIT_SECONDS - (now - self._last_flush_ts))
                if self._flush_timer_task is None or self._flush_timer_task.done():
                    self._flush_timer_task = asyncio.create_task(self._run_flush_after(wait_for))

        if need_immediate:
            await self._do_flush()

    async def flush(self) -> None:
        """对外显式强制落盘：等返回后确保磁盘有最新状态。"""
        await self._schedule_flush(force=True)

    # ============================================================
    # 兼容 API：旧 API 是 async def save()，继续保留为"强制攒批+落盘"别名，
    # 这样原调用方 save_checkpoint / 扫描结束的 flush 逻辑不变。
    # ============================================================
    async def save(self) -> None:
        await self._schedule_flush(force=True)

    async def update(self, **kwargs) -> None:
        async with self._state_lock:
            self._state.update(kwargs)
            self._dirty = True
            self._dirty_count += 1
        await self._schedule_flush(force=False)

    def get(self, key: str, default=None):
        return self._state.get(key, default)

    async def set_progress(self, current: int, total: int) -> None:
        if total > 0:
            async with self._state_lock:
                self._state['progress'] = int(current / total * 100)
                self._state['scanned'] = current
                self._state['total'] = total
                self._dirty = True
                self._dirty_count += 1
            await self._schedule_flush(force=False)

    async def mark_url_done(self, url: str) -> None:
        async with self._state_lock:
            done = set(self._state.get('done_urls', []))
            done.add(url)
            self._state['done_urls'] = list(done)
            self._dirty = True
            self._dirty_count += 1
        await self._schedule_flush(force=False)

    def get_done_urls(self) -> set:
        return set(self._state.get('done_urls', []))

    def is_url_done(self, url: str) -> bool:
        return url in self.get_done_urls()

    async def clear(self) -> None:
        async with self._state_lock:
            self._state.clear()
            self._dirty = True
            self._dirty_count += 1
        # 删除旧文件可同步执行（只跑一次）
        if self.state_file.exists():
            try:
                self.state_file.unlink()
            except BaseException:
                pass
        logger.info("🧹 已清除扫描状态")
        await self._schedule_flush(force=True)

    async def save_checkpoint(self, checkpoint: Dict) -> None:
        checkpoint['_metadata'] = {
            'version': CHECKPOINT_VERSION,
            'timestamp': time.time(),
            'datetime': datetime.now().isoformat(),
            'tool_stats': self._state.get('tool_stats', {}),
            'scan_stage': checkpoint.get('pending_stages', ['unknown']),
        }

        checkpoint_dir = self.state_dir.parent / "checkpoints"
        checkpoint_dir.mkdir(exist_ok=True)

        ckpt_file = checkpoint_dir / f"checkpoint_{int(time.time())}.json"
        tmp_file = ckpt_file.with_suffix('.tmp')
        latest_file = checkpoint_dir / "latest_checkpoint.json"
        latest_tmp = latest_file.with_suffix('.tmp')

        async with self._write_lock:
            try:
                # 写入检查点文件
                with open(tmp_file, 'w', encoding='utf-8') as f:
                    json.dump(checkpoint, f, indent=2, default=str)
                    f.flush()
                    os.fsync(f.fileno())
                # 尝试原子替换
                try:
                    tmp_file.replace(ckpt_file)
                except (PermissionError, OSError):
                    # 降级：直接写入
                    with open(ckpt_file, 'w', encoding='utf-8') as f:
                        f.write(open(tmp_file, 'r', encoding='utf-8').read())
                        f.flush()
                        os.fsync(f.fileno())
                    if tmp_file.exists():
                        tmp_file.unlink()

                # 写入最新检查点
                with open(latest_tmp, 'w', encoding='utf-8') as f:
                    json.dump(checkpoint, f, indent=2, default=str)
                    f.flush()
                    os.fsync(f.fileno())
                try:
                    latest_tmp.replace(latest_file)
                except (PermissionError, OSError):
                    with open(latest_file, 'w', encoding='utf-8') as f:
                        f.write(open(latest_tmp, 'r', encoding='utf-8').read())
                        f.flush()
                        os.fsync(f.fileno())
                    if latest_tmp.exists():
                        latest_tmp.unlink()

                self._cleanup_old_checkpoints()
                logger.info(f"💾 检查点已保存: {ckpt_file}")
            except Exception as e:
                logger.error(f"❌ 保存检查点失败: {e}")
                for tmp in [tmp_file, latest_tmp]:
                    if tmp.exists():
                        try:
                            tmp.unlink()
                        except BaseException:
                            pass

    def load_latest_checkpoint(self) -> Dict:
        checkpoint_dir = self.state_dir.parent / "checkpoints"
        latest_file = checkpoint_dir / "latest_checkpoint.json"
        if not latest_file.exists():
            return {}
        try:
            with open(latest_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            metadata = data.get('_metadata', {})
            version = metadata.get('version', 0)
            if version != CHECKPOINT_VERSION:
                logger.info(f"⚠️ 检查点版本不兼容 ({version} != {CHECKPOINT_VERSION})，将重新扫描")
                return {}
            timestamp = metadata.get('timestamp', 0)
            if time.time() - timestamp > CHECKPOINT_EXPIRE_DAYS * 86400:
                logger.info(f"⏰ 检查点已过期（超过 {CHECKPOINT_EXPIRE_DAYS} 天），将重新扫描")
                return {}
            progress = data.get('progress', 0)
            logger.info(f"♻️ 加载检查点成功，进度: {progress}%")
            return data
        except json.JSONDecodeError:
            logger.warning("⚠️ 检查点文件损坏，将重新扫描")
            return {}
        except Exception as e:
            logger.warning(f"⚠️ 加载检查点失败: {e}")
            return {}

    def _cleanup_old_checkpoints(self):
        checkpoint_dir = self.state_dir.parent / "checkpoints"
        if not checkpoint_dir.exists():
            return
        files = sorted(
            checkpoint_dir.glob("checkpoint_*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        now = time.time()
        for f in files:
            if now - f.stat().st_mtime > CHECKPOINT_EXPIRE_DAYS * 86400:
                try:
                    f.unlink()
                except BaseException:
                    pass
        remaining = sorted(
            checkpoint_dir.glob("checkpoint_*.json"),
            key=lambda f: f.stat().st_mtime,
            reverse=True
        )
        if len(remaining) > MAX_CHECKPOINTS:
            for f in remaining[MAX_CHECKPOINTS:]:
                try:
                    f.unlink()
                except BaseException:
                    pass

    def has_pending_tasks(self) -> bool:
        data = self.load_latest_checkpoint()
        if not data:
            return False
        return bool(data.get('pending_urls', []) or data.get('pending_stages', []))

    def get_pending_urls(self) -> List[str]:
        data = self.load_latest_checkpoint()
        return data.get('pending_urls', [])

    def get_pending_stages(self) -> List[str]:
        data = self.load_latest_checkpoint()
        return data.get('pending_stages', [])

    # ===== A4.6 断点续扫 =====
    def resume(self) -> tuple:
        """返回 (should_resume, checkpoint)。

        若检查点不存在/过期/损坏或无待处理任务，则 should_resume=False；
        否则 True，调用方据此跳过已完成阶段、恢复 pending_urls/stages。
        """
        ckpt = self.load_latest_checkpoint()
        if not ckpt:
            return (False, {})
        if not (ckpt.get('pending_urls') or ckpt.get('pending_stages')):
            return (False, ckpt)
        return (True, ckpt)


class IncrementalSaver:
    """增量数据保存器 - 瓶颈5版：合并写入 & 攒批落盘
    （每 save_partial 只更新内存 dict + 调度 flush；200ms 或 64 次合并后触发一次 JSON 写盘）
    """

    def __init__(self, base_dir: str = None):
        if base_dir is None:
            base_dir = os.path.join(PROJECT_CACHE_DIR, "incremental")
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.index_file = self.base_dir / "incremental_index.json"
        self._index: Dict[str, Any] = {}
        self._loaded = False
        self._state_lock = asyncio.Lock()
        self._flush_lock = asyncio.Lock()
        self._dirty = False
        self._dirty_count = 0
        self._last_flush_ts = 0.0
        self._flush_timer_task: Optional[asyncio.Task] = None

    def _load_index(self):
        if self._loaded:
            return
        if self.index_file.exists():
            try:
                with open(self.index_file, 'r', encoding='utf-8') as f:
                    self._index = json.load(f)
            except BaseException:
                self._index = {}
        self._loaded = True

    # ===== 攒批调度：和 ScanState 策略一致 =====
    def _cancel_pending_timer(self) -> None:
        t = self._flush_timer_task
        if t is not None and not t.done():
            t.cancel()
            self._flush_timer_task = None

    async def _run_flush_after(self, delay_seconds: float) -> None:
        try:
            await asyncio.sleep(delay_seconds)
        except asyncio.CancelledError:
            return
        await self._do_flush()

    async def _do_flush(self) -> None:
        async with self._state_lock:
            if not self._dirty:
                return
            snapshot = self._index.copy()
            self._dirty = False
            self._dirty_count = 0

        async with self._flush_lock:
            try:
                await asyncio.to_thread(_run_io_save_sync, snapshot, self.index_file)
                async with self._state_lock:
                    self._last_flush_ts = time.time()
            except Exception as e:
                logger.error(f"❌ 保存增量索引失败: {e}")
                async with self._state_lock:
                    self._dirty = True
                    self._dirty_count = max(self._dirty_count, 1)

    async def _schedule_flush(self, force: bool) -> None:
        async with self._state_lock:
            if not self._dirty:
                self._cancel_pending_timer()
                return
            now = time.time()
            if force or self._dirty_count >= BATCH_MAX_ITEMS or (now - self._last_flush_ts) >= BATCH_MAX_WAIT_SECONDS:
                self._cancel_pending_timer()
                need_immediate = True
            else:
                need_immediate = False
                wait_for = max(0.0, BATCH_MAX_WAIT_SECONDS - (now - self._last_flush_ts))
                if self._flush_timer_task is None or self._flush_timer_task.done():
                    self._flush_timer_task = asyncio.create_task(self._run_flush_after(wait_for))
        if need_immediate:
            await self._do_flush()

    async def flush(self) -> None:
        await self._schedule_flush(force=True)

    async def save_partial(self, key: str, data: Dict, merge: bool = True) -> None:
        self._load_index()
        async with self._state_lock:
            if merge and key in self._index:
                existing = self._index[key]
                if isinstance(existing, list) and isinstance(data, list):
                    existing_ids = {self._get_id(item) for item in existing if self._get_id(item)}
                    for item in data:
                        item_id = self._get_id(item)
                        if not item_id or item_id not in existing_ids:
                            existing.append(item)
                            if item_id:
                                existing_ids.add(item_id)
                    self._index[key] = existing
                elif isinstance(existing, dict) and isinstance(data, dict):
                    existing.update(data)
                    self._index[key] = existing
                else:
                    self._index[key] = data
            else:
                self._index[key] = data
            self._dirty = True
            self._dirty_count += 1
        await self._schedule_flush(force=False)

    def _get_id(self, item: Any) -> Optional[str]:
        if isinstance(item, dict):
            return item.get('id') or item.get('url') or item.get('name')
        return None

    def get_partial(self, key: str) -> Optional[Any]:
        self._load_index()
        return self._index.get(key)

    def get_all(self) -> Dict:
        self._load_index()
        return self._index.copy()

    # ===== A3.2 目标画像持久化 =====
    async def save_target_profile(self, target: str, profile: Dict) -> None:
        """持久化目标画像（指纹/资产/上次结论），复用 save_partial 增量合并。"""
        key = f"target_profile::{target}"
        await self.save_partial(key, {"profile": profile, "updated_at": time.time()}, merge=True)

    def load_target_profile(self, target: str) -> Optional[Dict]:
        """加载目标画像；无则返回 None。"""
        data = self.get_partial(f"target_profile::{target}")
        if isinstance(data, dict) and "profile" in data:
            return data["profile"]
        return None

    async def clear(self):
        async with self._write_lock:
            self._index.clear()
            self._loaded = False
            if self.index_file.exists():
                try:
                    self.index_file.unlink()
                except BaseException:
                    pass


class CorrelationEngine:
    """历史扫描关联引擎 - 精简版（写入已禁用）"""

    def __init__(self, history_dir: str = None):
        if history_dir is None:
            history_dir = os.path.join(PROJECT_CACHE_DIR, "history")
        self.history_dir = Path(history_dir)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self._write_lock = asyncio.Lock()

    def _sanitize_filename(self, name: str, max_len: int = 200) -> str:
        safe = re.sub(r'[^a-zA-Z0-9.\-]', '_', name)
        safe = safe.replace('..', '').replace('/', '').replace('\\', '')
        if len(safe) > max_len:
            safe = safe[:max_len]
        return safe

    async def save_scan(self, target: str, vulns: List[Dict], metadata: Dict = None) -> None:
        # 完全禁用历史记录保存
        logger.debug("ℹ️ 历史记录保存已禁用（CorrelationEngine.save_scan 被跳过）")
        return

    def load_all_scans(self) -> List[Dict]:
        scans = []
        for filepath in self.history_dir.glob("*.json"):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    scans.append(data)
            except BaseException:
                pass
        return scans

    def find_common_vulns(self, current_vulns: List[Dict]) -> List[Dict]:
        common = []
        historical_patterns = set()
        all_scans = self.load_all_scans()
        for scan in all_scans:
            for vuln in scan.get('vulns', []):
                vuln_type = vuln.get('type', '')
                if vuln_type:
                    historical_patterns.add(vuln_type)
                vuln_url = vuln.get('url', '')
                if vuln_url:
                    try:
                        historical_patterns.add(vuln_url.split('/')[2] if '://' in vuln_url else '')
                    except BaseException:
                        pass
        for vuln in current_vulns:
            vuln_type = vuln.get('type', '')
            vuln_url = vuln.get('url', '')
            vuln_domain = vuln_url.split('/')[2] if '://' in vuln_url else ''
            if vuln_type in historical_patterns or vuln_domain in historical_patterns:
                common.append(vuln)
        if common:
            logger.info(f"🔗 发现 {len(common)} 个漏洞在历史扫描中也出现过")
        return common

    def suggest_re_test(self, current_target: str) -> List[Dict]:
        suggestions = []
        all_scans = self.load_all_scans()
        current_patterns = set()
        for scan in all_scans:
            if scan.get('target') == current_target:
                for vuln in scan.get('vulns', []):
                    vuln_type = vuln.get('type', '')
                    if vuln_type:
                        current_patterns.add(vuln_type)
        for scan in all_scans:
            if scan.get('target') != current_target:
                for vuln in scan.get('vulns', []):
                    if vuln.get('type', '') in current_patterns:
                        suggestions.append({
                            "target": scan.get('target', ''),
                            "vuln_type": vuln.get('type', ''),
                            "reason": "与当前目标有相同的漏洞模式"
                        })
        return suggestions[:5]


_incremental_saver: Optional[IncrementalSaver] = None
_correlation_engine: Optional[CorrelationEngine] = None


def get_incremental_saver() -> IncrementalSaver:
    global _incremental_saver
    if _incremental_saver is None:
        _incremental_saver = IncrementalSaver()
    return _incremental_saver


def get_correlation_engine() -> CorrelationEngine:
    global _correlation_engine
    if _correlation_engine is None:
        _correlation_engine = CorrelationEngine()
    return _correlation_engine


__all__ = [
    'ScanState',
    'IncrementalSaver',
    'CorrelationEngine',
    'get_incremental_saver',
    'get_correlation_engine'
]
