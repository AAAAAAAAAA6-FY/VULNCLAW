# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/executor.py
"""
异步执行器 - 修复版（命令执行安全化 + 锁保护）
修复：
1. get_session 增加异步锁，防止并发创建多个 ClientSession
2. 命令执行强制要求 cmd 为列表，禁用 shell=True
3. 进程树清理支持跨平台（Windows/Linux）
4. 使用 asyncio.create_subprocess_exec 替代字符串命令
"""

import asyncio
import aiohttp
import os
import sys
import psutil
import subprocess
from vulnclaw.core.logger import logger
from typing import List, Optional, Tuple


class AsyncExecutor:
    def __init__(self, max_concurrent: int = 50, timeout: int = 10):
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._timeout = timeout
        self._running_processes = []  # 跟踪子进程
        # ===== 修复：添加异步锁保护 =====
        self._session_lock = asyncio.Lock()

    async def get_session(self) -> aiohttp.ClientSession:
        """
        获取共享会话 - 修复：增加锁保护，防止并发创建
        """
        # ===== 修复：使用锁保护检查和创建 =====
        async with self._session_lock:
            if self._session is None or self._session.closed:
                connector = aiohttp.TCPConnector(
                    ssl=False,
                    limit=self._semaphore._value,
                    force_close=True
                )
                self._session = aiohttp.ClientSession(
                    connector=connector,
                    timeout=aiohttp.ClientTimeout(total=self._timeout)
                )
                logger.debug("✅ 创建新的 ClientSession")
            return self._session

    async def http_get(self, url: str, headers: Optional[dict] = None) -> Tuple[int, str]:
        async with self._semaphore:
            session = await self.get_session()
            try:
                async with session.get(url, headers=headers or {}, ssl=False) as resp:
                    text = await resp.text()
                    return resp.status, text
            except Exception as e:
                return 0, str(e)

    async def http_post(self, url: str, data: Optional[dict] = None, json: Optional[dict] = None, headers: Optional[dict] = None) -> Tuple[int, str]:
        async with self._semaphore:
            session = await self.get_session()
            try:
                async with session.post(url, data=data, json=json, headers=headers or {}, ssl=False) as resp:
                    text = await resp.text()
                    return resp.status, text
            except Exception as e:
                return 0, str(e)

    # ============================================================
    # 安全命令执行（强制列表传参，禁用 shell=True）
    # ============================================================
    async def run_command(self, cmd: List[str], timeout: int = 120) -> Tuple[int, str, str]:
        """
        安全执行命令，cmd 必须为列表，禁用 shell=True
        返回 (returncode, stdout, stderr)
        """
        if not isinstance(cmd, list):
            raise ValueError(f"cmd 必须为列表，禁止字符串形式（防注入）。收到: {type(cmd)}")

        if not cmd:
            raise ValueError("cmd 列表不能为空")

        logger.debug(f"🔧 执行命令: {' '.join(cmd)}")

        proc = None
        try:
            # ===== 跨平台进程创建 =====
            if sys.platform == 'win32':
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if hasattr(subprocess, 'CREATE_NEW_PROCESS_GROUP') else 0
                )
            else:
                # Unix: 使用 setsid 创建新进程组
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    preexec_fn=os.setsid if hasattr(os, 'setsid') else None
                )
            self._running_processes.append(proc)

            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                return proc.returncode, stdout.decode(errors="ignore"), stderr.decode(errors="ignore")
            except asyncio.TimeoutError:
                logger.warning(f"⏰ 命令超时 ({timeout}s): {' '.join(cmd)}，强制终止进程树")
                await self._kill_process_tree(proc)
                return -1, "", "Timeout (killed with process tree)"

        except FileNotFoundError as e:
            logger.error(f"❌ 命令未找到: {cmd[0]} - {e}")
            return -1, "", f"FileNotFound: {cmd[0]}"
        except PermissionError as e:
            logger.error(f"❌ 权限不足: {cmd[0]} - {e}")
            return -1, "", f"PermissionError: {e}"
        except Exception as e:
            logger.error(f"❌ 命令执行异常: {e}")
            if proc:
                await self._kill_process_tree(proc)
            return -1, "", str(e)
        finally:
            if proc and proc in self._running_processes:
                self._running_processes.remove(proc)

    def _kill_process_tree_sync(self, proc):
        """同步实现：psutil 枚举 + taskkill 回退（纯 CPU/IO 操作）"""
        try:
            if proc.pid is None:
                return
            parent = psutil.Process(proc.pid)
            children = parent.children(recursive=True)
            for child in children:
                try:
                    child.terminate()
                except psutil.NoSuchProcess:
                    pass
            try:
                parent.terminate()
            except psutil.NoSuchProcess:
                pass
            gone, alive = psutil.wait_procs(children + [parent], timeout=3)
            for p in alive:
                try:
                    p.kill()
                except psutil.NoSuchProcess:
                    pass
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            logger.warning(f"清理进程树失败: {e}")
        # Windows 回退：taskkill 同步调用（保持在同步函数内，避免阻塞事件循环）
        if sys.platform == 'win32':
            try:
                subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                               capture_output=True, timeout=5)
            except BaseException:
                pass
        else:
            try:
                subprocess.run(['kill', '-9', '-{}'.format(proc.pid)],
                               capture_output=True, timeout=5)
            except BaseException:
                pass

    async def _kill_process_tree(self, proc):
        """异步入口：将同步实现放到线程池执行，避免阻塞事件循环"""
        await asyncio.to_thread(self._kill_process_tree_sync, proc)

    async def close(self):
        if self._running_processes:
            tasks = [self._kill_process_tree(proc) for proc in self._running_processes]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self._running_processes.clear()
        if self._session and not self._session.closed:
            await self._session.close()
            logger.debug("关闭 AsyncExecutor 会话")


# 全局执行器实例
executor = AsyncExecutor()


__all__ = ['AsyncExecutor', 'executor']
