# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/logger.py
"""
日志模块 - 修复版
日志输出到控制台和文件（文件日志默认写入 _runtime_cache/logs/）
"""

import logging
import sys
import os
from datetime import datetime

# ===== 获取项目根目录（src/vulnclaw/core/logger.py → 上溯 3 级，与 paths.py 对齐）=====
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ===== 日志目录迁移至 _runtime_cache/logs =====
LOG_DIR = os.path.join(PROJECT_ROOT, "_runtime_cache", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# ===== 日志文件名 =====
LOG_FILE = os.path.join(LOG_DIR, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# ===== 配置根日志记录器 =====
if not logging.getLogger().handlers:
    # 控制台处理器（INFO 级别）
    # MCP / stdio 协议使用 stdout 传输 JSON-RPC，必须将日志留给 stderr。
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )
    console_handler.setFormatter(console_format)

    # 文件处理器（DEBUG 级别，记录所有）
    from logging.handlers import RotatingFileHandler, MemoryHandler
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=50 * 1024 * 1024,
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    file_format = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_format)

    # ============================================================
    # 瓶颈6：每条日志的 FileHandler.flush 会同步阻塞事件循环
    #   - 10 worker + 每条请求 3~5 条日志 = ~40-50 logs/s 同步刷盘
    #   - fsync 对 Windows 机械盘/杀毒软件尤其敏感（>10ms/次）
    #
    # MemoryHandler 策略：
    #   capacity=50        ：攒 50 条再 flush（通常 ~1s）
    #   flushLevel=WARNING ：一旦出现 WARNING/ERROR 立刻 flush，
    #                        保证严重错误不落"还在 buffer 里进程就崩"的风险
    # ============================================================
    LOG_MEMORY_CAPACITY = int(getattr(__builtins__, 'PENTEST_LOG_MEMORY_CAPACITY', 50)) or 50
    buffered_file_handler = MemoryHandler(
        capacity=LOG_MEMORY_CAPACITY,
        flushLevel=logging.WARNING,
        target=file_handler,
    )
    # MemoryHandler 等级设为和目标一样：底层真正过滤由 target 承担
    buffered_file_handler.setLevel(logging.DEBUG)

    # 配置根日志记录器（控制台保持同步直出，MemoryHandler 只缓冲到文件）
    logging.basicConfig(
        level=logging.INFO,
        handlers=[console_handler, buffered_file_handler]
    )

# ===== 获取模块日志记录器 =====
logger = logging.getLogger("pentest_agent")

# ===== P3-2: 注册到 DI 容器（供测试注入 mock）=====
try:
    from vulnclaw.core.container import get_container
    get_container().register("logger", logger)
except Exception:  # noqa: BLE001 - 容器不可用时不影响日志模块本身
    pass

# ===== 导出 =====
__all__ = ['logger', 'LOG_DIR', 'LOG_FILE']
