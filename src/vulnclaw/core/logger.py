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
import json
import re
import threading
import uuid
from datetime import datetime

# ===== 获取项目根目录（src/vulnclaw/core/logger.py → 上溯 3 级，与 paths.py 对齐）=====
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ===== 日志目录迁移至 _runtime_cache/logs =====
LOG_DIR = os.path.join(PROJECT_ROOT, "_runtime_cache", "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# ===== 日志文件名 =====
LOG_FILE = os.path.join(LOG_DIR, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")

# ===== 平台自保护：日志凭据脱敏过滤器（fail-open，脱敏异常绝不影响日志）=====
class _RedactFilter(logging.Filter):
    """输出前把日志中的明文凭据替换为掩码（Authorization/Cookie/token/私钥等）。

    默认走 core.utils.redact_secrets 的**保守内置规则**（Authorization/Cookie/
    key=value 凭据/PEM 私钥）。可选传入 ``extra_pattern`` 做自定义正则脱敏：
    命中片段整体替换为 ``[REDACTED]``。任何异常都 fail-open 放行原日志。
    """

    def __init__(self, extra_pattern=None, mask="[REDACTED]"):
        super().__init__()
        self.extra_pattern = re.compile(extra_pattern) if extra_pattern is not None else None
        self.mask = mask

    def _redact(self, value):
        if not isinstance(value, str):
            return value
        try:
            from vulnclaw.core.utils import redact_secrets  # 延迟导入避免循环依赖
            out = redact_secrets(value)  # 保守内置规则
            if self.extra_pattern is not None:
                out = self.extra_pattern.sub(self.mask, out)
            return out
        except Exception:  # noqa: BLE001 - 脱敏失败必须放行日志
            return value

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            if isinstance(record.msg, str):
                record.msg = self._redact(record.msg)
            else:
                record.msg = self._redact(str(record.msg))
            if record.args:
                if isinstance(record.args, tuple):
                    record.args = tuple(self._redact(a) for a in record.args)
                elif isinstance(record.args, dict):
                    record.args = {k: self._redact(v) for k, v in record.args.items()}
                else:
                    record.args = self._redact(record.args)
        except Exception:  # noqa: BLE001 - 脱敏失败必须放行日志
            pass
        return True


# ===== 结构化日志：trace 上下文（thread-local，供 JSON 输出 trace_id）=====
_LOCAL = threading.local()


def set_trace_context(trace_id: str) -> None:
    """设置当前线程/协程的 trace_id（透传到结构化日志）。"""
    _LOCAL.trace_id = trace_id


def get_trace_context() -> str:
    """获取当前线程的 trace_id（未设置返回空串）。"""
    return getattr(_LOCAL, "trace_id", "")


def new_trace_id() -> str:
    """生成新 trace_id（uuid4 hex）并设为当前上下文。"""
    tid = uuid.uuid4().hex
    set_trace_context(tid)
    return tid


# ===== 结构化日志 JSON formatter（env STRUCTURED_LOG=1 启用）=====
class _JsonFormatter(logging.Formatter):
    """输出 {ts, level, name, trace_id, message} 的 JSON 行（不引入第三方依赖）。"""

    def format(self, record: logging.LogRecord) -> str:
        try:
            return json.dumps({
                "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                "level": record.levelname,
                "name": record.name,
                "trace_id": get_trace_context(),
                "message": record.getMessage(),
            }, ensure_ascii=False)
        except Exception:  # noqa: BLE001 - 失败回退标准格式
            return super().format(record)


# ===== 配置根日志记录器 =====
if not logging.getLogger().handlers:
    # 结构化日志开关：STRUCTURED_LOG=1 → 控制台+文件都用 JSON 格式（含 trace_id）
    _structured = os.environ.get("STRUCTURED_LOG", "0") == "1"

    # 控制台处理器（INFO 级别）
    # MCP / stdio 协议使用 stdout 传输 JSON-RPC，必须将日志留给 stderr。
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.INFO)
    if _structured:
        console_format: logging.Formatter = _JsonFormatter()  # type: ignore[assignment]
    else:
        console_format = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )
    console_handler.setFormatter(console_format)
    console_handler.addFilter(_RedactFilter())  # 控制台不输出明文凭据

    # 文件处理器（DEBUG 级别，记录所有）
    from logging.handlers import RotatingFileHandler, MemoryHandler
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=50 * 1024 * 1024,
        backupCount=3,
        encoding='utf-8'
    )
    file_handler.setLevel(logging.DEBUG)
    if _structured:
        file_format: logging.Formatter = _JsonFormatter()  # type: ignore[assignment]
    else:
        file_format = logging.Formatter(
            '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    file_handler.setFormatter(file_format)
    file_handler.addFilter(_RedactFilter())  # 日志文件不落明文凭据

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

# ============================================================
# T15 异常协议第 1 批：统一"被吞异常"审计
# ============================================================
# 背景：全项目有 300+ 处 `logger.debug("suppressed exception (core audit)")`，
# 只有一行固定文本 —— **异常对象完全丢失**（连 type/message 都没有），
# 排查时只知道"这里吞了异常"，不知道吞了什么、在哪吞的。
#
# 本函数把这些点升级为**结构化审计事件**，且**不改 except 绑定**：
# 用 sys.exc_info() 在 except 块内取回正在处理的异常 —— 因此调用点只需
# 把原来的字面量 debug 换成 `audit_suppressed()`，零结构性改动。
#
# 三件事：
#   1. 主日志：DEBUG 级输出 [类型] 位置: 消息（控制台不污染，文件日志可查）
#   2. 结构化落盘：_runtime_cache/logs/suppressed_exceptions.jsonl
#      （kind/site/caller/type/message/trace_id），供离线统计"哪段代码在吞什么"
#   3. 绝不抛异常 —— 审计自身失败也 fail-open，不得反过来影响业务
_SUPPRESSED_AUDIT_PATH = os.path.join(LOG_DIR, "suppressed_exceptions.jsonl")
_SUPPRESSED_AUDIT_LOCK = threading.Lock()


def audit_suppressed(site: str = "", **extra) -> str:
    """记录一个被吞掉的异常（结构化 + 落盘）。

    **必须在 except 块内调用**（依赖 ``sys.exc_info()`` 取当前异常）；
    在 except 块外调用不会报错，但 type/message 为空。

    Args:
        site: 语义位置标签（如 ``"orchestrator.gc"``）；留空则自动用
              调用点 ``文件名:行号``（异常路径低频，inspect 开销可接受）。
        **extra: 附加结构化字段（如 ``phase="verify"``）。

    Returns:
        实际使用的 site 字符串（失败返回空串）。
    """
    try:
        exc = sys.exc_info()[1]
        exc_type = type(exc).__name__ if exc is not None else ""
        exc_msg = str(exc)[:300] if exc is not None else ""

        caller = ""
        try:
            frame = sys._getframe(1)
            caller = f"{os.path.basename(frame.f_code.co_filename)}:{frame.f_lineno}"
        except Exception:  # noqa: BLE001 - 取不到调用点不影响审计语义
            caller = ""

        resolved_site = site or caller
        event = {
            "kind": "suppressed_exception",
            "ts": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "site": resolved_site,
            "caller": caller,
            "type": exc_type,
            "message": exc_msg,
            "trace_id": get_trace_context(),
        }
        for k, v in extra.items():
            event[str(k)] = v

        # 1) 主日志（DEBUG 级，但信息量远超旧的固定文本）
        logger.debug(
            f"suppressed exception [{exc_type or '?'}] {resolved_site}: {exc_msg}")

        # 2) 结构化审计落盘（追加 JSONL；失败静默，不影响业务）
        try:
            with _SUPPRESSED_AUDIT_LOCK:
                with open(_SUPPRESSED_AUDIT_PATH, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        except Exception:  # noqa: BLE001 - 审计落盘失败绝不影响主流程
            pass
        return resolved_site
    except Exception:  # noqa: BLE001 - 审计自身也 fail-open
        return ""


def read_suppressed_audit(limit: int = 0) -> list:
    """读回被吞异常审计（离线排查/统计用）。

    Args:
        limit: 最多返回最近 N 条；0 表示全量。

    Returns:
        结构化事件列表（文件缺失/损坏返回已解析部分，不抛异常）。
    """
    out: list = []
    try:
        if not os.path.exists(_SUPPRESSED_AUDIT_PATH):
            return out
        with open(_SUPPRESSED_AUDIT_PATH, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:  # noqa: BLE001
        return out
    return out[-limit:] if limit and limit > 0 else out


# ===== 导出 =====
__all__ = ['logger', 'LOG_DIR', 'LOG_FILE', 'set_trace_context', 'get_trace_context', 'new_trace_id',
           'audit_suppressed', 'read_suppressed_audit']
