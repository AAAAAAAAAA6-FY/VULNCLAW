# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""R3 迁移完成：cache/metrics/alerting/persistence 的实现源。

core 下对应旧文件已改为存根转发到本包；本包内模块依赖 core.logger /
core.settings（转发 config.settings），无循环依赖。
"""

from vulnclaw.core_modules.cache import CacheBackend, FileCache, MemoryCache, cache, get_cache
from vulnclaw.core_modules.metrics import Metrics, get_metrics, start_metrics_server
from vulnclaw.core_modules.alerting import AlertSender, get_alert_sender, send_alert
from vulnclaw.core_modules.persistence import ScanState, CHECKPOINT_VERSION, CHECKPOINT_EXPIRE_DAYS

__all__ = [
    "CacheBackend",
    "FileCache",
    "MemoryCache",
    "cache",
    "get_cache",
    "Metrics",
    "get_metrics",
    "start_metrics_server",
    "AlertSender",
    "get_alert_sender",
    "send_alert",
    "ScanState",
    "CHECKPOINT_VERSION",
    "CHECKPOINT_EXPIRE_DAYS",
]
