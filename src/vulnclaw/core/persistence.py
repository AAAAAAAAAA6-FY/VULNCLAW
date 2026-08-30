# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/persistence.py
"""R3 迁移兼容存根：实现已迁至 vulnclaw.core_modules.persistence。"""

from vulnclaw.core_modules.persistence import (  # noqa: F401
    CorrelationEngine,
    IncrementalSaver,
    ScanState,
    get_correlation_engine,
    get_incremental_saver,
    CHECKPOINT_VERSION,
    CHECKPOINT_EXPIRE_DAYS,
)

__all__ = [
    'ScanState',
    'IncrementalSaver',
    'CorrelationEngine',
    'get_incremental_saver',
    'get_correlation_engine',
    'CHECKPOINT_VERSION',
    'CHECKPOINT_EXPIRE_DAYS',
]
