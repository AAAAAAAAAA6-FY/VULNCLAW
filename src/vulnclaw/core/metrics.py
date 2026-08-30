# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/metrics.py
"""R3 迁移兼容存根：实现已迁至 vulnclaw.core_modules.metrics。"""

from vulnclaw.core_modules.metrics import (  # noqa: F401
    Metrics,
    get_metrics,
    start_metrics_server,
)

__all__ = ['get_metrics', 'start_metrics_server', 'Metrics']
