# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/alerting.py
"""R3 迁移兼容存根：实现已迁至 vulnclaw.core_modules.alerting。"""

from vulnclaw.core_modules.alerting import (  # noqa: F401
    AlertSender,
    get_alert_sender,
    send_alert,
)

__all__ = ['AlertSender', 'get_alert_sender', 'send_alert']
