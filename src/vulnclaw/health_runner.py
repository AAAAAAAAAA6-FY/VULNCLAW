# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""健康检查入口适配模块。

R2 拆分后实现已迁移至 vulnclaw.runners.health_runner，此处保持旧调用方兼容。
注意：run_health_check 为同步无参函数（scan_main.main 直接调用）。
"""

from vulnclaw.runners.health_runner import run_health_check  # noqa: F401

__all__ = ["run_health_check"]
