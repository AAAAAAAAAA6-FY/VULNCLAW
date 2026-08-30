# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""scan_main.py 的执行层适配模块。

R2 拆分后实现已迁移至 vulnclaw.runners.scan_runner，此处保持旧调用方完全兼容。
"""

from __future__ import annotations

import argparse

from vulnclaw.runners.scan_runner import main_async  # noqa: F401


async def run_scan(args: argparse.Namespace):
    """兼容别名，统一扫描入口。"""
    return await main_async(args)


__all__ = ["main_async", "run_scan"]
