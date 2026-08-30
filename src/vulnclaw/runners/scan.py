# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Scan runner facade（R2 拆分后指向 vulnclaw.runners.scan_runner）。"""

from vulnclaw.runners.scan_runner import main_async

run_scan = main_async

__all__ = ["main_async", "run_scan"]
