# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""health 命令适配层：转发 scan_main 的 --health 检查。"""
from __future__ import annotations

import sys

import vulnclaw.bootstrap  # noqa: F401
from vulnclaw.paths import PROJECT_ROOT


def run_health() -> None:
    sys.argv = [str(PROJECT_ROOT / "scan.py"), "--health"]
    import vulnclaw.scan_main as _sm
    _sm.main()
