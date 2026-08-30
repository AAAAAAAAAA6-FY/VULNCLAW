# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""路径单源 - 所有运行时路径的唯一出处（防回退核心）。"""
from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

RUNTIME_DIR = PROJECT_ROOT / "_runtime_cache"
REPORT_DIR = RUNTIME_DIR / "reports"
COOKIE_DIR = RUNTIME_DIR / "cookies"
POC_DIR = RUNTIME_DIR / "pocs"
LOG_DIR = RUNTIME_DIR / "logs"
TOOLS_HOME = RUNTIME_DIR / "tools"
ARCHIVE_DIR = RUNTIME_DIR / "archives"
DEBUG_DIR = RUNTIME_DIR / "debug"
THIRDPARTY_DIR = PROJECT_ROOT / "thirdparty"


def ensure_runtime_dirs() -> None:
    for d in (RUNTIME_DIR, REPORT_DIR, COOKIE_DIR, POC_DIR, LOG_DIR, TOOLS_HOME, ARCHIVE_DIR):
        d.mkdir(parents=True, exist_ok=True)
