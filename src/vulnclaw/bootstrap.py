# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""环境固化 - 禁止字节码/外部工具垃圾再生。所有入口统一 import。"""
from __future__ import annotations

import os
import sys

sys.dont_write_bytecode = True
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

from vulnclaw.paths import TOOLS_HOME  # noqa: E402

_TOOLS_HOME = str(TOOLS_HOME)
for _sub in ("nuclei", "uncover"):
    (TOOLS_HOME / _sub).mkdir(parents=True, exist_ok=True)
os.environ["HOME"] = _TOOLS_HOME
os.environ["USERPROFILE"] = _TOOLS_HOME
os.environ["NUCLEI_CONFIG_DIR"] = str(TOOLS_HOME / "nuclei")
os.environ["UNCOVER_CONFIG_DIR"] = str(TOOLS_HOME / "uncover")
os.environ.setdefault("GITHUB_ACTIONS_FORCE_COLORS", "0")

if sys.platform.startswith("win"):
    for _name in ("stdout", "stderr"):
        _stream = getattr(sys, _name, None)
        try:
            if _stream is not None and hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    os.environ.setdefault("TQDM_DISABLE", "1")
    os.environ.setdefault("FORCE_COLOR", "0")
