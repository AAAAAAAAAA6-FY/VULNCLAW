# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""外部扫描器结果导入器（**薄封装**）。

实现全部在 :mod:`vulnclaw.core.interop`（UnifiedFinding + 每个格式的纯函数解析器 +
``FIELD_MAPPING`` + fail-closed 跳过计数），本包**只做统一入口 re-export 与文档**，
刻意不重复任何解析逻辑——避免"同一格式两处实现"的漂移。

支持的格式（``--format`` 取值，见 ``IMPORTERS``）：
    nuclei_jsonl / jsonl / vulnclaw_json / burp_xml / zap_json / sarif / csv / raw_http

CLI 用法：
    python -m scripts.importers.cli --format nuclei_jsonl --input nuclei.jsonl --output unified.json
    python -m scripts.importers.cli --list-formats

说明：``scripts/`` 为隐式命名空间包（无 __init__ 亦可 `-m` 运行）；CLI 内部自行把
项目 ``src`` 加入 ``sys.path``，不要求先 pip install。
"""
import os
import sys


def _ensure_src_on_path() -> None:
    """允许未 pip install 直接运行：``python -m scripts.importers.cli`` 会**先导入本包**
    （runpy 语义），因此 src 路径处理必须放在 ``__init__`` 顶部——放进 CLI.main 里就太晚了
    （实测会在 re-export 处抛 ModuleNotFoundError）。
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    src = os.path.join(root, "src")
    if os.path.isdir(src) and src not in sys.path:
        sys.path.insert(0, src)


_ensure_src_on_path()

from vulnclaw.core.interop import (  # noqa: E402,F401 - 统一 re-export（薄）
    IMPORTERS,
    ImportResult,
    import_any,
    import_burp_xml,
    import_csv,
    import_jsonl,
    import_nuclei_jsonl,
    import_raw_http,
    import_sarif,
    import_vulnclaw_json,
    import_zap_json,
    resolve_format,
    to_unified_dicts,
)

__all__ = [
    "IMPORTERS",
    "ImportResult",
    "import_any",
    "import_burp_xml",
    "import_csv",
    "import_jsonl",
    "import_nuclei_jsonl",
    "import_raw_http",
    "import_sarif",
    "import_vulnclaw_json",
    "import_zap_json",
    "resolve_format",
    "to_unified_dicts",
]
