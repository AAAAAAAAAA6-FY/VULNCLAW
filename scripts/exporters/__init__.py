# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""VULNCLAW finding 导出器（**薄封装**）。

实现全部在 :mod:`vulnclaw.core.interop`（UnifiedFinding → 各格式纯函数渲染，
含 lossless 扩展位与 ``FIELD_MAPPING``），本包**只做统一入口 re-export 与文档**，
刻意不重复任何渲染逻辑。

支持的格式（``--format`` 取值，见 ``EXPORTERS``）：
    jsonl / vulnclaw_json / csv / sarif / nuclei_jsonl / burp_xml / markdown

CLI 用法：
    python -m scripts.exporters.cli --format sarif --input report.json --output report.sarif
    python -m scripts.exporters.cli --format csv --input report.json          # 输出到 stdout
    python -m scripts.exporters.cli --list-formats

输入约定：VULNCLAW 报告 JSON（取 ``vulnerabilities``）或直接是 finding 数组；
两者皆可，自动识别（见 CLI 实现）。
"""
import os
import sys


def _ensure_src_on_path() -> None:
    """允许未 pip install 直接运行：``python -m scripts.exporters.cli`` 会**先导入本包**
    （runpy 语义），因此 src 路径处理必须放在 ``__init__`` 顶部——放进 CLI.main 里就太晚了
    （实测会在 re-export 处抛 ModuleNotFoundError）。
    """
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    src = os.path.join(root, "src")
    if os.path.isdir(src) and src not in sys.path:
        sys.path.insert(0, src)


_ensure_src_on_path()

from vulnclaw.core.interop import (  # noqa: E402,F401 - 统一 re-export（薄）
    EXPORTERS,
    export_any,
    export_burp_xml,
    export_csv,
    export_jsonl,
    export_markdown,
    export_nuclei_jsonl,
    export_sarif,
    export_vulnclaw_json,
    resolve_format,
    to_unified_dicts,
)

__all__ = [
    "EXPORTERS",
    "export_any",
    "export_burp_xml",
    "export_csv",
    "export_jsonl",
    "export_markdown",
    "export_nuclei_jsonl",
    "export_sarif",
    "export_vulnclaw_json",
    "resolve_format",
    "to_unified_dicts",
]
