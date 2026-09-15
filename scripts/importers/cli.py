#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""外部扫描器结果导入 CLI —— **薄封装** :mod:`vulnclaw.core.interop`（零重复解析逻辑）。

用法：
    python -m scripts.importers.cli --format nuclei_jsonl --input nuclei.jsonl --output unified.json
    python -m scripts.importers.cli --format sarif --input in.sarif            # 输出到 stdout
    python -m scripts.importers.cli --list-formats

输出 JSON 结构（确定性序列化）：
    {"format": <归一格式>, "imported": N, "skipped_count": M, "errors_count": K,
     "findings": [<统一模型 UnifiedFinding.to_dict()>...]}

语义约定（与 interop 保持一致，本 CLI 不做任何"修补"）：
  * fail-closed：解析失败/缺关键字段的记录由 interop **跳过并计数**，绝不编造字段；
  * 未知格式 → 显式报错退出 1（不静默降级）；
  * ``to_unified_dicts`` 做最终归一，保证输出与 ``finding_schema`` 字段口径一致。

退出码：0 成功；1 导入失败（格式不支持 / IO 错误）；2 参数错误。
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def _ensure_src_on_path() -> None:
    """允许未 pip install 直接 `python -m scripts.importers.cli` 运行。"""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def _count(value) -> int:
    """宽容计数：列表 → len；整数 → 原值；其它 → 0（绝不因统计字段抛错）。"""
    try:
        return len(value)
    except TypeError:
        try:
            return int(value)
        except (TypeError, ValueError):
            return 0


def _read_input(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts.importers.cli",
        description="外部扫描器结果 → VULNCLAW 统一模型（薄封装 core.interop）",
    )
    parser.add_argument("--format", "-f", help="输入格式（支持别名，见 --list-formats）")
    parser.add_argument("--input", "-i", default="-", help="输入文件（默认 - 读 stdin）")
    parser.add_argument("--output", "-o", default="-", help="输出文件（默认 - 写 stdout）")
    parser.add_argument("--list-formats", action="store_true", help="列出支持的格式名")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _ensure_src_on_path()
    from vulnclaw.core.interop import IMPORTERS, import_any, resolve_format, to_unified_dicts

    if args.list_formats:
        print("\n".join(sorted(IMPORTERS)))
        return 0
    if not args.format:
        print("错误：必须指定 --format（或 --list-formats 查看可选值）", file=sys.stderr)
        return 2
    try:
        text = _read_input(args.input)
    except OSError as exc:
        print(f"读取输入失败: {exc}", file=sys.stderr)
        return 1
    try:
        result = import_any(text, args.format)
    except ValueError as exc:
        print(f"导入失败: {exc}", file=sys.stderr)
        return 1

    payload = {
        "format": resolve_format(args.format),
        "imported": len(result),
        "skipped_count": _count(getattr(result, "skipped", None)),
        "errors_count": _count(getattr(result, "errors", None)),
        "findings": to_unified_dicts(result),
    }
    text_out = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(text_out)
    else:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(text_out)
        print(
            f"已导入 {payload['imported']} 条"
            f"（跳过 {payload['skipped_count']}）→ {args.output}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
