#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""VULNCLAW finding 导出 CLI —— **薄封装** :mod:`vulnclaw.core.interop`（零重复渲染逻辑）。

用法：
    python -m scripts.exporters.cli --format sarif --input report.json --output report.sarif
    python -m scripts.exporters.cli --format csv  --input report.json          # stdout
    python -m scripts.exporters.cli --list-formats

输入约定（自动识别，二者皆可）：
    1) VULNCLAW 报告 JSON：取其中 ``vulnerabilities``（其次 ``findings`` / ``results``）；
    2) 直接的 finding 数组，或单个 finding 对象。

语义约定：
  * 导出**确定性**：同输入必然同输出（interop 保证，无时间戳/UUID/随机）；
  * 空输入 → 空清单（各格式的空表示），不是异常；
  * 未知格式 → 显式报错退出 1（不静默降级）。

退出码：0 成功；1 导出失败（格式不支持 / IO 错误）；2 参数错误。
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def _ensure_src_on_path() -> None:
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    src = os.path.join(root, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def extract_findings(data) -> list:
    """从报告 JSON / finding 数组 / 单条 finding 中提取 finding 列表（宽容，不抛错）。

    注意：空 dict（``{}``）或只有元信息（如 ``{"target": ...}``）**不算**单条 finding——
    否则会把空报告导出一条"全空字段"的假记录（测试抓到的真实缺陷）。
    """
    if isinstance(data, dict):
        for key in ("vulnerabilities", "findings", "results"):
            value = data.get(key)
            if isinstance(value, list):
                return value
        # 单条 finding：必须含可识别标识字段，否则视为空报告
        if any(data.get(k) for k in ("url", "type", "title", "finding_id")):
            return [data]
        return []
    if isinstance(data, list):
        return data
    return []


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scripts.exporters.cli",
        description="VULNCLAW finding → 外部格式（薄封装 core.interop）",
    )
    parser.add_argument("--format", "-f", help="目标格式（支持别名，见 --list-formats）")
    parser.add_argument("--input", "-i", default="-", help="输入文件（默认 - 读 stdin）")
    parser.add_argument("--output", "-o", default="-", help="输出文件（默认 - 写 stdout）")
    parser.add_argument("--list-formats", action="store_true", help="列出支持的格式名")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    _ensure_src_on_path()
    from vulnclaw.core.interop import EXPORTERS, export_any, resolve_format

    if args.list_formats:
        print("\n".join(sorted(EXPORTERS)))
        return 0
    if not args.format:
        print("错误：必须指定 --format（或 --list-formats 查看可选值）", file=sys.stderr)
        return 2
    try:
        text = sys.stdin.read() if args.input == "-" else open(args.input, encoding="utf-8").read()
    except OSError as exc:
        print(f"读取输入失败: {exc}", file=sys.stderr)
        return 1
    try:
        data = json.loads(text) if text.strip() else {}
    except json.JSONDecodeError as exc:
        print(f"输入不是合法 JSON: {exc}", file=sys.stderr)
        return 1

    findings = extract_findings(data)
    try:
        rendered = export_any(findings, args.format)
    except ValueError as exc:
        print(f"导出失败: {exc}", file=sys.stderr)
        return 1

    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        with open(args.output, "w", encoding="utf-8", newline="\n") as f:
            f.write(rendered)
        print(
            f"已导出 {len(findings)} 条 → {args.output}"
            f"（format={resolve_format(args.format)}，{len(rendered)} 字节）",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
