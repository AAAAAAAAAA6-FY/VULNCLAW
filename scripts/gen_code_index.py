#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I.2 编号索引地图（只索引不解释）。

任务清单 v2：项目中大量使用 SP*/A*/C*/D*/E* 编号（如 SP15.3、A4.4、D4.2、E5.2），
但全项目没有索引，导致"编号→文件→含义"全靠口口相传。本脚本扫描 src 下所有
Python 文件，抽取编号及其上下文，生成 docs/CODE_INDEX.md 索引表。

原则：**只索引不解释**——不臆测编号含义，只记录它在哪、上下文那一行写了什么。
未来写设计文档时再逐个补说明。

用法：
    python scripts/gen_code_index.py
输出：
    docs/CODE_INDEX.md
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "vulnclaw"
OUT = ROOT / "docs" / "CODE_INDEX.md"

# SP15.3 / A4.4 / C1 / D4.2 / E5.2 —— 大写前缀 + 数字（可含点分小版本）
PAT = re.compile(r"\b(SP|A|C|D|E)(\d+(?:\.\d+)*)\b")

# 明显的噪声（版本号、HTTP 状态等）不算编号
NOISE = {"200", "404", "500", "403", "401", "429"}


def scan() -> dict[str, list[tuple[str, int, str]]]:
    idx: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for f in sorted(SRC.rglob("*.py")):
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:  # noqa: BLE001 - 单文件读取失败不阻断索引
            continue
        rel = str(f.relative_to(ROOT)).replace("\\", "/")
        for i, ln in enumerate(lines, 1):
            for m in PAT.finditer(ln):
                code = f"{m.group(1)}{m.group(2)}"
                if m.group(1) != "SP" and m.group(2) in NOISE:
                    continue
                ctx = ln.strip()
                # 去掉行首注释符号，保留语义
                ctx = re.sub(r"^[#\s]*", "", ctx)
                idx[code].append((rel, i, ctx[:140]))
    return idx


def main() -> int:
    idx = scan()
    if not idx:
        print("NO_CODE_FOUND")
        return 2

    def sort_key(code: str):
        prefix = re.match(r"[A-Z]+", code).group(0)
        try:
            num = float(re.sub(r"[A-Z]+", "", code) or 0)
        except ValueError:
            num = 0.0
        return (prefix, num)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# 编号索引地图（CODE_INDEX）",
        "",
        "> 由 `scripts/gen_code_index.py` 自动生成，**只索引不解释**。",
        "> 表中「上下文」直接取代码里出现该编号的那一行原文（截断 140 字符），不做臆测。",
        "> 未来写设计文档时，按此表逐个补「编号含义」。",
        "",
        f"共收录编号 **{len(idx)}** 个，累计引用 **{sum(len(v) for v in idx.values())}** 处。",
        "",
        "| 编号 | 出现次数 | 首次出现（文件:行） | 上下文（原文截断） |",
        "|---|---|---|---|",
    ]
    for code in sorted(idx, key=sort_key):
        refs = idx[code]
        first = f"{refs[0][0]}:{refs[0][1]}"
        ctx = refs[0][2].replace("|", "\\|")
        lines.append(f"| `{code}` | {len(refs)} | {first} | {ctx} |")

    lines += [
        "",
        "## 使用说明",
        "",
        "- 重跑：`python scripts/gen_code_index.py`（幂等，覆盖重写本文件）。",
        "- 新增编号时无需手工登记，脚本自动收录。",
        "- 含义解释请补在对应设计文档中，不要改本表（本表只做索引）。",
        "",
    ]
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"CODES={len(idx)} REFS={sum(len(v) for v in idx.values())}")
    print(f"OUT={OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
