#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I.3 测试覆盖盘点（只盘点，不盲目堆测例）。

任务清单 v2 组 I：评审指出"测试覆盖未知"。本脚本回答三件事：
  1. tests/ 里现在有多少测试、分布在哪些文件；
  2. 82 个引擎中，有哪些**从未在任何测试里被提到**（覆盖 gap）；
  3. 关键治理/验证模块（danger_guard、verification_gateway、oob_channel 等）
     是否有对应测试。
输出 gap 报告，补齐项与 G.1（fixture/benchmark）联动——不重复造轮子。

用法：
    python scripts/test_coverage_audit.py
输出：
    docs/TEST_GAP.md
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SRC = ROOT / "src" / "vulnclaw"
OUT = ROOT / "docs" / "TEST_GAP.md"

# 关键模块（安全/正确性敏感，必须有测试覆盖）
KEY_MODULES = [
    "danger_guard", "verification_gateway", "oob_channel", "smart_queue",
    "rate_limiter", "tool_governance", "report_generator", "dedupe",
    "finding_lifecycle", "exploit_verify", "cost_router", "provider_failover",
    "target_capacity_probe", "adaptive_concurrency", "audit_receipt",
]


def _test_funcs(path: Path) -> list[str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:  # noqa: BLE001
        return []
    return [
        n.name
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test_")
    ]


def _engine_names() -> list[tuple[str, str, str]]:
    """(引擎 name, 文件, 类名)"""
    out: list[tuple[str, str, str]] = []
    if not (SRC / "engines").is_dir():
        return out
    for f in sorted((SRC / "engines").glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for st in node.body:
                if isinstance(st, ast.Assign):
                    for tg in st.targets:
                        if (
                            isinstance(tg, ast.Name)
                            and tg.id == "name"
                            and isinstance(st.value, ast.Constant)
                        ):
                            out.append((str(st.value.value), f.name, node.name))
    return out


def main() -> int:
    files = sorted(TESTS.glob("test_*.py"))
    per_file: dict[str, list[str]] = {}
    total = 0
    for f in files:
        names = _test_funcs(f)
        per_file[f.name] = names
        total += len(names)

    blob = "\n".join(
        f.read_text(encoding="utf-8", errors="replace") for f in files
    ) if files else ""

    engines = _engine_names()
    covered, gap = [], []
    for name, fname, cname in engines:
        if name and name in blob:
            covered.append((name, fname))
        else:
            gap.append((name, fname, cname))

    mod_cov = {m: (m in blob) for m in KEY_MODULES}

    lines = [
        "# 测试覆盖盘点与 gap 报告（I.3）",
        "",
        f"> 由 `scripts/test_coverage_audit.py` 生成，**只盘点不自动补测**。",
        f"> 统计口径：测试函数 = `tests/test_*.py` 中以 `test_` 开头的函数；",
        f"> 引擎覆盖 = 引擎注册名是否在任何测试文件中被提到（粗略但足以定位 gap）。",
        "",
        f"- 测试文件：**{len(files)}** 个",
        f"- 测试函数：**{total}** 个",
        f"- 引擎总数：**{len(engines)}** ｜ 有测试提及：**{len(covered)}** ｜ **未被提及：{len(gap)}**",
        "",
        "## 关键模块覆盖",
        "",
        "| 模块 | 是否有测试提及 |",
        "|---|---|",
    ]
    for m, ok in mod_cov.items():
        lines.append(f"| `{m}` | {'是' if ok else '**否**'} |")

    lines += [
        "",
        "## 测试分布（按文件）",
        "",
        "| 文件 | 测试函数数 |",
        "|---|---|",
    ]
    for fname, names in sorted(per_file.items(), key=lambda x: -len(x[1])):
        lines.append(f"| {fname} | {len(names)} |")

    lines += [
        "",
        f"## 引擎测试 gap（{len(gap)} 个从未被测试提及）",
        "",
        "| 引擎名 | 文件 | 类 |",
        "|---|---|---|",
    ]
    for name, fname, cname in gap[:60]:
        lines.append(f"| `{name}` | {fname} | {cname} |")
    if len(gap) > 60:
        lines.append(f"| ... | 其余 {len(gap) - 60} 个 | |")

    lines += [
        "",
        "## 补齐计划（与 G.1 联动，不重复造轮子）",
        "",
        "1. **引擎类 gap 优先用 G.1 的 fixture + benchmark 补**：`scripts/benchmark.py` "
        "已支持注入式 mock，给一个引擎加正反例只需在 `tests/fixtures/engines/` 加一个 YAML，"
        "无需真实靶场，也无需写 pytest 样板。",
        "2. **关键模块 gap 补单元测试**：上表标「否」的模块优先补（尤其 `danger_guard`、"
        "`verification_gateway`、`audit_receipt` 属安全与合规敏感路径）。",
        "3. **不盲目堆测例**：先补「能证明正确性」的最小集合，再随 bug 回归逐步增厚。",
        "",
    ]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"TEST_FILES={len(files)} TEST_FUNCS={total} ENGINES={len(engines)} GAP={len(gap)}")
    print(f"REPORT={OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
