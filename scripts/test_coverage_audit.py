#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""I.3 测试覆盖盘点（只盘点，不盲目堆测例）。

任务清单 v2 组 I：评审指出"测试覆盖未知"。本脚本回答三件事：
  1. tests/ 里现在有多少测试、分布在哪些文件；
  2. 静态引擎定义中，有哪些**从未在任何测试里被提到**（覆盖 gap）；
  3. 关键治理/验证模块（danger_guard、verification_gateway、oob_channel 等）
     是否有对应测试。
输出 gap 报告，补齐项与 G.1（fixture/benchmark）联动——不重复造轮子。

用法：
    python scripts/test_coverage_audit.py
输出：
    docs/TEST_GAP.md
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"
SRC = ROOT / "src" / "vulnclaw"
OUT = ROOT / "docs" / "TEST_GAP.md"
FIXTURES = ROOT / "tests" / "fixtures" / "engines"

# 关键模块（安全/正确性敏感，必须有测试覆盖）
KEY_MODULES = [
    "danger_guard", "verification_gateway", "oob_channel", "smart_queue",
    "rate_limiter", "tool_governance", "report_generator", "dedupe",
    "finding_lifecycle", "exploit_verify", "cost_router", "provider_failover",
    "target_capacity_probe", "adaptive_concurrency", "audit_receipt",
]


def _read_source(path: Path) -> str:
    """读取源码文本，**去掉 UTF-8 BOM**。

    踩过的坑（2026-09-15 定位）：带 BOM 的文件用 ``encoding="utf-8"`` 读出来首字符是
    U+FEFF，``ast.parse`` 会直接抛 ``SyntaxError: invalid non-printable character
    U+FEFF``——旧实现把这个异常静默吞成「0 个测试」，于是
    ``tests/test_httpbin_live.py``（实有 3 个用例）、``tests/test_js_triage.py``
    （实有 6 个用例）在全量盘点里长期显示为 0，报告数字被系统性低估。
    """
    return path.read_text(encoding="utf-8-sig", errors="replace")


def _test_funcs(path: Path) -> list[str]:
    try:
        tree = ast.parse(_read_source(path))
    except Exception as exc:  # noqa: BLE001
        # 不再静默：解析失败必须可见，否则「盘点为 0」会被误读成「没有测试」
        print(f"[warn] 解析失败（按 0 个测试计）: {path.name}: {type(exc).__name__}: {exc}",
              file=sys.stderr)
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
            tree = ast.parse(_read_source(f))
        except Exception as exc:  # noqa: BLE001
            print(f"[warn] 引擎文件解析失败（跳过）: {f.name}: {type(exc).__name__}: {exc}",
                  file=sys.stderr)
            continue
        class_bases = {
            node.name: {
                base.id for base in node.bases if isinstance(base, ast.Name)
            }
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
        }
        constants = {
            node.targets[0].id: node.value.value
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        }

        def is_engine_class(class_name: str, seen: set[str] | None = None) -> bool:
            seen = seen or set()
            if class_name in seen:
                return False
            seen.add(class_name)
            bases = class_bases.get(class_name, set())
            return "BaseEngine" in bases or any(is_engine_class(base, seen) for base in bases)

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not is_engine_class(node.name):
                continue
            for st in node.body:
                if isinstance(st, (ast.Assign, ast.AnnAssign)):
                    targets = st.targets if isinstance(st, ast.Assign) else [st.target]
                    value = st.value
                    for tg in targets:
                        if (
                            isinstance(tg, ast.Name)
                            and tg.id == "name"
                            and (
                                (isinstance(value, ast.Constant) and isinstance(value.value, str))
                                or (isinstance(value, ast.Name) and value.id in constants)
                            )
                        ):
                            resolved = value.value if isinstance(value, ast.Constant) else constants[value.id]
                            out.append((resolved, f.name, node.name))
    return out


def _deep_test_blob(files: list[Path]) -> str:
    """收集"深度测试"源码片段。

    DEPTH 口径（组 D）：
      1) pytest 侧：测试名含 "_deep_" 的函数视为深度测试；命名即承诺——
         其函数体必须同时包含 evidence 断言与 payload/reproduction 复现断言
         （两标记任缺其一不计入深度，防止只改名不改内容）；
      2) fixture 侧：expect=positive 且同时带非空 evidence_contains 与
         reproduction 字段的 case，映射回 fixture 顶层 engine 名。
      DEPTH = 两个口径覆盖到的去重引擎数（名义覆盖已满时的"含金量"指标）。
    """
    parts: list[str] = []
    for f in files:
        text = f.read_text(encoding="utf-8", errors="replace")
        try:
            tree = ast.parse(text)
        except Exception:  # noqa: BLE001
            continue
        src_lines = text.splitlines()
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if "_deep_" not in node.name:
                continue
            seg = "\n".join(
                src_lines[node.lineno - 1: node.end_lineno or node.lineno]
            )
            # "_deep_positive(...)" 助手内部固定执行 evidence+payload 复现断言，
            # 调用它即视为满足深度口径
            has_evidence = "evidence" in seg or "_deep_positive(" in seg
            has_repro = (
                "payload" in seg or "reproduction" in seg or "_deep_positive(" in seg
            )
            if has_evidence and has_repro:
                parts.append(seg)
    return "\n".join(parts)


def _fixture_deep_engines() -> set[str]:
    """fixture 侧深度口径：正例 case 同时带 evidence_contains + reproduction。"""
    out: set[str] = set()
    if not FIXTURES.is_dir():
        return out
    import yaml  # 局部导入：保持脚本可独立运行

    for y in sorted(FIXTURES.glob("*.yaml")):
        try:
            data = yaml.safe_load(y.read_text(encoding="utf-8")) or {}
        except Exception:  # noqa: BLE001
            continue
        engine_name = str(data.get("engine") or data.get("class") or "")
        if not engine_name:
            continue
        for case in data.get("cases") or []:
            if not isinstance(case, dict):
                continue
            if (
                str(case.get("expect") or "") == "positive"
                and str(case.get("evidence_contains") or "").strip()
                and str(case.get("reproduction") or "").strip()
            ):
                out.add(engine_name)
                break
    return out


def main() -> int:
    files = sorted(TESTS.glob("test_*.py"))
    per_file: dict[str, list[str]] = {}
    total = 0
    for f in files:
        names = _test_funcs(f)
        per_file[f.name] = names
        total += len(names)

    blob = "\n".join(_read_source(f) for f in files) if files else ""

    engines = _engine_names()
    covered, gap = [], []
    for name, fname, cname in engines:
        if name and name in blob:
            covered.append((name, fname))
        else:
            gap.append((name, fname, cname))

    mod_cov = {m: (m in blob) for m in KEY_MODULES}

    # ---- DEPTH：含 evidence+reproduction 深度断言的引擎数（口径见函数 docstring）----
    # pytest 侧按引擎类名匹配（精确，避免 'session' 这类常见词被测试参数名误匹配）
    deep_blob = _deep_test_blob(files)
    depth_engines = {
        name for name, _fname, cname in engines
        if cname and cname in deep_blob
    }
    depth_engines |= {e for e in _fixture_deep_engines() if e}
    depth = len(depth_engines)

    lines = [
        "# 测试覆盖盘点与 gap 报告（I.3）",
        "",
        f"> 由 `scripts/test_coverage_audit.py` 生成，**只盘点不自动补测**。",
        f"> 统计口径：测试函数 = `tests/test_*.py` 中以 `test_` 开头的函数；",
        f"> 引擎覆盖 = 引擎注册名是否在任何测试文件中被提到（粗略但足以定位 gap）。",
        f"> 注意：这里统计静态引擎定义；继承名称、模块常量名称或动态注册可能不在 "
        f"静态表中。运行时实例化/启用数量以扫描报告的 `engine_inventory` 为准。",
        "",
        f"- 测试文件：**{len(files)}** 个",
        f"- 测试函数：**{total}** 个",
        f"- 引擎总数：**{len(engines)}** ｜ 有测试提及：**{len(covered)}** ｜ **未被提及：{len(gap)}**",
        f"- 深度覆盖（DEPTH）：**{depth}** 个引擎有 evidence+reproduction 深度断言"
        f"（口径：pytest `*_deep_*` 测试含 evidence/payload 断言，或 fixture 正例带"
        f"非空 `evidence_contains`+`reproduction`）",
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
    args = _parse_args()
    if not args.stdout_only:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text("\n".join(lines), encoding="utf-8")
        print(f"REPORT={OUT}")
    print(
        f"TEST_FILES={len(files)} TEST_FUNCS={total} ENGINES={len(engines)} "
        f"GAP={len(gap)} DEPTH={depth}"
    )
    return 0


def _parse_args():
    ap = argparse.ArgumentParser(description="测试覆盖盘点（I.3）")
    ap.add_argument(
        "--stdout-only", action="store_true",
        help="只打印统计，不写 docs/TEST_GAP.md（文档清理期间避免重建已删除的报告）",
    )
    return ap.parse_args()


if __name__ == "__main__":
    sys.exit(main())
