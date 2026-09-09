#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""G.2 边缘引擎盘点（只出报告，不改代码）。

依据任务清单 v2 组 G "先测后砍"：DeepSeek 建议砍掉 70% 引擎，但直接删违反
质量红线（no benchmark degradation）。故先做静态盘点，输出每个引擎的：
  - 引用次数（src 全量代码中该引擎名出现次数）
  - 近 N 次扫描命中数（从最近报告 json 的 finding 反查）
  - 维护复杂度（引擎类代码行数评级）
  - 处置建议（可下线候选 / 需补样本 / 保留）
由人决定是否下线，脚本绝不自动删除任何引擎。

用法：
    python scripts/engine_audit.py [--top N] [--reports 3]
输出：
    docs/engine_disposition_report.md
"""
from __future__ import annotations

import argparse
import ast
import glob
import json
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "vulnclaw"
ENG = SRC / "engines"
DOCS = ROOT / "docs"
REPORT_PATH = DOCS / "engine_disposition_report.md"

# 引擎名在 yaml/配置里也可能出现，一并统计
EXTRA_SCAN_DIRS = [SRC / "core" / "data"]

# 【重要修正】local_lab 靶场真值实际覆盖的漏洞类别关键词。
# 当前唯一可用靶场只覆盖这些类别；**不在此列的引擎在该靶场上永远不可能命中**，
# 其"零命中"属于靶场覆盖偏差，**绝不能据此判定引擎无用**。
LAB_COVERED_KEYWORDS = (
    "xss", "sqli", "sql", "ssti", "nosql", "ldap", "deser", "upload",
    "env", "cors", "redirect", "cmdi", "lfi", "rfi", "crlf", "leak",
    "serial", "template", "inject",
)


def lab_covered(name: str) -> bool:
    """该引擎的漏洞类别是否落在 local_lab 靶场真值覆盖范围内。

    返回 False 表示该引擎在现有靶场上**无法被评估**（不是它无用），
    必须补对应场景的 fixture 才能判定（对应任务卡 G.1）。
    """
    n = (name or "").lower()
    return any(k in n for k in LAB_COVERED_KEYWORDS)


def iter_engine_classes() -> list[dict]:
    """解析 engines/*.py 中所有类，提取 name 属性（引擎注册名）与代码行数。"""
    out: list[dict] = []
    if not ENG.is_dir():
        return out
    for f in sorted(ENG.glob("*.py")):
        if f.name.startswith("_"):
            continue
        try:
            tree = ast.parse(f.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001 - 单文件解析失败不阻断盘点
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            nm = None
            for st in node.body:
                if isinstance(st, ast.Assign):
                    for t in st.targets:
                        if isinstance(t, ast.Name) and t.id == "name" and isinstance(st.value, ast.Constant):
                            nm = st.value.value
            bases = [b.id for b in node.bases if isinstance(b, ast.Name)]
            lines = (node.end_lineno or node.lineno or 0) - (node.lineno or 0) + 1
            out.append({
                "file": f.name,
                "class": node.name,
                "name": nm or node.name,
                "bases": bases,
                "lines": lines,
            })
    return out


def build_ref_index() -> dict[str, int]:
    """统计每个引擎名在 src（含 data 配置）中的出现次数。"""
    texts: list[str] = []
    for p in list(SRC.rglob("*.py")) + [q for d in EXTRA_SCAN_DIRS for q in d.rglob("*.yaml")]:
        try:
            texts.append(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:  # noqa: BLE001
            continue
    blob = "\n".join(texts)
    return blob


def count_refs(blob: str, name: str) -> int:
    if not name:
        return 0
    return len(re.findall(rf"\b{re.escape(name)}\b", blob))


def load_recent_hits(n: int) -> tuple[dict[str, int], list[str]]:
    """从最近 n 份报告统计引擎命中数（finding 的 engine/source/type 字段）。"""
    paths = sorted(
        glob.glob(str(ROOT / "_runtime_cache" / "reports" / "report_*.json")),
        key=os.path.getmtime, reverse=True,
    )[:n]
    hits: dict[str, int] = {}
    for p in paths:
        try:
            d = json.load(open(p, encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        vs = d.get("vulnerabilities") or d.get("findings") or []
        for v in vs or []:
            if not isinstance(v, dict):
                continue
            for key in ("engine", "source", "type", "rule_id", "ruleId"):
                val = str(v.get(key) or "").strip()
                if val:
                    hits[val] = hits.get(val, 0) + 1
                    break
    return hits, [os.path.basename(p) for p in paths]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", type=int, default=3, help="参考最近几份扫描报告（默认 3）")
    args = ap.parse_args()

    engines = iter_engine_classes()
    if not engines:
        print("NO_ENGINE_FOUND")
        return 2
    blob = build_ref_index()
    hits, report_files = load_recent_hits(max(1, args.reports))

    rows = []
    for e in engines:
        name = str(e["name"])
        refs = count_refs(blob, name)
        # 命中：报告里的 engine/source/type 值包含该引擎名（大小写不敏感）
        h = sum(c for k, c in hits.items() if name.lower() in k.lower())
        lines = int(e["lines"])
        cx = "高" if lines > 400 else ("中" if lines > 150 else "低")
        # 【修正后的判据】
        # 1) 有命中 → 保留（已验证有效）
        # 2) 零命中但该类别不在靶场覆盖范围 → 靶场未覆盖，禁止判死（需补 fixture）
        # 3) 零命中且类别被覆盖 → 需补样本/存疑（可能是真弱，也可能是靶场样例不够典型）
        # 说明：引用数不再作为"无用"证据——引擎靠 glob 自动发现 + ENGINE_REGISTRY
        #      注册，引用少属正常现象，不能反推没人用。
        covered = lab_covered(name)
        if h > 0:
            verdict = "保留"
        elif not covered:
            verdict = "靶场未覆盖·不可判死"
        else:
            verdict = "需补样本/存疑"
        rows.append({**e, "refs": refs, "hits": h, "complexity": cx,
                     "verdict": verdict, "covered": covered})

    rows.sort(key=lambda r: (r["hits"], r["refs"]))

    DOCS.mkdir(parents=True, exist_ok=True)
    total = len(rows)
    cand = [r for r in rows if r["verdict"] == "靶场未覆盖·不可判死"]
    nosample = [r for r in rows if r["verdict"] == "需补样本/存疑"]
    keep = [r for r in rows if r["verdict"] == "保留"]

    lines_md = [
        "# 边缘引擎处置建议（G.2 盘点报告）",
        "",
        f"生成时间：{__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
        f"盘点引擎总数：**{total}** ｜ 靶场未覆盖·不可判死：**{len(cand)}** ｜ "
        f"需补样本/存疑：**{len(nosample)}** ｜ 保留：**{len(keep)}**  ",
        f"命中统计参考报告：{', '.join(report_files) if report_files else '(无报告)'}",
        "",
        "> 本报告由 `scripts/engine_audit.py` 生成，**只出报告不改代码**。",
        "",
        "> ## ⚠️ 方法局限（必读）",
        ">",
        "> 1. **零命中 ≠ 引擎无用**。当前唯一可用靶场是 local_lab，只覆盖 XSS/SQLi/SSTI/"
        "LFI/CMDI/NoSQL/LDAP/反序列化/.env/重定向/CORS/上传 等十余类；",
        ">    Fastjson、Struts2、Shiro、Solr、Nacos、Confluence、JSONP、XPath 等引擎在该靶场上"
        "**永远不可能命中**，属靶场覆盖偏差。",
        "> 2. **引用数少 ≠ 没人用**。引擎靠 glob 自动发现 + `ENGINE_REGISTRY` 按 name 注册，"
        "无需显式引用，引用数不再作为「无用」证据。",
        "> 3. 因此**本报告不产出任何「可下线」结论**。判定去留必须先有对应场景的 fixture"
        " 与检出率基线（任务卡 G.1），在此之前一律保留。",
        "",
        "## 汇总",
        "",
        "| 分类 | 数量 | 说明 |",
        "|---|---|---|",
        f"| 靶场未覆盖·不可判死 | {len(cand)} | 现有靶场无法评估，需先补场景 fixture（G.1） |",
        f"| 需补样本/存疑 | {len(nosample)} | 类别被靶场覆盖但零命中，可能是引擎弱或样例不典型 |",
        f"| 保留 | {len(keep)} | 近期有命中，确认有效 |",
        f"| 可下线结论 | **0** | 无足够依据，**不建议下线任何引擎** |",
        "",
        "## 明细",
        "",
        "| 引擎名 | 类 | 文件 | 引用数 | 近扫描命中 | 代码行 | 复杂度 | 建议 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines_md.append(
            f"| `{r['name']}` | {r['class']} | {r['file']} | {r['refs']} | {r['hits']} | "
            f"{r['lines']} | {r['complexity']} | {r['verdict']} |"
        )
    lines_md += [
        "",
        "## 下一步",
        "",
        "1. '需补样本' 项先由 G.1 补正反例 fixture，跑出真实检出率再决定去留。",
        "2. 本报告**不产出任何「可下线」结论**：判定引擎去留必须先有对应场景的 fixture"
        " 与检出率基线（G.1），在此之前一律保留，脚本也不会自动删除。",
        "3. 任何下线动作后需重跑 8090/8091 靶场，确认检出基线不回退。",
        "",
    ]
    REPORT_PATH.write_text("\n".join(lines_md), encoding="utf-8")
    print(f"ENGINES={total} CANDIDATE={len(cand)} NOSAMPLE={len(nosample)} KEEP={len(keep)}")
    print(f"REPORT={REPORT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
