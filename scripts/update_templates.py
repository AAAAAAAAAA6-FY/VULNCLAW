#!/usr/bin/env python3
"""Nuclei 模板质量过滤工具（v105，任务 4）

只保留高质量模板（severity ∈ critical/high/medium），移除 low/info 与无
severity 字段的模板，降低扫描误报率。

默认 dry-run 打印统计；加 --apply 才会实际删除低质量模板。

用法:
    python scripts/update_templates.py [--dir thirdparty/nuclei-templates] [--apply]
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    print("缺少 PyYAML 依赖，请先执行: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

DEFAULT_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "thirdparty" / "nuclei-templates"
KEEP_SEVERITIES = ("critical", "high", "medium")
# 无 severity 语义的目录（workflows 编排、profiles 等）不参与质量过滤
SKIP_DIRS = {"workflows", "profiles", "helpers", "headless", "javascript"}


def filter_high_quality(
    template_dir: str | Path,
    keep: tuple = KEEP_SEVERITIES,
    skip_dirs: set = SKIP_DIRS,
) -> tuple:
    """过滤模板：只保留 severity ∈ keep 的高质量模板。

    Args:
        template_dir: nuclei 模板根目录。
        keep: 保留的 severity 集合（小写）。
        skip_dirs: 不参与过滤的子目录名。

    Returns:
        (kept_paths, removed_paths, stats)：
            kept_paths    保留的模板相对路径列表；
            removed_paths 被过滤掉的模板相对路径列表；
            stats         统计 dict（total/kept/removed/removed_pct/severity_counts）。
    """
    root = Path(template_dir)
    kept: list[str] = []
    removed: list[str] = []
    severity_counts: Counter = Counter()

    for path in sorted(root.rglob("*.yaml")):
        rel = path.relative_to(root)
        if any(part in skip_dirs for part in rel.parts):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                data = yaml.safe_load(f)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue

        info = data.get("info") or {}
        severity = str(info.get("severity", "")).strip().lower()
        if severity:
            severity_counts[severity] += 1
        if severity in keep:
            kept.append(str(rel))
        else:
            removed.append(str(rel))

    total = len(kept) + len(removed)
    removed_pct = round((len(removed) / total) * 100, 1) if total else 0.0
    stats = {
        "total": total,
        "kept": len(kept),
        "removed": len(removed),
        "removed_pct": removed_pct,
        "severity_counts": dict(severity_counts.most_common()),
    }
    return kept, removed, stats


def sync_cve_index(
    template_dir: str | Path | None = None,
) -> dict:
    """Z1.3：比对上游新 CVE 模板并增量入库（新模板随后可被 Z1.1 索引收录）。

    复用 Z1.1 的 CVE 索引构建器；幂等，无新增模板时返回 added=0。
    """
    project_root = DEFAULT_TEMPLATE_DIR.parent.parent  # 项目根
    index_dir = DEFAULT_TEMPLATE_DIR / "cve_index"
    cve_dir = Path(template_dir) if template_dir else (DEFAULT_TEMPLATE_DIR / "http" / "cves")

    # 引导 src 到 path，以便导入 vulnclaw
    import sys as _sys

    for p in (project_root / "src", project_root / "src" / "vulnclaw"):
        if str(p) not in _sys.path:
            _sys.path.insert(0, str(p))

    try:
        from vulnclaw.core.data import cve_index_builder as _b
    except Exception as exc:  # pragma: no cover
        return {"added": 0, "error": f"CVE 索引模块导入失败: {exc}"}

    if cve_dir.is_dir():
        new_entries = [
            rec for rec in (_b.parse_cve_template(str(p)) for p in cve_dir.rglob("*.yaml"))
            if rec is not None
        ]
    else:
        new_entries = []

    idx = _b.CVEIndex(index_dir=str(index_dir))
    added = idx.ingest_records(new_entries)
    idx.load()
    out = {
        "added": added,
        "extra_total": len(idx._load_extra_records()),
        "index_total": idx.count,
    }
    print(
        f"CVE 情报增量同步完成: 扫描模板 {len(new_entries)}，"
        f"新增入库 {out['added']}，累计增量 {out['extra_total']}，索引总数 {out['index_total']}"
    )
    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="Nuclei 模板质量过滤（只保留 critical/high/medium）")
    parser.add_argument("--dir", default=str(DEFAULT_TEMPLATE_DIR), help="nuclei 模板根目录")
    parser.add_argument("--apply", action="store_true", help="实际删除低质量模板（默认仅统计）")
    parser.add_argument("--keep", nargs="+", default=list(KEEP_SEVERITIES), help="保留的 severity 集合")
    parser.add_argument("--sync-cve-index", action="store_true",
                        help="Z1.3：增量比对上游新 CVE 模板并入库（不执行质量过滤）")
    args = parser.parse_args()

    if args.sync_cve_index:
        cve_dir = Path(args.dir) / "http" / "cves"
        sync_cve_index(template_dir=cve_dir)
        return

    root = Path(args.dir)
    if not root.is_dir():
        print(f"模板目录不存在: {root}", file=sys.stderr)
        sys.exit(1)

    kept, removed, stats = filter_high_quality(root, keep=tuple(args.keep))
    print(f"模板目录: {root}")
    print(f"模板总数: {stats['total']}")
    print(f"保留(高质量): {stats['kept']}")
    print(f"移除: {stats['removed']} 条（移除比例 {stats['removed_pct']}%）")
    print("severity 分布:", ", ".join(f"{k}={v}" for k, v in stats["severity_counts"].items()))

    if args.apply:
        for rel in removed:
            target = root / rel
            try:
                target.unlink()
            except OSError as exc:
                print(f"删除失败 {rel}: {exc}", file=sys.stderr)
        print(f"已删除 {len(removed)} 个低质量模板")
    else:
        print("\n提示: dry-run 模式未实际删除。确认无误后加 --apply 执行删除。")


if __name__ == "__main__":
    main()
