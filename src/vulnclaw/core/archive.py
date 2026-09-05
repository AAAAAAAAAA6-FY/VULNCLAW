# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""SP18 商业化落地：扫描成果归档 / ZIP 打包 / 多目标批量规划（A 线独占模块）。

- build_scan_archive: 把报告 JSON/HTML/CSV 归档到 out_dir/<scan_id>/ 并生成 ARCHIVE.md 清单
- zip_archive: 将归档目录整体打成 zip，返回 zip 绝对路径
- batch_targets: 多目标批量入口规划（不扫描，只产出目标 -> 建议参数档位 + 调度分组建议）

纯 stdlib；不 import / 不改动 report_generator / cli / settings（并行线独占）。
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import zipfile
from urllib.parse import urlparse

# report_data 中可能携带的"已生成报告文件"候选键（任一命中且文件存在即归档）
_REPORT_FILE_KEYS = {
    "html": ("html_file", "report_html", "html_path"),
    "csv": ("csv_file", "report_csv", "csv_path"),
}
_REPORT_OUT_NAMES = {"html": "report.html", "csv": "report.csv"}

_DEFAULT_CFG = {"tier": "standard"}


def _pick_existing_file(report_data, fmt):
    """从 report_data 候选键里找 fmt 格式已落盘的文件路径；没有返回 None（不抛错）。"""
    for key in _REPORT_FILE_KEYS.get(fmt, ()):
        val = report_data.get(key)
        if isinstance(val, (str, os.PathLike)) and os.path.isfile(os.fspath(val)):
            return os.fspath(val)
    return None


def _compute_distribution(report_data):
    """distribution 摘要：优先用 report_data 里已有的，否则按 severity 现算（纯 stdlib）。"""
    dist = report_data.get("distribution")
    if isinstance(dist, dict) and dist:
        return dist
    by_severity = {}
    for f in report_data.get("vulnerabilities") or []:
        sev = str(f.get("severity") or "").strip().lower() or "unknown"
        by_severity[sev] = by_severity.get(sev, 0) + 1
    return {"by_type": {}, "by_severity": by_severity}


def _write_archive_md(scan_id, report_data, archive_dir):
    findings = report_data.get("vulnerabilities") or []
    dist = _compute_distribution(report_data)
    sev_line = ", ".join(f"{k}: {v}" for k, v in sorted((dist.get("by_severity") or {}).items()))
    type_line = ", ".join(f"{k}: {v}" for k, v in sorted((dist.get("by_type") or {}).items()))
    lines = [
        "# 扫描归档清单",
        "",
        f"- scan_id: {scan_id}",
        f"- 归档时间: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 目标: {report_data.get('target', '')}",
        f"- findings 数: {len(findings)}",
        f"- distribution(by_severity): {sev_line}",
        f"- distribution(by_type): {type_line}",
        "",
        "## 归档文件",
    ]
    for name in ("report.json", "report.html", "report.csv"):
        if os.path.isfile(os.path.join(archive_dir, name)):
            lines.append(f"- {name}")
    with open(os.path.join(archive_dir, "ARCHIVE.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def build_scan_archive(scan_id, report_data, out_dir):
    """把报告归档到 out_dir/<scan_id>/ 并生成 ARCHIVE.md，返回归档目录绝对路径。

    report.json 始终由 report_data 落盘；HTML/CSV 仅在 report_data 携带已存在路径时复制，
    找不到某格式就跳过该文件不报错。纯 stdlib（shutil/json）。
    """
    archive_dir = os.path.join(os.fspath(out_dir), str(scan_id))
    os.makedirs(archive_dir, exist_ok=True)
    # 1. 报告 JSON：始终从 report_data 写入
    with open(os.path.join(archive_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump(report_data, fh, ensure_ascii=False, indent=2, default=str)
    # 2. HTML / CSV：存在才复制，缺失跳过
    for fmt, out_name in _REPORT_OUT_NAMES.items():
        src = _pick_existing_file(report_data, fmt)
        if src:
            try:
                shutil.copy2(src, os.path.join(archive_dir, out_name))
            except OSError:
                pass  # 单文件复制失败不影响归档整体
    # 3. ARCHIVE.md 清单
    _write_archive_md(scan_id, report_data, archive_dir)
    return os.path.abspath(archive_dir)


def zip_archive(archive_dir, zip_path):
    """把整个归档目录打成 zip（zipfile，顶层保留 <scan_id>/ 目录），返回 zip 绝对路径。"""
    archive_dir = os.path.abspath(os.fspath(archive_dir))
    zip_path = os.fspath(zip_path)
    parent = os.path.dirname(archive_dir)
    os.makedirs(os.path.dirname(os.path.abspath(zip_path)), exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(archive_dir):
            for fn in sorted(files):
                full = os.path.join(root, fn)
                zf.write(full, arcname=os.path.relpath(full, parent))
    return os.path.abspath(zip_path)


def _split_target(target):
    """把目标串拆成 (host, port)；支持 URL 与 host:port 两种形态。"""
    raw = str(target).strip()
    if not raw:
        return "", None, raw
    norm = raw if "://" in raw else "//" + raw
    parsed = urlparse(norm)
    return (parsed.hostname or "").lower(), parsed.port, raw


def batch_targets(targets, per_target_cfg):
    """多目标批量入口规划：去重后输出"目标 -> 建议参数档位"的计划列表。

    每项为 dict：{target, host, port, cfg, group, group_id, port_mode}。
    分组建议遵循"热点串行"纪律：互不相关目标可并行（group=parallel）；
    同一目标多端口串行（同 host 多个目标 -> group=serial，共享 group_id）。
    不做真实扫描，仅产出规划供主线程编排。
    """
    cfg = dict(per_target_cfg) if isinstance(per_target_cfg, dict) else dict(_DEFAULT_CFG)
    seen = set()
    items = []
    host_groups = {}
    for t in targets or []:
        key = str(t).strip()
        if not key or key in seen:
            continue
        seen.add(key)
        host, port, raw = _split_target(t)
        item = {"target": raw, "host": host or raw, "port": port, "cfg": dict(cfg)}
        items.append(item)
        host_groups.setdefault(host or raw, []).append(item)
    plan = []
    for item in items:
        host = item["host"]
        if len(host_groups[host]) > 1:
            item["group"] = "serial"
            item["group_id"] = f"serial-{host}"
        else:
            item["group"] = "parallel"
            item["group_id"] = f"parallel-{item['target']}"
        ports = cfg.get("ports")
        item["port_mode"] = "serial" if isinstance(ports, (list, tuple)) and len(ports) > 1 else "parallel"
        plan.append(item)
    return plan