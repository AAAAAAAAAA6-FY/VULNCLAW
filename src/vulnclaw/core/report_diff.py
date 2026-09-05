# SPDX-License-Identifier: AGPL-3.0-or-later
"""P4-6: scan_diff 自动基线（报告后存基线 + 下次扫描输出增量 diff）。

设计：
- settings.scan_diff=True（默认）时启用；False 直接跳过（零开销）。
- 基线路径优先级：settings.scan_diff_baseline（显式指定）> _runtime_cache/baseline/<target>.json（自动）。
- diff 签名：vulnerability 的 (url, title) 组合；仅统计对比，不判定安全结论。
- 显式指定基线时只读比对不写回；自动基线则比对后写回（供下次 diff）。
"""
import json
import os

from vulnclaw.config.settings import settings
from vulnclaw.core.logger import logger


def _default_baseline_path(safe_target: str) -> str:
    rt = os.path.join("_runtime_cache", "baseline")
    os.makedirs(rt, exist_ok=True)
    return os.path.join(rt, f"{safe_target}.json")


def _signature(vuln: dict) -> str:
    url = str(vuln.get("url") or "")
    title = str(vuln.get("title") or vuln.get("type") or vuln.get("name") or "")
    return f"{url}|{title}"


def _diff_reports(prev: list, cur: list) -> dict:
    prev_sig = {_signature(v) for v in prev if isinstance(v, dict)}
    cur_sig = {_signature(v) for v in cur if isinstance(v, dict)}
    added = [v for v in cur if isinstance(v, dict) and _signature(v) not in prev_sig]
    fixed = [v for v in prev if isinstance(v, dict) and _signature(v) not in cur_sig]
    return {"added": added, "fixed": fixed}


def maybe_diff_baseline(report: dict, target: str, safe_target: str, json_path) -> None:
    """扫描报告落盘后调用：存在旧基线则输出增量 diff，然后写回新基线。"""
    if not getattr(settings, "scan_diff", True):
        return
    try:
        vulns = report.get("vulnerabilities") or []
        explicit = str(getattr(settings, "scan_diff_baseline", "") or "").strip()
        base_path = explicit if explicit else _default_baseline_path(safe_target)
        if os.path.exists(base_path):
            try:
                with open(base_path, "r", encoding="utf-8") as f:
                    prev = json.load(f)
                prev_vulns = prev.get("vulnerabilities") or [] if isinstance(prev, dict) else []
                _print_diff(target, _diff_reports(prev_vulns, vulns))
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"scan_diff 基线解析跳过: {exc}")
        else:
            print(f"[scan_diff] 首次扫描，已建立基线（下次扫描将输出增量）: {base_path}")
        if not explicit:
            with open(base_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"scan_diff 基线处理跳过: {exc}")


def _print_diff(target: str, d: dict) -> None:
    added, fixed = d.get("added") or [], d.get("fixed") or []
    print(f"[scan_diff] 目标 {target} 相对上次扫描: 新增 {len(added)} 项 / 已修复 {len(fixed)} 项")
    for v in added[:10]:
        print(f"  新增: {_signature(v)}")
    for v in fixed[:10]:
        print(f"  已修复: {_signature(v)}")
    if len(added) > 10:
        print(f"  ...其余 {len(added) - 10} 项新增见报告")
    if len(fixed) > 10:
        print(f"  ...其余 {len(fixed) - 10} 项已修复见报告")