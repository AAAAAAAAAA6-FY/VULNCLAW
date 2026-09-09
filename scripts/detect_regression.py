# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
#
# scripts/detect_regression.py
"""检出率 / 误报率自动回归（固化 2026-09-06 测法，立项）。
不依赖外网靶场；用本地 local_lab 自带真值表（EXPECTED_FINDINGS）做基准。

固化标准流程（来自多轮人工测法的收敛结论）：
  1) 探测 127.0.0.1:8090 是否存活，未起则子进程拉起 local_lab.py
  2) INCREMENTAL_SCAN=false 跑一次 v100 扫描（关闭增量 = 全量，避免重复扫同一目标 findings 减少的假象）
  3) 取 _runtime_cache/reports 下最新 report_*.json
  4) 解析 vulnerabilities（type/url/parameter/severity）对照真值
  5) 输出 TP/FN/FP、检出率、误报率；核心回归未达标则非 0 退出

用法:
  python scripts/detect_regression.py                 # 全跑（起靶机 + 扫描 + 比对）
  python scripts/detect_regression.py --no-scan       # 只比对已有最新报告
  python scripts/detect_regression.py --target URL    # 自定义靶机（需自备真值，否则只算误报）
"""
import argparse
import glob
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
REPORT_DIR = os.path.join(ROOT, "_runtime_cache", "reports")

# 扫描器解释器：优先仓库外已装 python，回退 sys.executable
SCAN_PY = os.path.join(ROOT, "scan.py")
DEFAULT_TARGET = "http://127.0.0.1:8090"


def _log(msg: str) -> None:
    print(f"[regression] {msg}", flush=True)


def _import_expected(target: str):
    """从 local_lab 读真值表；若靶机非 local_lab 则返回 None（只算误报）。"""
    try:
        sys.path.insert(0, HERE)
        import local_lab  # type: ignore
        if local_lab.EXPECTED_FINDINGS.get("target") == target:
            return local_lab.EXPECTED_FINDINGS
    except Exception as e:  # noqa: BLE001
        _log(f"无法导入 local_lab 真值表（仅做误报统计）: {e}")
    return None


def _ensure_lab(target: str) -> bool:
    """探测靶机存活；local_lab 未起则拉起。返回是否可用。"""
    try:
        with urllib.request.urlopen(target, timeout=3) as r:
            if r.status == 200:
                _log(f"靶机已存活: {target}")
                return True
    except Exception:
        pass
    if target != DEFAULT_TARGET:
        _log(f"靶机 {target} 未存活且非 local_lab，跳过自动拉起")
        return False
    _log("拉起 local_lab 靶机...")
    try:
        subprocess.Popen(
            [sys.executable, os.path.join(HERE, "local_lab.py")],
            cwd=HERE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(20):
            time.sleep(0.5)
            try:
                with urllib.request.urlopen(target, timeout=2) as r:
                    if r.status == 200:
                        _log("local_lab 已就绪")
                        return True
            except Exception:
                continue
    except Exception as e:  # noqa: BLE001
        _log(f"拉起 local_lab 失败: {e}")
    return False


def _run_scan(target: str) -> None:
    env = dict(os.environ)
    env["INCREMENTAL_SCAN"] = "false"  # 关键：全量，避免增量语义造成的假象
    env["PYTHONIOENCODING"] = "utf-8"
    _log(f"启动扫描: {target} （INCREMENTAL_SCAN=false）")
    code = subprocess.run(
        [sys.executable, SCAN_PY, "scan", "-t", target],
        cwd=ROOT, env=env,
    ).returncode
    _log(f"扫描进程退出码: {code}")


def _latest_report() -> str:
    pats = [os.path.join(REPORT_DIR, "report_*.json")]
    files = []
    for p in pats:
        files.extend(glob.glob(p))
    if not files:
        raise FileNotFoundError(f"未找到报告 JSON（{REPORT_DIR}）")
    files.sort(key=os.path.getmtime, reverse=True)
    return files[0]


def _match_type(vuln_type: str, expect: list) -> bool:
    vt = (vuln_type or "").lower()
    return any(alias.lower() in vt or vt in alias.lower() for alias in expect)


def _evaluate(report_path: str, expected) -> dict:
    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)
    vulns = report.get("vulnerabilities") or report.get("findings") or []
    _log(f"报告 {os.path.basename(report_path)}: {len(vulns)} 条 vulnerabilities")

    negatives = (expected or {}).get("negatives", {}) or {}
    neg_paths = list(negatives.keys())

    # 误报：已知负样本端点出现在报告中
    fp_list = []
    for v in vulns:
        url = str(v.get("url", ""))
        for np in neg_paths:
            if np in url:
                fp_list.append(v)
                break

    tp, fn, fp_extra = [], [], []
    if expected:
        for ep, spec in expected["endpoints"].items():
            ep_path = ep.split("?")[0]
            expect = spec.get("expect", [])
            hit = [v for v in vulns
                   if ep_path in str(v.get("url", "")) and _match_type(v.get("type", ""), expect)]
            if hit:
                tp.append((ep, hit[0].get("type")))
            else:
                fn.append(ep)
        # 非负样本但 type 完全不在任何期望里的，也计入额外误报（可选）
    else:
        _log("无真值表：仅统计负样本误报")

    total_ep = len(expected["endpoints"]) if expected else 0
    detect_rate = (len(tp) / total_ep) if total_ep else 0.0
    fp_count = len(fp_list)
    total_flagged = len(tp) + fp_count
    fp_rate = (fp_count / total_flagged) if total_flagged else 0.0

    return {
        "report": os.path.basename(report_path),
        "total_vulns": len(vulns),
        "tp": tp, "fn": fn, "fp": fp_list,
        "detect_rate": detect_rate, "fp_rate": fp_rate,
        "total_ep": total_ep,
    }


def _print_result(r: dict) -> None:
    print("\n" + "=" * 60)
    print("  检出率 / 误报率回归结果")
    print("=" * 60)
    print(f"  报告: {r['report']}  漏洞总数: {r['total_vulns']}")
    if r["total_ep"]:
        print(f"  期望端点: {r['total_ep']}  命中(TP): {len(r['tp'])}  漏报(FN): {len(r['fn'])}")
        print(f"  ★ 检出率: {r['detect_rate']*100:.1f}%  (目标 ≥80%)")
        if r["fn"]:
            print(f"  漏报端点: {', '.join(r['fn'])}")
    print(f"  ★ 误报(FP): {len(r['fp'])}  误报率: {r['fp_rate']*100:.1f}%  (目标 ≤5%)")
    for v in r["fp"]:
        print(f"    - FP: {v.get('type')} @ {v.get('url')}")
    print("=" * 60)


def main() -> int:
    # Windows GBK 控制台兜底：✗/★ 等符号直接 print 会 UnicodeEncodeError 崩溃
    # （PYTHONIOENCODING 只对 _run_scan 子进程生效，保护不到本进程）
    for _s in (sys.stdout, sys.stderr):
        if hasattr(_s, "reconfigure"):
            _s.reconfigure(encoding="utf-8", errors="replace")
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=DEFAULT_TARGET)
    ap.add_argument("--no-scan", action="store_true")
    args = ap.parse_args()

    expected = _import_expected(args.target)
    if expected:
        _log(f"真值表: {len(expected['endpoints'])} 期望端点, {len(expected.get('negatives', {}))} 负样本")
    else:
        _log("未匹配到真值表（仅做误报统计）")

    if not args.no_scan:
        if not _ensure_lab(args.target):
            _log("靶机不可用，无法扫描；如已有报告请用 --no-scan")
            return 2
        # 联动第2点：注入靶机负样本端点，使验证层拦截在回归中生效（/safe 不应再出现）
        if expected and expected.get("negatives"):
            os.environ["NEGATIVE_ENDPOINTS"] = ",".join(expected["negatives"].keys())
            _log(f"注入负样本拦截端点: {os.environ['NEGATIVE_ENDPOINTS']}（验证层第2点）")
        _run_scan(args.target)
    else:
        _log("跳过扫描，直接比对最新报告")

    try:
        report = _latest_report()
    except FileNotFoundError as e:
        _log(str(e))
        return 2
    _log(f"使用报告: {report}")

    r = _evaluate(report, expected)
    _print_result(r)

    # 退出码：核心回归未达标
    ok = True
    if expected and r["detect_rate"] < 0.8:
        _log("✗ 检出率 < 80% 阈值")
        ok = False
    if r["fp_rate"] > 0.05:
        _log("✗ 误报率 > 5% 阈值")
        ok = False
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
