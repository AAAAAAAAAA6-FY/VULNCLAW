#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""G.1 引擎 benchmark：用 fixture（正反例 + mock 响应）测引擎，输出检出率/误报率基线。

设计要点：
  - **不依赖真实靶场**：每个 case 自带 responses，benchmark 把它注入引擎模块的
    async_get，从而可离线、可重复地评估引擎（含合并后的规则驱动引擎）。
    这正好补上"local_lab 只覆盖十余类漏洞、其余引擎无法评估"的缺口。
  - **正反例成对**：positive = 应检出（漏了就是 FN）；negative = 不应检出
    （报了就是 FP）。这样"零误报的零发现"骗不了人。
  - 判定口径：
      expect=positive 且有 finding → TP ；无 finding → FN
      expect=negative 且有 finding → FP ；无 finding → TN
      检出率 = TP / (TP+FN)   误报率 = FP / (FP+TN)

用法：
    python scripts/benchmark.py                # 跑全部 fixture 并打印
    python scripts/benchmark.py --save         # 额外写入基线文件
输出：
    控制台表格 + tests/fixtures/benchmark_baseline.json
"""
from __future__ import annotations

import argparse
import asyncio
import importlib
import json
import sys
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# 复刻 scan.py：在任何 vulnclaw 导入前先装 numpy 兼容桩（Python 3.13+/Windows 防段错误）
try:
    from vulnclaw.core.numpy_compat import install_numpy_compat_stub_if_needed

    install_numpy_compat_stub_if_needed()
except Exception:  # noqa: BLE001 - 桩不可用时继续，多数场景本就不需要
    pass

FIXTURE_DIR = ROOT / "tests" / "fixtures" / "engines"
BASELINE = ROOT / "tests" / "fixtures" / "benchmark_baseline.json"


def _load_yaml(path: Path) -> Dict:
    import yaml  # 局部导入：脚本可独立运行

    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _make_fake_async_get(responses: Dict):
    """按 URL 子串匹配返回预设响应（模拟 async_get 的 (status, text, headers)）。"""

    async def _get(url, *args, **kwargs):
        s = str(url)
        for suffix, resp in (responses or {}).items():
            if str(suffix) in s:
                print(f"      [mock] HIT  {s} -> {resp.get('status', 200)}")
                return int(resp.get("status", 200)), str(resp.get("body", "")), {}
        print(f"      [mock] MISS {s} -> 404")
        return 404, "", {}

    return _get


def _run_case(spec: Dict, engine, loop) -> List[Dict]:
    """注入 mock 响应后跑一次引擎 scan。"""
    module_name = spec.get("module") or ""
    fake = _make_fake_async_get(spec.get("responses") or {})
    orig = None
    mod = None
    if module_name:
        mod = importlib.import_module(module_name)
        orig = getattr(mod, "async_get", None)
        mod.async_get = fake
    try:
        findings = loop.run_until_complete(
            engine.scan(spec.get("target", "http://127.0.0.1:8080"), None)
        )
        return findings or []
    except Exception as exc:  # noqa: BLE001 - 单 case 异常记为未检出
        print(f"  [!] case {spec.get('id')} 执行异常: {exc}")
        return []
    finally:
        if mod is not None and orig is not None:
            mod.async_get = orig


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--save", action="store_true", help="写入基线文件")
    args = ap.parse_args()

    if not FIXTURE_DIR.is_dir():
        print(f"NO_FIXTURE_DIR {FIXTURE_DIR}")
        return 2

    loop = asyncio.new_event_loop()
    try:
        rows: List[Dict] = []
        stats: Dict[str, Dict[str, int]] = {}

        for f in sorted(FIXTURE_DIR.glob("*.yaml")):
            data = _load_yaml(f)
            module_name = data.get("module") or ""
            class_name = data.get("class") or ""
            engine_name = data.get("engine") or class_name
            try:
                mod = importlib.import_module(module_name) if module_name else None
                cls = getattr(mod, class_name) if (mod and class_name) else None
                engine = cls() if cls else None
            except Exception as exc:  # noqa: BLE001
                print(f"[!] 引擎 {engine_name} 加载失败: {exc}")
                continue

            for case in data.get("cases") or []:
                if not isinstance(case, dict):
                    continue
                case = dict(case)
                # 修复：module/class 定义在 fixture 顶层，必须带进 case，
                # 否则 _run_case 拿不到模块名 → mock 不注入 → 引擎走真实 HTTP。
                case.setdefault("module", module_name)
                expect = str(case.get("expect") or "positive")
                findings = _run_case(case, engine, loop) if engine else []
                found = len(findings) > 0
                if expect == "positive":
                    verdict = "TP" if found else "FN"
                else:
                    verdict = "FP" if found else "TN"
                top = (findings[0].get("title") or findings[0].get("type") or "") if findings else ""
                rows.append({
                    "file": f.name, "engine": engine_name, "case": case.get("id"),
                    "expect": expect, "found": found, "verdict": verdict,
                    "severity": (findings[0].get("severity") if findings else ""),
                    "top": top[:48],
                })
                st = stats.setdefault(engine_name, {"TP": 0, "FN": 0, "FP": 0, "TN": 0})
                st[verdict] += 1

        # ---- 输出 ----
        print("=" * 96)
        print(" 引擎 benchmark（fixture 驱动，离线可重复）")
        print("=" * 96)
        print(f"{'引擎':<24}{'用例':<34}{'期望':<10}{'检出':<8}{'判定':<8}严重级/标题")
        print("-" * 96)
        for r in rows:
            print(
                f"{r['engine'][:23]:<24}{str(r['case'])[:33]:<34}{r['expect']:<10}"
                f"{('是' if r['found'] else '否'):<8}{r['verdict']:<8}{r['severity']} {r['top']}"
            )
        print("-" * 96)
        print(f"{'引擎':<24}{'TP':>6}{'FN':>6}{'FP':>6}{'TN':>6}{'检出率':>10}{'误报率':>10}")
        summary = []
        for name, st in stats.items():
            pos = st["TP"] + st["FN"]
            neg = st["FP"] + st["TN"]
            dr = (st["TP"] / pos * 100) if pos else 0.0
            fr = (st["FP"] / neg * 100) if neg else 0.0
            print(
                f"{name[:23]:<24}{st['TP']:>6}{st['FN']:>6}{st['FP']:>6}{st['TN']:>6}"
                f"{dr:>9.1f}%{fr:>9.1f}%"
            )
            summary.append({"engine": name, **st, "detect_rate": round(dr, 1),
                            "false_rate": round(fr, 1)})
        tot = {k: sum(s[k] for s in stats.values()) for k in ("TP", "FN", "FP", "TN")}
        pos = tot["TP"] + tot["FN"]
        neg = tot["FP"] + tot["TN"]
        print("-" * 96)
        print(
            f"{'合计':<24}{tot['TP']:>6}{tot['FN']:>6}{tot['FP']:>6}{tot['TN']:>6}"
            f"{(tot['TP'] / pos * 100) if pos else 0:>9.1f}%"
            f"{(tot['FP'] / neg * 100) if neg else 0:>9.1f}%"
        )
        print("=" * 96)

        if args.save:
            BASELINE.parent.mkdir(parents=True, exist_ok=True)
            BASELINE.write_text(
                json.dumps({"summary": summary, "total": tot, "cases": rows},
                           ensure_ascii=False, indent=2),
                encoding="utf-8",
            )
            print(f"BASELINE_SAVED={BASELINE}")
        return 0
    finally:
        loop.close()


if __name__ == "__main__":
    sys.exit(main())
import os as _os


# ---------------------------------------------------------------------------
# 兼容层（2026-09-09）：G.1 重写为 fixture 驱动基准后，保留旧评测 API，
# 供 tests/test_benchmark_eval.py（D7.2 剧本评测）继续收集运行 —— 纯增量，不参与新 main 逻辑。
# ---------------------------------------------------------------------------
_VULN_TYPE_ALIASES = {
    "xss": "xss", "cross-site scripting": "xss", "cross site scripting": "xss",
    "反射型xss": "xss", "存储型xss": "xss", "dom xss": "xss",
    "sqli": "sqli", "sql injection": "sqli", "sql注入": "sqli", "sql-injection": "sqli",
    "file upload": "file_upload", "file_upload": "file_upload", "文件上传": "file_upload",
    "lfi": "lfi", "local file inclusion": "lfi", "path traversal": "lfi",
    "rce": "rce", "remote code execution": "rce", "命令注入": "rce", "command injection": "rce",
    "cmdi": "cmdi",
    "ssti": "ssti", "template injection": "ssti", "模板注入": "ssti",
    "ssrf": "ssrf", "server-side request forgery": "ssrf",
    "xxe": "xxe", "xml external entity": "xxe",
    "idor": "idor", "insecure direct object reference": "idor",
    "jwt": "jwt", "jwt bypass": "jwt", "json web token": "jwt",
    "cors": "cors", "misconfigured cors": "cors",
    "sensitive files": "sensitive_files", "sensitive_file": "sensitive_files",
    "信息泄露": "info_leak", "information disclosure": "info_leak", "info_leak": "info_leak",
    "directory listing": "directory_listing",
    "csrf": "csrf", "cross-site request forgery": "csrf",
    "open redirect": "open_redirect", "redirect": "open_redirect",
    "nosql": "nosql", "nosql injection": "nosql",
    "deserialization": "deser", "deser": "deser", "反序列化": "deser",
}


def normalize_vuln_type(raw) -> str:
    """剧本期望名 / 引擎报告 type → 规范漏洞类名（未识别原样小写返回，宁保守）。"""
    if raw is None:
        return ""
    s = str(raw).strip().lower()
    if not s:
        return ""
    key = _VULN_TYPE_ALIASES.get(s)
    if key:
        return key
    best = ""
    best_len = 0
    for alias, canon in _VULN_TYPE_ALIASES.items():
        if alias in s and len(alias) > best_len:
            best = canon
            best_len = len(alias)
    return best or s


def _report_findings(report: dict) -> list:
    """从扫描报告中提取 finding 列表（平台 JSON / finding JSON / SARIF 2.1 三形态）。"""
    if not isinstance(report, dict):
        return []
    findings = (report.get("vulnerabilities")
                or report.get("findings")
                or report.get("results")
                or [])
    if not findings:
        for k, v in report.items():
            if k.endswith('_findings') and isinstance(v, list):
                findings = findings or []
                findings.extend(v)
    if findings:
        return list(findings)
    out: list = []
    for run in report.get("runs") or []:
        for res in run.get("results") or []:
            props = res.get("properties") or {}
            f: dict = {
                "type": res.get("ruleId") or props.get("type") or "unknown",
                "url": props.get("url") or "",
                "parameter": props.get("parameter") or "",
                "payload": props.get("payload") or "",
                "evidence": props.get("evidence") or "",
            }
            if props.get("severity"):
                f["severity"] = props.get("severity")
            out.append(f)
    return out


def evaluate_report(report: dict, scenarios: list) -> dict:
    """计算所有剧本期望漏洞的召回率/精确率（旧评测脚本依赖的稳定 API）。"""
    found_types = set()
    for f in _report_findings(report):
        vt = f.get("type") or f.get("vuln_type") or f.get("name")
        if vt:
            canon = normalize_vuln_type(vt)
            if canon:
                found_types.add(canon)
    expected = set()
    for s in scenarios:
        for ev in getattr(s, "expected_vulns", []) or []:
            canon = normalize_vuln_type(ev)
            if canon:
                expected.add(canon)
    tp = expected & found_types
    fn = expected - found_types
    fp = found_types - expected
    recall = len(tp) / len(expected) if expected else 1.0
    precision = len(tp) / len(found_types) if found_types else 1.0
    return {
        "expected": sorted(expected),
        "found": sorted(found_types),
        "recall": recall,
        "precision": precision,
        "missed": sorted(fn),
        "extra": sorted(fp),
    }


class TargetScenario:
    """剧本场景：期望发现的漏洞清单（旧评测脚本兼容定义）。"""
    def __init__(self, name: str, target: str, expected_vulns=None, auth=None):
        self.name = name
        self.target = target
        self.expected_vulns = list(expected_vulns or [])
        self.auth = auth

    @classmethod
    def from_dict(cls, d: dict):
        return cls(
            name=d.get("name", d.get("target", "unnamed")),
            target=d["target"],
            expected_vulns=d.get("expected_vulns", []),
            auth=d.get("auth"),
        )

    def __repr__(self):
        return f"TargetScenario(name={self.name!r}, target={self.target!r})"


def load_scenarios(path: str) -> list:
    """从 YAML 文件/目录加载剧本场景（旧评测脚本依赖的稳定 API）。"""
    import yaml as _yaml  # 局部导入

    if not _os.path.exists(path):
        raise FileNotFoundError(path)
    if _os.path.isdir(path):
        out: list = []
        for fn in sorted(_os.listdir(path)):
            if fn.endswith((".yaml", ".yml")):
                out.extend(load_scenarios(_os.path.join(path, fn)))
        return out
    with open(path, "r", encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or []
    return [TargetScenario.from_dict(d) for d in data]
