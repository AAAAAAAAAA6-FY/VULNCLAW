# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""VULNCLAW 检出率基准（D7.2）：剧本化靶场评估 + 吞吐基准。

两种模式：
  --mode throughput   原 asyncio 并发吞吐基准（默认）
  --mode eval         给定剧本(expected) + 扫描报告(report)，计算检出率(recall/precision)并对照红线

用法示例：
  python scripts/benchmark.py --mode eval \
      --scenarios-dir scripts/benchmarks \
      --report scripts/benchmarks/baseline_report.json \
      --min-recall 0.8
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from dataclasses import dataclass, field
from statistics import mean
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


# ---------------- throughput 基准（保留原有能力） ----------------
async def simulate_request(request_id: int, delay: float = 0.05) -> dict:
    await asyncio.sleep(delay)
    return {"id": request_id, "status": "ok"}


async def run_benchmark(total_requests: int = 200, concurrency: int = 20) -> float:
    sem = asyncio.Semaphore(concurrency)

    async def worker(rid: int) -> dict:
        async with sem:
            return await simulate_request(rid)

    start = time.perf_counter()
    results = await asyncio.gather(*(worker(i) for i in range(total_requests)))
    elapsed = time.perf_counter() - start
    return elapsed if results else 0.0


async def _throughput(scenarios) -> None:
    timings = []
    for total, conc in scenarios:
        elapsed = await run_benchmark(total, conc)
        timings.append((total, conc, elapsed))
        rps = total / elapsed if elapsed else 0.0
        print(f"requests={total:>3} concurrency={conc:>2} elapsed={elapsed:.3f}s rps={rps:.2f}")
    print(f"average_elapsed={mean(d for _, _, d in timings):.3f}s")


# ---------------- 剧本化评估 ----------------
@dataclass
class TargetScenario:
    name: str
    target: str
    expected_vulns: list[str] = field(default_factory=list)
    auth: dict | None = None

    @classmethod
    def from_dict(cls, d: dict) -> TargetScenario:
        return cls(
            name=d.get("name", d.get("target", "unnamed")),
            target=d["target"],
            expected_vulns=d.get("expected_vulns", []),
            auth=d.get("auth"),
        )


def load_scenarios(path: str) -> list[TargetScenario]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    if os.path.isdir(path):
        out: list[TargetScenario] = []
        for fn in sorted(os.listdir(path)):
            if fn.endswith((".yaml", ".yml")):
                out.extend(load_scenarios(os.path.join(path, fn)))
        return out
    if yaml is None:
        raise RuntimeError("PyYAML 未安装，无法解析剧本")
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or []
    return [TargetScenario.from_dict(d) for d in data]


def _report_findings(report: dict) -> list[dict]:
    """从扫描报告中提取 finding 列表。

    支持三种真实产物形态：
    - 平台 JSON 报告：{"vulnerabilities": [{...}]}（scan_runner 真实产物）
    - 平台 finding JSON：{"findings": [{...}]} / {"results": [...]}
    - 验证网关 SARIF 2.1：{"runs": [{"results": [{"ruleId": .., "properties": {..}}]}]}
    归一为统一 dict 列表（type 取 ruleId/properties.type，参数与证据取 properties）。
    """
    if not isinstance(report, dict):
        return []
    findings = (report.get("vulnerabilities")
                or report.get("findings")
                or report.get("results")
                or [])
    if not findings:
        # 平台分桶形态兜底：direct/burp/nuclei/idor/cred/..._findings 合并归一
        for k, v in report.items():
            if k.endswith('_findings') and isinstance(v, list):
                findings = findings or []
                findings.extend(v)

    if findings:
        return list(findings)
    out: list[dict] = []
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


# D7.2 补丁：剧本期望名（自然语言）与引擎报告 type（规范类名）的命名空间归一。
# 不做归一化时 "XSS"/"SQL Injection" 与 "xss"/"sqli" 集合交集恒为空，召回率恒为 0。
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


def normalize_vuln_type(raw: Any) -> str:
    """剧本期望名 / 引擎报告 type → 规范漏洞类名（未识别原样小写返回，宁保守）。"""
    if raw is None:
        return ""
    s = str(raw).strip().lower()
    if not s:
        return ""
    # 精确命中优先；再按最长后缀模糊匹配（如 "SQL Injection at login" → sqli）
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


def evaluate_report(report: dict, scenarios: list[TargetScenario]) -> dict:
    """计算所有剧本期望漏洞的召回率/精确率。"""
    found_types = set()
    for f in _report_findings(report):
        vt = f.get("type") or f.get("vuln_type") or f.get("name")
        if vt:
            canon = normalize_vuln_type(vt)
            if canon:
                found_types.add(canon)
    expected = set()
    for s in scenarios:
        for ev in s.expected_vulns:
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


def _load_report_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


async def _eval_mode(scenarios_dir: str, report_path: str, min_recall: float) -> None:
    scenarios = load_scenarios(scenarios_dir)
    report = await asyncio.to_thread(_load_report_json, report_path)
    res = evaluate_report(report, scenarios)
    print("=" * 60)
    print(f"剧本数={len(scenarios)} 期望漏洞={len(res['expected'])} 检出={len(res['found'])}")
    print(f"recall={res['recall']:.2%}  precision={res['precision']:.2%}")
    if res["missed"]:
        print(f"未检出(missed): {res['missed']}")
    if res["extra"]:
        print(f"额外检出(extra): {res['extra']}")
    print("=" * 60)
    if min_recall is not None and res["recall"] < min_recall:
        print(f"[FAIL] 检出率 {res['recall']:.2%} 低于红线 {min_recall:.2%}")
        sys.exit(1)
    print("[OK] 检出率达标")


def main() -> None:
    ap = argparse.ArgumentParser(description="VULNCLAW 检出率基准")
    ap.add_argument("--mode", choices=["throughput", "eval"], default="throughput")
    ap.add_argument("--scenarios-dir", default="scripts/benchmarks")
    ap.add_argument("--report", default="artifacts/report.json")
    ap.add_argument("--min-recall", type=float, default=0.8)
    args = ap.parse_args()
    if args.mode == "eval":
        asyncio.run(_eval_mode(args.scenarios_dir, args.report, args.min_recall))
    else:
        asyncio.run(_throughput([(100, 10), (200, 20), (400, 40)]))


if __name__ == "__main__":
    main()
