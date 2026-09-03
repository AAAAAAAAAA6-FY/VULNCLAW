#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
逐条手动复现验证脚本。

读取扫描报告 JSON，对每条漏洞实际发起只读 GET 请求，检查 payload 是否在响应中
原样回显，从而区分"疑似真实漏洞"与"误报"。本脚本只做只读请求，不执行任何利用，
请在已获授权的目标上运行。

用法:
  python scripts/verify_findings.py --report _runtime_cache/reports/report_audible_com_20260902_030741.json
  python scripts/verify_findings.py --report <报告.json> --scheme https --timeout 15 --only-reflective
"""
import argparse
import json
import sys
import urllib.parse
import urllib.request
import urllib.error

# 仅验证反射/报错类（盲注/时间盲注无回显属正常，不在此脚本判定范围）
REFLECT_KEYWORDS = ("xss", "反射", "跨站", "报错", "error", "回显")


def ensure_scheme(url: str, default: str = "https") -> str:
    if not url:
        return url
    if "://" in url:
        return url
    return f"{default}://{url.lstrip('/')}"


def build_url(url: str, param: str, payload: str, scheme: str) -> str:
    url = ensure_scheme(url, scheme)
    p = urllib.parse.urlparse(url)
    base = f"{p.scheme}://{p.netloc}{p.path}"
    q = urllib.parse.parse_qs(p.query)
    if param:
        q[param] = [payload]
    query = urllib.parse.urlencode(q, doseq=True)
    return f"{base}?{query}" if query else base


def fetch(url: str, timeout: float):
    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 VulnVerify/1.0 (read-only)"}
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return None, f"请求异常: {e}"


def main() -> int:
    ap = argparse.ArgumentParser(description="逐条手动复现扫描报告中的漏洞")
    ap.add_argument("--report", required=True, help="扫描报告 JSON 路径")
    ap.add_argument("--scheme", default="https", help="无 scheme URL 的默认协议 (默认 https)")
    ap.add_argument("--timeout", type=float, default=15.0, help="单请求超时秒数")
    ap.add_argument("--only-reflective", action="store_true",
                    help="只验证反射/报错类漏洞 (xss/报错注入)")
    args = ap.parse_args()

    try:
        with open(args.report, encoding="utf-8") as f:
            report = json.load(f)
    except Exception as e:  # noqa: BLE001
        print(f"❌ 无法读取报告: {e}", file=sys.stderr)
        return 1

    vulns = report.get("vulnerabilities", []) or []
    print(f"报告目标: {report.get('target')}   漏洞条目: {len(vulns)}\n")

    real = fp = unknown = 0
    for i, v in enumerate(vulns, 1):
        vtype = v.get("type", "")
        vt_l = str(vtype).lower()
        if args.only_reflective and not any(k in vt_l for k in REFLECT_KEYWORDS):
            continue
        url = v.get("url", "")
        param = v.get("parameter", "") or v.get("param", "")
        payload = v.get("payload", "") or v.get("attack_payload", "")
        if not url:
            continue

        target = build_url(url, param, payload, args.scheme)
        status, body = fetch(target, args.timeout)

        reflected = False
        reason = ""
        if body is not None and status is not None:
            candidates = [payload, payload.lower(), "<script", "alert("]
            reflected = any(c and c in body for c in candidates)
            reason = "payload/特征在响应中回显" if reflected else "响应中未回显 payload"
        else:
            reason = body  # 实为异常字符串

        verdict_now = v.get("ai_verdict", "")
        if reflected:
            conclusion = "疑似真实漏洞 ✅"
            real += 1
        elif "待人工复核" in verdict_now:
            conclusion = "待人工复核 (原判定已保守)"
            unknown += 1
        else:
            conclusion = "误报嫌疑 ⚠️"
            fp += 1

        print(f"[{i}] {vtype}  param={param}")
        print(f"     URL : {target}")
        print(f"     状态: {status}   回显: {'是' if reflected else '否'}  -> {conclusion}")
        print(f"     原判定: {verdict_now}  ({reason})")
        print()

    print("=" * 60)
    print(f"汇总: 疑似真实 {real} / 误报嫌疑 {fp} / 待复核 {unknown}")
    print("注意: 回显=否 不代表绝对无漏洞（可能是编码转义/事件触发/存储型），")
    print("      但对反射型 XSS 与报错注入而言，无回显即为强误报信号，需人工确认。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
