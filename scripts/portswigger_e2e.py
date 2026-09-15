#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PortSwigger Web Security Academy 真实 E2E wrapper（路线 A，零安装 / 不需 Docker）。

背景
----
Vulhub 真实 E2E 依赖 Docker/WSL2，在受限网络环境装不上。PortSwigger Web
Security Academy（Burp Suite 官方免费靶场）是**真实 Web 应用**（非 mock），
覆盖 XSS / SQLi / SSRF / XXE / 命令注入 / SSTI / 文件上传 / CORS / JWT /
反序列化 / API 越权 等 200+ 场景，且**零安装**——浏览器开 Lab 即可。

用法
----
  1. 浏览器登录 https://portswigger.net/web-security
  2. 选一个 Lab -> "Start lab" -> 复制地址栏 URL
     （形如 https://0a1b2c3d1e.web-security-academy.net）
  3. 运行本脚本：
       python scripts/portswigger_e2e.py --url <lab_url> --expect XSS --authorized
  4. 脚本调用**真实 scan.py** 对该 URL 做真实扫描，记录命中证据。

合规
----
PortSwigger 官方允许对其 Academy Lab 做安全测试，但仍需 --authorized 显式
声明已获授权；脚本拒绝对未授权外部目标扫描。

说明
----
真实目标无内置真值表，本脚本只记录"命中/未命中"，**不产出 P/R/F1**（无真值
算出的准确率是自欺）。Lab 是否真正"解决"以 PortSwigger 页面判定为准。
"""
import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = Path(__file__).resolve().parent


def _run_scan(url: str) -> dict:
    """调用真实 scan.py 扫描目标，返回结构化结果。"""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "src")
    cmd = [str(ROOT / "venv" / "Scripts" / "python.exe"), str(ROOT / "scan.py"),
           "scan", "-t", url, "--profile", "standard"]
    try:
        proc = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
    except subprocess.TimeoutExpired as exc:
        return {"returncode": -1, "report": {"finding_lines": [], "count": 0},
                "raw_tail": f"scan 超时: {exc}"}
    out = (proc.stdout or "") + (proc.stderr or "")
    return {"returncode": proc.returncode, "report": _extract_report(out),
            "raw_tail": out[-1500:]}


def _extract_report(text: str) -> dict:
    """从 scan 输出中尽力提取结构化命中行（scan.py 报告多落盘，这里回退解析关键词）。"""
    findings = []
    for line in text.splitlines():
        low = line.lower()
        if any(k in low for k in ("[critical]", "[high]", "[medium]", "[low]",
                                   "vuln", "漏洞", "hit", "finding", "cwe")):
            findings.append(line.strip())
    return {"finding_lines": findings, "count": len(findings)}


def main() -> int:
    ap = argparse.ArgumentParser(description="PortSwigger Academy 真实 E2E wrapper")
    ap.add_argument("--url", required=True, help="PortSwigger Lab URL")
    ap.add_argument("--expect", default="",
                    help="预期漏洞类型关键词，如 XSS/SQLi/SSRF（仅用于记录）")
    ap.add_argument("--authorized", action="store_true",
                    help="声明已获授权（PortSwigger Academy 官方允许测试，仍须显式声明）")
    args = ap.parse_args()
    if not args.authorized:
        print("[portswigger_e2e] 拒绝执行：需 --authorized 声明已获授权。")
        return 3
    if ("web-security-academy.net" not in args.url
            and "portswigger.net" not in args.url):
        print("[portswigger_e2e] 警告：URL 不是 PortSwigger Academy 域名，请确认授权范围。")
    print(f"[portswigger_e2e] 真实扫描 {args.url}（预期 {args.expect or '未知'}）...")
    res = _run_scan(args.url)
    print("=" * 60)
    print(f"  返回码: {res['returncode']}")
    rep = res["report"]
    print(f"  命中行数: {rep.get('count', 0)}")
    for ln in rep.get("finding_lines", [])[:30]:
        print("   · " + ln[:110])
    print("=" * 60)
    out_path = HERE / "_runtime_cache" / "portswigger_e2e.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"url": args.url, "expect": args.expect,
                             "returncode": res["returncode"],
                             "finding_count": rep.get("count", 0)},
                            ensure_ascii=False) + "\n")
    print(f"[portswigger_e2e] 已记录到 {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
