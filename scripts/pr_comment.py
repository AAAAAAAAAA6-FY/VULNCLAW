# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""E3.3: PR 评论机器人——把 verified SARIF 以评论形式回贴 PR（含凭证链审计锚）。

用法（CI 内）：
    python scripts/pr_comment.py --input verified.sarif
环境变量：GITHUB_TOKEN / GITHUB_REPOSITORY；PR 号取 --pr 或 GITHUB_REF。
无 token / 非 PR 环境自动退化为 dry-run（只打印 markdown）——本地与测试可用。

upsert 语义：用 <!-- vulnclaw-verify --> 标记识别机器人旧评论，PATCH 更新
而非 POST 追加——同一 PR 反复跑不刷屏。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

MARKER = "<!-- vulnclaw-verify -->"
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def _sev_index(sev: str) -> int:
    return _SEV_ORDER.index(sev) if sev in _SEV_ORDER else len(_SEV_ORDER)


def load_findings_from_sarif(path: str) -> list:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for run in data.get("runs", []):
        for r in run.get("results", []):
            props = r.get("properties") or {}
            loc = (r.get("locations") or [{}])[0]
            out.append({
                "type": r.get("ruleId", "?"),
                "url": (((loc.get("physicalLocation") or {}).get("artifactLocation")) or {}).get("uri", ""),
                "severity": props.get("severity", "info"),
                "status": props.get("status", "unverified"),
                "confidence": props.get("confidence", 0),
                "evidence": ((r.get("message") or {}).get("text") or ""),
            })
    return out


def build_pr_markdown(findings: list, chain_root: str = "", max_rows: int = 20) -> str:
    """渲染 PR 评论 markdown（纯函数，可单测）。"""
    counts: dict = {}
    for f in findings:
        s = f.get("severity", "info")
        counts[s] = counts.get(s, 0) + 1
    verified = [f for f in findings if f.get("status") == "verified"]

    lines = [MARKER, "## 🛡️ VULNCLAW 验证网关报告", ""]
    lines += ["| 严重级 | 数量 |", "|---|---|"]
    for s in reversed(_SEV_ORDER):
        if counts.get(s):
            lines.append(f"| {s} | {counts[s]} |")
    lines.append("")
    lines.append(f"**已验证**: {len(verified)} / {len(findings)} 条"
                 f"（其余为低置信/待复核，全程确定性流水线）")
    if chain_root:
        lines.append(f"**凭证链根**: `{chain_root}` —— 篡改任意结论将链式暴露；"
                     f"用同密钥 `vulnclaw verify --verify-only` 复核")
    if verified:
        lines += ["", "| 级别 | 类型 | URL | 置信度 |", "|---|---|---|---|"]
        for f in sorted(verified, key=lambda x: _sev_index(x.get("severity", "info")))[:max_rows]:
            lines.append(
                f"| {f.get('severity')} | {f.get('type')} | {f.get('url')} | {f.get('confidence')} |")
        if len(verified) > max_rows:
            lines.append(f"\n…（其余 {len(verified) - max_rows} 条见 CI artifact 的 verified.sarif）")
    else:
        lines.append("\n✅ 本轮没有达到 verified 阈值的发现（完整明细见 CI artifact）")
    lines.append("\n<sub>由 VULNCLAW 验证网关生成 · 去伪存真 · 结果可用凭证链审计</sub>")
    return "\n".join(lines)


def gh_api(method: str, url: str, token: str, payload: dict | None = None):
    req = urllib.request.Request(
        url,
        method=method,
        data=json.dumps(payload).encode("utf-8") if payload is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "vulnclaw-verify",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        body = resp.read().decode("utf-8")
        return json.loads(body) if body else None


def upsert_comment(repo: str, pr: str, token: str, markdown: str):
    api = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
    existing = gh_api("GET", api, token) or []
    for c in existing:
        if MARKER in (c.get("body") or ""):
            return gh_api("PATCH", f"{api}/{c['id']}", token, {"body": markdown})
    return gh_api("POST", api, token, {"body": markdown})


def _pr_number_from_env() -> str:
    ref = os.environ.get("GITHUB_REF", "")
    if ref.startswith("refs/pull/"):
        return ref.split("/")[2]
    return ""


def main(argv: list | None = None) -> int:
    ap = argparse.ArgumentParser(description="把 VULNCLAW verified SARIF 回贴成 PR 评论")
    ap.add_argument("--input", required=True, help="verified SARIF 文件（网关输出）")
    ap.add_argument("--pr", default="", help="PR 编号（缺省从 GITHUB_REF 推断）")
    ap.add_argument("--dry-run", action="store_true", help="只打印 markdown，不调 GitHub API")
    a = ap.parse_args(argv)

    findings = load_findings_from_sarif(a.input)
    receipt_path = Path(a.input).with_name(Path(a.input).stem + ".receipt.json")
    chain_root = ""
    if receipt_path.is_file():
        try:
            chain_root = str(json.loads(receipt_path.read_text(encoding="utf-8")).get("chain_root", ""))
        except Exception:  # noqa: BLE001
            chain_root = ""
    md = build_pr_markdown(findings, chain_root=chain_root)

    token = os.environ.get("GITHUB_TOKEN", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    pr = str(a.pr or _pr_number_from_env() or "")
    if a.dry_run or not (token and repo and pr):
        print(md)
        if not a.dry_run:
            print("# 未检测到 GITHUB_TOKEN / GITHUB_REPOSITORY / PR 号，已退化为 dry-run",
                  file=sys.stderr)
        return 0
    upsert_comment(repo, pr, token, md)
    print(f"# 已回贴 PR #{pr}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
