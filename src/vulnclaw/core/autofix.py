# -*- coding: utf-8 -*-  # noqa: UP009 - 平台统一文件头约定
# SPDX-License-Identifier: AGPL-3.0-or-later
"""自动修复补丁链路（对标 Strix auto-fix，但不自动 push：默认只产出补丁文件，零风险）。

- build_patch_plan: 把 report JSON 的 vulnerabilities 转为补丁计划（按 type 模板化）
- write_patch_files: 每条补丁写成 <out_dir>/patch_<idx>.patch，并汇总 autofix_manifest.json
- apply_patches: dry_run 默认开启只统计可应用数；dry_run=False 才真正落盘，且绝不自动 git commit
- main: 命令行入口 --report <json> --out-dir <dir> [--repo <path>] [--apply]

设计约束：纯 stdlib；无 emoji；所有异常降级（缺字段 / 坏 JSON / 文件不存在）不抛错，
统一记入 manifest 的 skipped 数组。
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sys

try:
    from vulnclaw.core.logger import logger
except Exception:  # noqa: BLE001 - 独立运行场景不强制依赖平台日志
    import logging as _logging

    logger = _logging.getLogger("vulnclaw.autofix")

# ===== 类型元信息：tier / 基础 confidence / 补丁模板 =====
_TYPE_INFO = {
    "sql_injection": {
        "tier": "critical",
        "confidence": 0.90,
        "summary": "使用参数化查询（cursor.execute(sql, params)），禁止拼接 SQL",
        "old": 'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        "new": [
            "# 修复 SQL 注入：改用参数化查询，禁止拼接 SQL（cursor.execute(sql, params) 形式）",
            'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        ],
    },
    "xss": {
        "tier": "high",
        "confidence": 0.85,
        "summary": "对不可信输出做 HTML 转义（html.escape / 输出编码）",
        "old": 'return "<div>" + user_input + "</div>"',
        "new": [
            "# 修复 XSS：对不可信输出做 HTML 转义，禁止直接拼接渲染",
            'return "<div>" + html.escape(user_input) + "</div>"',
        ],
    },
    "hardcoded_secret": {
        "tier": "critical",
        "confidence": 0.90,
        "summary": "移除硬编码密钥，改为从环境变量读取",
        "old": 'API_KEY = "sk-xxxxxxxxxxxxxxxxxxxxxxxx"',
        "new": [
            "# 修复硬编码密钥：改为从环境变量读取，禁止把密钥写入源码",
            'API_KEY = os.environ.get("API_KEY", "")',
        ],
    },
    "weak_credential": {
        "tier": "high",
        "confidence": 0.70,
        "summary": "弱口令加固：改用高强度随机密码并从环境变量注入",
        "old": 'password = "admin123"',
        "new": [
            "# 修复弱口令：使用高强度随机密码并从环境变量注入，禁止硬编码默认口令",
            'password = os.environ.get("APP_PASSWORD", "")',
        ],
    },
    "insecure_headers": {
        "tier": "medium",
        "confidence": 0.75,
        "summary": "配置加固：补齐安全响应头（X-Content-Type-Options / X-Frame-Options / CSP）",
        "old": None,
        "new": [
            "# 配置加固：补齐安全响应头",
            'response.headers["X-Content-Type-Options"] = "nosniff"',
            'response.headers["X-Frame-Options"] = "DENY"',
            'response.headers["Content-Security-Policy"] = "default-src \'self\'"',
        ],
    },
}

_TIER_DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "low"}

# 从 evidence / description 里提取源码文件路径的启发式正则
_FILE_RE = re.compile(
    r"[A-Za-z0-9_./\\-]+\.(?:py|js|ts|jsx|tsx|java|go|php|rb|c|cc|cpp|hpp|h|cs|sql|html|htm|sh|ps1|bat|ini|conf|cfg|yml|yaml|json)",
    re.IGNORECASE,
)
_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

_USAGE = "usage: vulnclaw autofix --report <report.json> --out-dir <dir> [--repo <path>] [--apply]"


def _normalize_type(raw):
    """把 finding 里的原始 type 归一化为模板键；无法识别返回 'unknown'。"""
    t = str(raw or "").strip().lower()
    if not t:
        return ""
    if ("sql" in t and "injection" in t) or t.startswith("sqli") or "sql-injection" in t:
        return "sql_injection"
    if any(k in t for k in ("xss", "cross-site", "cross site", "html injection")):
        return "xss"
    if any(k in t for k in ("weak password", "weak pass", "weak credential", "default password", "weak_pwd")):
        return "weak_credential"
    if any(k in t for k in ("hardcoded", "hard-coded", "hard coded", "api key", "apikey", "embedded secret", "secret in")):
        return "hardcoded_secret"
    if any(k in t for k in ("security header", "insecure header", "missing header", "clickjacking", "csp")):
        return "insecure_headers"
    return "unknown"


def _clean_file(raw):
    """清理文件路径：去引号、统一斜杠、去掉前导 ./ 与 /。"""
    s = str(raw or "").strip().strip("\"'`")
    s = s.replace("\\", "/")
    s = re.sub(r"^\./", "", s)
    s = s.lstrip("/")
    if not s or s.endswith(".pyc"):
        return ""
    return s


def _extract_file(finding):
    """从 evidence / description 里正则提取文件路径，找不到返回 ''。"""
    for key in ("evidence", "description"):
        text = str(finding.get(key) or "")
        if not text:
            continue
        for m in _FILE_RE.finditer(text):
            candidate = _clean_file(m.group(0))
            if candidate:
                return candidate
    return ""


def _line_hint(finding):
    """提取行号线索（字符串），没有返回 ''。"""
    for key in ("line", "line_number", "line_no", "start_line", "begin_line"):
        val = finding.get(key)
        if isinstance(val, (int, str)) and str(val).strip():
            return str(val).strip()
    for key in ("evidence", "description"):
        m = re.search(r"(?:line|L)\s*[:=#]?\s*(\d{1,6})", str(finding.get(key) or ""), re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def _hunk_line(line_hint):
    """把 line_hint 转成 hunk 起始行号，默认 1。"""
    m = re.search(r"\d{1,6}", str(line_hint or ""))
    return max(1, int(m.group(0))) if m else 1


def _confidence_tier(base_conf, base_tier, location):
    """按类型基础值 + 源码定位精度计算 (confidence, tier)。

    location: exact=有 file 字段 / heuristic=从 evidence 提取 / none=完全无法定位。
    """
    if location == "exact":
        return base_conf, base_tier
    if location == "heuristic":
        return round(base_conf * 0.7, 2), _TIER_DOWNGRADE[base_tier]
    return round(base_conf * 0.4, 2), _TIER_DOWNGRADE[_TIER_DOWNGRADE[base_tier]]


def _build_diff(file_path, line_hint, info):
    """生成统一 diff 格式补丁：--- a/  +++ b/  @@ 头 + 行内容。"""
    ln = _hunk_line(line_hint)
    new = info["new"]
    n_new = len(new)
    if info.get("old"):
        count = f",{n_new}" if n_new > 1 else ""
        lines = [f"--- a/{file_path}", f"+++ b/{file_path}", f"@@ -{ln} +{ln}{count} @@", f"-{info['old']}"]
    else:
        lines = [f"--- a/{file_path}", f"+++ b/{file_path}", f"@@ -{ln},0 +{ln},{n_new} @@"]
    lines += [f"+{n}" for n in new]
    return "\n".join(lines) + "\n"


def _build_suggestion(norm, info):
    """无源码定位时的建议文本补丁（纯说明，不含 diff 头）。"""
    lines = [
        f"# 修复建议（{norm}）：{info['summary']}",
        "# 未能定位源码文件（finding 缺少 file 字段，且 evidence/description 中未提取到路径），",
        "# 请人工定位后参考以下补丁模板应用：",
        f"# -{info['old']}",
    ]
    lines += [f"# +{n}" for n in info["new"]]
    return "\n".join(lines) + "\n"


def _build_remediation_patch(file_path, line_hint, remediation):
    """未知类型：引用 report 的 remediation 文本作为补丁说明（confidence 低）。"""
    body = remediation or "参考报告中的 remediation 字段进行人工修复。"
    body_lines = body.splitlines() or [body]
    if file_path:
        ln = _hunk_line(line_hint)
        lines = [
            f"--- a/{file_path}",
            f"+++ b/{file_path}",
            f"@@ -{ln},0 +{ln},{len(body_lines) + 1} @@",
            "+ # 修复建议（引用报告 remediation，confidence 低，请人工确认）：",
        ]
        lines += [f"+ # {b}" for b in body_lines]
        return "\n".join(lines) + "\n"
    lines = ["# 修复建议（引用报告 remediation，confidence 低，请人工确认）："]
    lines += [f"# {b}" for b in body_lines]
    lines.append("# 未能定位源码文件，请人工定位后修复。")
    return "\n".join(lines) + "\n"


def _build_plan_item(finding, idx, repo_root):
    """把单条 finding 转成补丁计划项。repo_root 保留给签名，plan 阶段不做文件存在性校验。"""
    norm = _normalize_type(finding.get("type"))
    finding_id = str(finding.get("finding_id") or finding.get("id") or f"finding_{idx + 1}")
    severity = str(finding.get("severity") or "unknown")
    line_hint = _line_hint(finding)
    remediation = str(finding.get("remediation") or "").strip()

    file_field = finding.get("file")
    if isinstance(file_field, str) and file_field.strip():
        file_path = _clean_file(file_field)
        location = "exact"
    else:
        file_path = _extract_file(finding)
        location = "heuristic" if file_path else "none"

    if not norm and not remediation:
        return {
            "finding_id": finding_id,
            "type": "unknown",
            "severity": severity,
            "file": "",
            "line_hint": line_hint,
            "patch": "",
            "confidence": 0.0,
            "tier": "low",
            "skipped": True,
            "skipped_reason": "missing type and remediation",
        }

    key = norm if norm else "unknown"
    info = _TYPE_INFO.get(key)
    base_conf = info["confidence"] if info else 0.30
    base_tier = info["tier"] if info else "low"
    confidence, tier = _confidence_tier(base_conf, base_tier, location)

    if norm and info:
        patch = _build_diff(file_path, line_hint, info) if file_path else _build_suggestion(norm, info)
    else:
        patch = _build_remediation_patch(file_path, line_hint, remediation)

    item = {
        "finding_id": finding_id,
        "type": key,
        "severity": severity,
        "file": file_path,
        "line_hint": line_hint,
        "patch": patch,
        "confidence": confidence,
        "tier": tier,
    }
    if not file_path:
        item["suggestion_only"] = True
    return item


def build_patch_plan(report_data, repo_root=""):
    """遍历 report 的 vulnerabilities 生成补丁计划（list[dict]）。

    缺字段 / 非 dict / 空列表均不抛错，返回 [] 或带 skipped 标记的计划项。
    """
    if not isinstance(report_data, dict):
        return []
    findings = report_data.get("vulnerabilities")
    if not isinstance(findings, list):
        return []
    plan = []
    for idx, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue
        plan.append(_build_plan_item(finding, idx, repo_root))
    return plan


def _manifest_entry(item):
    return {
        "finding_id": item.get("finding_id"),
        "type": item.get("type"),
        "severity": item.get("severity"),
        "file": item.get("file"),
        "line_hint": item.get("line_hint"),
        "tier": item.get("tier"),
        "confidence": item.get("confidence"),
        "suggestion_only": bool(item.get("suggestion_only")),
    }


def write_patch_files(plan, out_dir):
    """把每条补丁写成 <out_dir>/patch_<idx>.patch，并写 autofix_manifest.json 汇总。

    返回补丁文件绝对路径列表；写失败的条目与 skipped 条目记入 manifest.skipped。
    """
    out_dir = os.fspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    written = []
    skipped = []
    summary = []
    for idx, item in enumerate(plan or [], start=1):
        entry = _manifest_entry(item)
        if item.get("skipped"):
            entry["skipped_reason"] = item.get("skipped_reason", "skipped")
            skipped.append(entry)
            continue
        path = os.path.join(out_dir, f"patch_{idx}.patch")
        try:
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(str(item.get("patch") or ""))
        except OSError as exc:
            entry["skipped_reason"] = f"write error: {exc}"
            skipped.append(entry)
            continue
        entry["patch_file"] = os.path.abspath(path)
        written.append(entry["patch_file"])
        summary.append(entry)

    manifest = {
        "generated_at": _dt.datetime.now(_dt.UTC).isoformat(timespec="seconds"),
        "count": len(plan or []),
        "patch_count": len(written),
        "skipped_count": len(skipped),
        "patches": written,
        "skipped": skipped,
        "plan": summary,
    }
    try:
        with open(os.path.join(out_dir, "autofix_manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
            json.dump(manifest, fh, ensure_ascii=False, indent=2, default=str)
    except OSError:
        pass  # manifest 写失败不阻断（补丁文件已产出）
    return written


def _resolve_target(file_rel, repo_root):
    """把补丁里的相对路径解析为磁盘绝对路径（优先拼 repo_root）。"""
    if os.path.isabs(file_rel):
        return os.path.abspath(file_rel)
    norm = re.sub(r"^\./", "", file_rel.replace("\\", "/")).lstrip("/")
    if repo_root:
        return os.path.join(os.fspath(repo_root), norm.replace("/", os.sep))
    return os.path.abspath(norm)


def _find_line(lines, target, old_start):
    """在文件行里定位目标行：先查 hunk 行号附近，再全文件扫描。"""
    target_r = target.rstrip("\r")
    candidates = [old_start - 1]
    for off in range(1, 6):
        candidates.append(old_start - 1 - off)
        candidates.append(old_start - 1 + off)
    for idx in candidates:
        if 0 <= idx < len(lines) and lines[idx].rstrip("\r") == target_r:
            return idx
    for idx, ln in enumerate(lines):
        if ln.rstrip("\r") == target_r:
            return idx
    return None


def _apply_diff(text, patch_text):
    """把统一 diff 应用到文本；返回 (新文本, 是否成功, 备注)。

    模板补丁为单 hunk 简单场景：- 行做替换，纯 + 行做插入；行号失效即放弃该补丁。
    """
    lines = text.split("\n")
    patch_lines = patch_text.split("\n")
    changed = 0
    i = 0
    while i < len(patch_lines):
        m = _HUNK_RE.match(patch_lines[i])
        if not m:
            i += 1
            continue
        old_start = int(m.group(1))
        i += 1
        old_lines = []
        new_lines = []
        while i < len(patch_lines) and not patch_lines[i].startswith("@@"):
            pl = patch_lines[i]
            if pl.startswith("-") and not pl.startswith("---"):
                old_lines.append(pl[1:])
            elif pl.startswith("+") and not pl.startswith("+++"):
                new_lines.append(pl[1:])
            i += 1
        if old_lines:
            idx = _find_line(lines, old_lines[0], old_start)
            if idx is None:
                return text, False, f"line not found for {old_lines[0]!r}"
            lines[idx:idx + len(old_lines)] = new_lines
        else:
            idx = min(max(old_start - 1, 0), len(lines))
            lines[idx:idx] = new_lines
        changed += 1
    return "\n".join(lines), changed > 0, "ok"


def apply_patches(plan, repo_root, dry_run=True):
    """把补丁应用到对应文件。

    默认 dry_run=True 只统计可应用补丁数；dry_run=False 才实际写入。
    文件不存在 / 行号失效 / 读写失败一律跳过并记入结果 skipped，绝不自动 git commit。
    返回 {"dry_run", "total", "applicable", "applied", "skipped"}。
    """
    result = {"dry_run": bool(dry_run), "total": 0, "applicable": 0, "applied": 0, "skipped": []}
    for item in plan or []:
        if item.get("skipped"):
            continue
        file_rel = str(item.get("file") or "").strip()
        patch_text = str(item.get("patch") or "")
        finding_id = item.get("finding_id")
        if not file_rel or not patch_text.startswith("--- a/"):
            continue  # 建议文本类，无法机械应用
        result["total"] += 1
        target = _resolve_target(file_rel, repo_root)
        if not os.path.isfile(target):
            result["skipped"].append({"finding_id": finding_id, "file": file_rel, "reason": "file not found"})
            continue
        try:
            with open(target, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError as exc:
            result["skipped"].append({"finding_id": finding_id, "file": file_rel, "reason": f"read error: {exc}"})
            continue
        new_text, ok, note = _apply_diff(text, patch_text)
        if not ok:
            result["skipped"].append({"finding_id": finding_id, "file": file_rel, "reason": note})
            continue
        if dry_run:
            result["applicable"] += 1
            continue
        try:
            with open(target, "w", encoding="utf-8", newline="") as fh:
                fh.write(new_text)
        except OSError as exc:
            result["skipped"].append({"finding_id": finding_id, "file": file_rel, "reason": f"write error: {exc}"})
            continue
        result["applicable"] += 1
        result["applied"] += 1
    return result


def main(argv=None):
    """命令行入口：vulnclaw autofix --report <json> --out-dir <dir> [--repo <path>] [--apply]。"""
    argv = list(sys.argv[1:] if argv is None else argv)
    report_path = ""
    out_dir = "autofix_out"
    repo_root = ""
    do_apply = False
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--report" and i + 1 < len(argv):
            report_path = argv[i + 1]
            i += 2
        elif arg == "--out-dir" and i + 1 < len(argv):
            out_dir = argv[i + 1]
            i += 2
        elif arg == "--repo" and i + 1 < len(argv):
            repo_root = argv[i + 1]
            i += 2
        elif arg == "--apply":
            do_apply = True
            i += 1
        else:
            i += 1
    if not report_path:
        print(_USAGE)
        return 2
    try:
        with open(report_path, "r", encoding="utf-8") as fh:
            report_data = json.load(fh)
    except (OSError, ValueError) as exc:
        logger.warning("autofix: 读取报告失败，按空报告降级处理: %s", exc)
        report_data = {}
    plan = build_patch_plan(report_data, repo_root)
    written = write_patch_files(plan, out_dir)
    result = apply_patches(plan, repo_root, dry_run=not do_apply)
    mode = "apply" if do_apply else "dry-run"
    print(
        f"[autofix] mode={mode} plan={len(plan)} patches={len(written)} "
        f"applicable={result['applicable']} applied={result['applied']}"
    )
    logger.info(
        "autofix done: plan=%d patches=%d applicable=%d applied=%d",
        len(plan), len(written), result["applicable"], result["applied"],
    )
    return 0
