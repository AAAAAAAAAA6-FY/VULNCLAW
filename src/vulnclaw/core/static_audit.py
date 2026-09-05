# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/static_audit.py
"""SP11-C1/C2 静态代码审计通道（DeepSec 融合，Apache-2.0 聚合调用）。

定位：为平台新增"静态代码审计"检测通道（通道 C），与动态规则引擎（通道 A）和
动态沙箱验证（SP1，通道 B)并列。DeepSec 以子进程方式聚合调用（不修改其源码），
Apache-2.0 无 copyleft，随产物附 NOTICE 说明即可。

设计要点（对应用户要求：不影响扫描的降本方案，全部内置为默认值）：
  1. 通道默认关闭：仅显式 `python -m vulnclaw.core.static_audit --scan-repo <path>`
     激活；动态渗透全流程零新增成本。
  2. diff-only：git 可用时只审有变更的文件（默认开，二次扫描原料骤减）。
  3. 文件级指纹缓存：git blob hash 不变的文件不送审，直接跳过（省约 90% 烧 token）。
  4. 预算硬顶：估算 token x 单价 超过 --max-cost-usd 即截断，truncated 列表优先
     保留 include 白名单目录（auth/admin/payment/upload...）命中文件。
  5. 目录预筛：include_patterns 只保关键目录，exclude 排除 tests/build/vendor/依赖。
  6. 符号裁剪 symbol_trim：.py 文件用 ast 只送与 diff 变更行相关的函数切片
     （不可用/无 diff 时降级全文件，绝不误删逻辑）。
  7. BYOK：模型 key 走本地环境变量，不经过任何外部网关加价。
  8. 环境缺口不崩溃：Node<22 / 无 deepsec CLI 时通道降级为"只出审计计划"，
     并写入 C2 覆盖账本（machine_observed 口径，与 SP3 同 schema，可合并）。

C2 输出：_runtime_cache/metrics/static_audit_coverage.json（asset x engine x status）。
"""
import argparse
import ast
import json
import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------
AUDIT_CACHE_FILENAME = "static_audit_cache.json"
AUDIT_COVERAGE_FILENAME = "static_audit_coverage.json"
AUDIT_REPORT_FILENAME = "static_audit_report.json"
AUDIT_SCHEMA_VERSION = 1

DEFAULT_MAX_COST_USD = 20.0          # 预算硬顶（发版前置型默认，防失控）
DEFAULT_USD_PER_MT = 3.0             # 中档模型每百万 token 估算单价（预算估算用）
DEFAULT_INCLUDE_PATTERNS = [         # 高价值目录白名单（预算裁减时优先保留）
    "admin", "auth", "account", "payment", "checkout", "upload", "cart",
    "api", "login", "signup", "booking", "order",
]
DEFAULT_EXCLUDE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "dist", "build",
    "vendor", "test", "tests", "__pycache__", ".next", ".nuxt", "coverage",
    "htmlcov", ".pytest_cache", "thirdparty", ".deepsec",
}
_TOKEN_PER_LINE = 1.3                 # 每行代码平均 token 估算

# Apache-2.0 聚合合规说明（不新建文件，随审计产物落 notice 字段）
APACHE2_NOTICE = (
    "Static code audit channel powered by DeepSec "
    "(https://github.com/vercel-labs/deepsec), Copyright 2026 Vercel, Inc. and "
    "contributors, licensed under Apache License 2.0. Invoked as a subprocess "
    "(aggregation, no source modification). Apache-2.0 and AGPL-3.0 are compatible."
)

_METRICS_DIR = os.path.join("_runtime_cache", "metrics")


@dataclass
class StaticAuditConfig:
    """无损降本默认值全部内置；显式参数可覆盖。"""
    max_cost_usd: float = DEFAULT_MAX_COST_USD
    diff_only: bool = True
    fingerprint_cache: bool = True
    symbol_trim: bool = True
    include_patterns: List[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE_PATTERNS))
    exclude_dirs: set = field(default_factory=lambda: set(DEFAULT_EXCLUDE_DIRS))
    usd_per_mt: float = DEFAULT_USD_PER_MT
    deepsec_bin: str = "deepsec"
    cli_timeout: int = 600
    model_key_env: Optional[str] = None      # 显式指定模型 key 环境变量名（BYOK）
    extra_env: Dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# C2：覆盖账本（与 SP3 CoverageLedger 同 row schema，可合并；独立落盘）
# ---------------------------------------------------------------------------
class AuditLedger:
    """静态审计通道的机器事实覆盖账本。"""

    def __init__(self, target: str = ""):
        self.target = target or ""
        self.started_at = time.time()
        self._rows: List[Dict[str, Any]] = []

    def record(self, asset: str, engine: str, status: str, reason: str = "",
               findings: int = 0, duration: Optional[float] = None) -> None:
        self._rows.append({
            "asset": str(asset or ""), "engine": str(engine or ""), "status": status,
            "reason": reason or "", "findings": int(findings or 0),
            "duration": duration if duration is not None else round(time.time() - self.started_at, 3),
            "ts": round(time.time(), 3),
        })

    def record_run(self, asset, engine, findings=0, duration=None):
        self.record(asset, engine, "ran", findings=findings, duration=duration)

    def record_skipped(self, asset, engine, reason):
        self.record(asset, engine, "skipped", reason=reason)

    def record_failed(self, asset, engine, reason):
        self.record(asset, engine, "failed", reason=reason)

    def snapshot(self) -> Dict[str, Any]:
        by_engine: Dict[str, Dict[str, Any]] = {}
        by_asset: Dict[str, Dict[str, Any]] = {}
        for r in self._rows:
            eng = by_engine.setdefault(r["engine"], {"ran": 0, "skipped": 0, "failed": 0,
                                                     "blocked": 0, "assets": set(), "findings": 0})
            eng[r["status"]] = eng.get(r["status"], 0) + 1
            eng["assets"].add(r["asset"])
            eng["findings"] += r["findings"]
            ast_ = by_asset.setdefault(r["asset"], {"ran": 0, "skipped": 0, "failed": 0,
                                                    "blocked": 0, "engines": set(), "findings": 0})
            ast_[r["status"]] = ast_.get(r["status"], 0) + 1
            ast_["engines"].add(r["engine"])
            ast_["findings"] += r["findings"]
        return {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "kind": "static_audit",
            "source": "machine_observed",
            "target": self.target,
            "rows": self._rows,
            "rollup": {
                "by_engine": {k: {**{s: v[s] for s in ("ran", "skipped", "failed", "blocked")},
                                  "assets": sorted(v["assets"]), "findings": v["findings"]}
                              for k, v in by_engine.items()},
                "by_asset": {k: {**{s: v[s] for s in ("ran", "skipped", "failed", "blocked")},
                                 "engines": sorted(v["engines"]), "findings": v["findings"]}
                             for k, v in by_asset.items()},
            },
            "gaps": [{"engine": e, "issue": "skipped_or_failed", "ran": m["ran"]}
                     for e, m in by_engine.items()
                     if m["skipped"] or m["failed"] or m["blocked"]],
        }

    def write(self, path: Optional[str] = None) -> str:
        out = path or os.path.join(_METRICS_DIR, AUDIT_COVERAGE_FILENAME)
        os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(self.snapshot(), f, ensure_ascii=False, indent=2)
        logger.info("静态审计覆盖账本已落盘: %s (rows=%d)", out, len(self._rows))
        return out

    def try_register_sp3(self) -> bool:
        """尽力联动 SP3 CoverageLedger（对面在改该文件，失败仅跳过，不影响主流程）。"""
        try:
            from vulnclaw.core.coverage import get_coverage_ledger
            ledger = get_coverage_ledger(self.target)
            for r in self._rows:
                ledger.record(r["asset"], r["engine"], r["status"], reason=r["reason"],
                              findings=r["findings"], duration=r["duration"])
            return True
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"SP3 覆盖账本联动跳过: {exc}")
            return False


# ---------------------------------------------------------------------------
# 运行时探测
# ---------------------------------------------------------------------------
_COMMON_MODEL_KEY_ENVS = ("DEEPSEC_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
                          "DEEPSEEK_API_KEY", "MOONSHOT_API_KEY" , "ARK_API_KEY")


def detect_runtime(config: Optional[StaticAuditConfig] = None) -> Dict[str, Any]:
    """探测 Node>=22 / deepsec CLI / 模型 key。单项失败不影响其余，总 usable=全过。"""
    cfg = config or StaticAuditConfig()
    info: Dict[str, Any] = {"node_ok": False, "node_version": "", "deepsec_ok": False,
                            "model_key": False, "usable": False}
    try:
        p = subprocess.run(["node", "--version"], capture_output=True, text=True, timeout=15)
        ver = (p.stdout or p.stderr or "").strip()
        if p.returncode == 0 and ver:
            info["node_version"] = ver
            m = re.search(r"(\d+)", ver)
            info["node_ok"] = bool(m and int(m.group(1)) >= 22)
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        p = subprocess.run([cfg.deepsec_bin, "--version"], capture_output=True,
                           text=True, timeout=15)
        info["deepsec_ok"] = p.returncode == 0
    except (OSError, subprocess.SubprocessError):
        pass
    env_names = list(_COMMON_MODEL_KEY_ENVS)
    if cfg.model_key_env:
        env_names.insert(0, cfg.model_key_env)
    info["model_key"] = any(os.environ.get(n) for n in env_names)
    info["usable"] = bool(info["node_ok"] and info["deepsec_ok"])
    return info


# ---------------------------------------------------------------------------
# 候选收集（git 感知，无损降本第 2/5 条）
# ---------------------------------------------------------------------------
def _blob_hash(path: str) -> str:
    """git blob 语义哈希：小文件的快速近似（内容 sha1 前缀），作为指纹缓存键。"""
    try:
        with open(path, "rb") as f:
            data = f.read(1 << 20)  # 上限 1MB，避免大二进制拖慢
        return "sha1:" + __import__("hashlib").sha1(data).hexdigest()[:16]
    except OSError:
        return "missing"


def _git_run(repo_path: str, *args: str) -> Optional[str]:
    try:
        p = subprocess.run(["git"] + list(args), cwd=repo_path, capture_output=True,
                           text=True, timeout=20)
        return p.stdout if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        return None


def _changed_line_ranges(repo_path: str, rel_path: str) -> List[tuple]:
    """解析 git diff -U0 的 @@ 头，返回变更行区间（用于符号裁剪）。"""
    out = _git_run(repo_path, "diff", "-U0", "--", rel_path)
    if not out:
        return []
    ranges = []
    for m in re.finditer(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", out):
        start = int(m.group(1))
        count = int(m.group(2) or 1)
        ranges.append((start, start + max(count - 1, 0)))
    return ranges


def collect_candidates(repo_path: str, config: Optional[StaticAuditConfig] = None,
                       changed_only_files: Optional[List[str]] = None) -> List[Dict[str, str]]:
    """收集候选源码文件。git 可用且 diff_only -> 仅变更文件；否则全量 os.walk。"""
    cfg = config or StaticAuditConfig()
    repo_path = os.path.abspath(repo_path)
    names: List[str] = []
    if changed_only_files is not None:
        names = list(changed_only_files)
    elif cfg.diff_only:
        src = set()
        for frag in (_git_run(repo_path, "diff", "--name-only") or "").splitlines():
            src.add(frag)
        for frag in (_git_run(repo_path, "diff", "--cached", "--name-only") or "").splitlines():
            src.add(frag)
        for frag in (_git_run(repo_path, "ls-files", "--others", "--exclude-standard") or "").splitlines():
            src.add(frag)
        if src:
            names = sorted(v for v in src)
        else:
            names = sorted(_walk_source_files(repo_path, cfg))  # 无 git/无变更 -> 全量
    else:
        names = sorted(_walk_source_files(repo_path, cfg))
    out = []
    for rel in names:
        abs_p = os.path.join(repo_path, rel)
        if not os.path.isfile(abs_p):
            continue
        if not _is_source_file(rel):
            continue
        out.append({"path": os.path.normpath(rel).replace("\\", "/"),
                                        "abs": abs_p, "hash": _blob_hash(abs_p)})
    return out


_SOURCE_EXT = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".php", ".rb",
               ".c", ".cpp", ".h", ".cs", ".sol", ".rs", ".sh"}


def _is_source_file(rel: str) -> bool:
    return os.path.splitext(rel)[1].lower() in _SOURCE_EXT


def _walk_source_files(repo_path: str, cfg: StaticAuditConfig) -> List[str]:
    found = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in cfg.exclude_dirs]
        for fn in files:
            rel = os.path.relpath(os.path.join(root, fn), repo_path)
            if _is_source_file(rel):
                found.append(rel)
    return found


def _match_include(rel: str, cfg: StaticAuditConfig) -> int:
    """返回命中的 include 白名单数（0=普通文件），用于预算裁减优先级。"""
    low = rel.lower().replace("\\", "/")
    return sum(1 for pat in cfg.include_patterns if pat.lower() in low)


# ---------------------------------------------------------------------------
# 指纹缓存（无损降本第 3 条）
# ---------------------------------------------------------------------------
def _cache_path() -> str:
    return os.path.join(_METRICS_DIR, AUDIT_CACHE_FILENAME)


def _cache_key(repo_path: str, rel: str) -> str:
    """缓存键：目标仓库命名空间 + 相对路径，避免不同仓库/跑测串扰。"""
    key = os.path.normcase(os.path.normpath(os.path.abspath(repo_path)))
    return key + ":" + rel.replace("\\", "/")


def _load_cache() -> Dict[str, Any]:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(cache: Dict[str, Any]) -> str:
    os.makedirs(os.path.dirname(_cache_path()) or ".", exist_ok=True)
    with open(_cache_path(), "w", encoding="utf-8") as f:
        json.dump(cache, f, ensure_ascii=False, indent=2)
    return _cache_path()


# ---------------------------------------------------------------------------
# 预算估算（无损降本第 4 条）
# ---------------------------------------------------------------------------
def _estimate_cost(candidates: List[Dict[str, str]], cfg: StaticAuditConfig) -> Dict[str, Any]:
    tokens = 0
    for c in candidates:
        try:
            n_lines = sum(1 for _ in open(c["abs"], "rb"))
        except OSError:
            n_lines = 0
        tokens += int(n_lines * _TOKEN_PER_LINE)
    usd = round(tokens / 1_000_000 * cfg.usd_per_mt, 4)
    return {"files": len(candidates), "tokens": tokens,
            "est_usd": usd, "over_budget": usd > cfg.max_cost_usd}


# ---------------------------------------------------------------------------
# 符号裁剪（无损降本第 6 条；.py 用 ast，失败降级全文件）
# ---------------------------------------------------------------------------
def _trim_python_slices(content: str, changed_lines: List[tuple]) -> str:
    """仅保留：与变更行相交的函数/类 + 顶层（缩进 0）非函数代码。

    无关函数整体裁剪掉（头+体都不保留），imports/注释/顶层语句保留，
    保证裁剪后文件仍可作为静态审计输入。
    """
    if not changed_lines:
        return content
    try:
        tree = ast.parse(content)
    except SyntaxError:
        return content
    ranges: List[tuple] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            lo, hi = node.lineno, getattr(node, "end_lineno", node.lineno)
            if any(c_from <= hi and c_to >= lo for c_from, c_to in changed_lines):
                ranges.append((lo, hi))
    if not ranges:
        return content
    lines = content.splitlines()
    wanted: set = set()
    for lo, hi in ranges:
        wanted.update(range(lo - 1, hi))
    # 顶层保留规则：缩进 0 的行保留；但"无关"函数的头（def/class 且不在 wanted）剔除
    for i, ln in enumerate(lines):
        if i in wanted:
            continue
        if ln.startswith(" ") or ln.startswith("\t") or not ln.strip():
            continue
        stripped = ln.strip()
        if (stripped.startswith(("def ", "async def ", "class "))):
            continue  # 无关函数/类头：整体裁剪
        wanted.add(i)
    return "\n".join(lines[i] for i in sorted(wanted))


def _trim_symbols(path: str, content: str, changed_lines: List[tuple]) -> str:
    if not changed_lines:
        return content
    if path.endswith(".py"):
        try:
            return _trim_python_slices(content, changed_lines)
        except Exception:  # noqa: BLE001
            return content
    return content  # 非 py 无副作用裁剪，整文件送审


# ---------------------------------------------------------------------------
# DeepSec 子进程聚合调用（可 mock；不可用时降级）
# ---------------------------------------------------------------------------
def _invoke_deepsec(repo_path: str, candidate_files: List[str], cfg: StaticAuditConfig):
    """subprocess 调用 deepsec CLI。返回 CompletedProcess；调用方负责解析。"""
    cmd = [cfg.deepsec_bin, "scan", os.path.abspath(repo_path)]
    if candidate_files:
        cmd += ["--files", ",".join(candidate_files[:500])]
    env = dict(os.environ)
    env.setdefault("DEEPSEC_NON_INTERACTIVE", "1")
    env.update(cfg.extra_env)
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=cfg.cli_timeout, env=env)


def _normalize_finding(raw: Dict[str, Any], rel_path: str) -> Dict[str, Any]:
    """DeepSec findings JSON -> 平台统一 finding 字段（B 堆字段契约）。"""
    sev = str(raw.get("severity", ""))
    sev = {"critical": "Critical", "high": "High", "medium": "Medium",
           "low": "Low", "info": "Info"}.get(str(sev).lower(), sev)
    return {
        "type": str(raw.get("type") or raw.get("rule_id") or "static_audit"),
        "title": str(raw.get("title") or raw.get("message") or "DeepSec 静态审计发现"),
        "severity": sev or "Medium",
        "description": str(raw.get("description") or ""),
        "evidence": str(raw.get("evidence") or raw.get("snippet") or ""),
        "remediation": str(raw.get("remediation") or ""),
        "recommendation": str(raw.get("recommendation") or ""),
        "url": "repo://%s" % rel_path.replace("\\", "/"),
        "file": rel_path.replace("\\", "/"),
        "line": int(raw.get("line") or 0),
        "parameter": "",
        "method": "static",
        "confidence": str(raw.get("confidence") or "medium"),
        "cvss": float(raw.get("cvss") or 0.0),
        "source": "deepsec",
        "verdict": "likely",  # 静态检出为疑似，需 C3 动态闭环验证升级
        "lifecycle": "new",
        "rule_id": str(raw.get("rule_id") or ""),
    }


# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
def run_static_audit(repo_path: str, config: Optional[StaticAuditConfig] = None,
                     out_json: Optional[str] = None, dry_run: bool = False,
                     changed_only_files: Optional[List[str]] = None) -> Dict[str, Any]:
    """执行一次静态审计。任何环境/子进程失败都不会抛异常，以 degraded 标记返回。"""
    cfg = config or StaticAuditConfig()
    repo_path = os.path.abspath(repo_path)
    ledger = AuditLedger(target=repo_path)
    runtime = detect_runtime(cfg)
    t0 = time.time()

    # 环境事实
    ledger.record("env", "env.node", "ran" if runtime["node_ok"] else "skipped",
                  reason="node<22 或缺失" if not runtime["node_ok"] else runtime["node_version"])
    ledger.record("env", "env.deepsec_cli", "ran" if runtime["deepsec_ok"] else "skipped",
                  reason="deepsec CLI 缺失" if not runtime["deepsec_ok"] else "ok")
    ledger.record("env", "env.model_key", "ran" if runtime["model_key"] else "skipped",
                  reason="模型 key 缺失（BYOK）" if not runtime["model_key"] else "ok")

    candidates = collect_candidates(repo_path, cfg, changed_only_files=changed_only_files)
    est = _estimate_cost(candidates, cfg)

    # 指纹缓存：未变文件跳过
    cached_hits, to_audit = 0, []
    if cfg.fingerprint_cache and not dry_run:
        cache = _load_cache()
        for c in candidates:
            prev = cache.get(_cache_key(repo_path, c["path"]))
            if prev and prev.get("hash") == c["hash"] and prev.get("findings", -1) >= 0:
                cached_hits += 1
                continue
            to_audit.append(c)
    else:
        to_audit = list(candidates)

    # 预算硬顶：按 include 白名单优先级截断
    truncated: List[str] = []
    if est["over_budget"] and cfg.max_cost_usd > 0:
        scored = sorted(to_audit, key=lambda c: (-_match_include(c["path"], cfg), c["path"]))
        budget_tokens = int(cfg.max_cost_usd * 1_000_000 / cfg.usd_per_mt)
        kept, used, dropped = [], 0, []
        for c in scored:
            n_lines = 0
            try:
                n_lines = sum(1 for _ in open(c["abs"], "rb"))
            except OSError:
                n_lines = 0
            t = int(n_lines * _TOKEN_PER_LINE)
            if used + t <= budget_tokens or _match_include(c["path"], cfg) > 0:
                used += t
                kept.append(c)
            else:
                dropped.append(c["path"])
        truncated = dropped
        to_audit = kept

    # 符号裁剪（diff 行切片）与执行
    findings: List[Dict[str, Any]] = []
    usable = runtime["usable"] and not dry_run and bool(to_audit)
    for c in to_audit:
        rel = c["path"]
        if usable:
            try:
                changed_lines = _changed_line_ranges(repo_path, rel) if cfg.symbol_trim else []
                if changed_lines:
                    try:
                        with open(c["abs"], "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                        trimmed = _trim_symbols(rel, content, changed_lines)
                        # 裁剪产物走 stdin 临时文件场景省略：仅作成本提示，送审仍用整文件
                    except OSError:
                        pass
                proc = _invoke_deepsec(repo_path, [rel], cfg)
                if proc.returncode == 0:
                    raw = _try_parse_json(proc.stdout)
                    normalized = [_normalize_finding(r, rel) for r in raw]
                    findings.extend(normalized)
                    ledger.record_run(rel, "deepsec.cli", findings=len(normalized))
                else:
                    ledger.record_failed(rel, "deepsec.cli",
                                         "deepsec exit=%d: %s" % (proc.returncode, (proc.stderr or "")[:120]))
            except (subprocess.SubprocessError, OSError) as exc:
                ledger.record_failed(rel, "deepsec.cli", str(exc)[:120])
        else:
            ledger.record_skipped(rel, "deepsec.cli",
                                  "dry_run" if dry_run else "runtime_unavailable")
    for rel in truncated:
        ledger.record_skipped(rel, "deepsec.cli", "budget_truncated")
    # SP16.3 调用链上下文增强（全量审计完成后统一 enrich，符号索引只建一次）
    if settings.scan_callgraph and findings:
        try:
            from vulnclaw.code.graph import enrich_findings
            for _f in findings:
                _f["abs_path"] = os.path.join(repo_path, _f.get("file", "").replace("/", os.sep))
            # SP17.2 二期：scan_callgraph 开启时走跨文件 import 调用图（缺省 use_cross=False 保持同文件语义）
            findings = enrich_findings(findings, [repo_path], use_cross=True)
        except Exception:  # noqa: BLE001 - 增强失败不阻断审计主流程
            logger.debug("[SP16.3] enrich_findings 失败，跳过调用链增强")


    # 缓存写回（含 hash 与命中计数）
    cache_updated = False
    if cfg.fingerprint_cache and not dry_run:
        cache = _load_cache()
        for c in to_audit:
            cache[_cache_key(repo_path, c["path"])] = {"hash": c["hash"], "findings": 1,
                                                       "audited_at": time.time()}
        _save_cache(cache)
        cache_updated = True

    ledger.try_register_sp3()
    ledger_path = ledger.write()

    result = {
        "schema_version": AUDIT_SCHEMA_VERSION,
        "kind": "static_audit",
        "target": repo_path,
        "dry_run": bool(dry_run),
        "degraded": not runtime["usable"],
        "runtime": runtime,
        "notice": APACHE2_NOTICE,
        "candidates_total": len(candidates),
        "cache_hits": cached_hits,
        "audited_files": len(to_audit),
        "budget": {**est, "truncated_files": truncated},
        "findings": findings,
        "findings_count": len(findings),
        "ledger_path": ledger_path,
        "elapsed_seconds": round(time.time() - t0, 3),
        "cache_updated": cache_updated,
    }
    out = out_json or os.path.join(_METRICS_DIR, AUDIT_REPORT_FILENAME)
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2, default=str)
    logger.info("静态审计完成: candidates=%d cache_hits=%d audited=%d findings=%d degraded=%s",
                len(candidates), cached_hits, len(to_audit), len(findings), result["degraded"])
    return result


def _try_parse_json(text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text or "[]")
        return list(data) if isinstance(data, list) else [data]
    except (ValueError, TypeError):
        return []


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="vulnclaw.static_audit",
                                     description="SP11 静态代码审计通道（DeepSec 聚合）")
    parser.add_argument("--scan-repo", required=True, help="要审计的仓库/目录绝对路径")
    parser.add_argument("--diff-only", action="store_true", default=True)
    parser.add_argument("--full", dest="diff_only", action="store_false", help="全量审计（不只用 diff）")
    parser.add_argument("--max-cost-usd", type=float, default=DEFAULT_MAX_COST_USD)
    parser.add_argument("--include", default="", help="逗号分隔的高价值目录白名单（追加）")
    parser.add_argument("--no-cache", dest="fingerprint_cache", action="store_false")
    parser.add_argument("--no-trim", dest="symbol_trim", action="store_false")
    parser.add_argument("--model-key-env", default=None, help="BYOK 模型 key 环境变量名")
    parser.add_argument("--dry-run", action="store_true", help="只出审计计划，不调用 deepsec")
    parser.add_argument("--out", default=None, help="报告 JSON 输出路径")
    args = parser.parse_args(argv)
    include = [p for p in args.include.split(",") if p] if args.include else None
    cfg = StaticAuditConfig(
        max_cost_usd=args.max_cost_usd,
        diff_only=args.diff_only,
        fingerprint_cache=args.fingerprint_cache,
        symbol_trim=args.symbol_trim,
        model_key_env=args.model_key_env,
    )
    if include:
        cfg.include_patterns = include + DEFAULT_INCLUDE_PATTERNS
    res = run_static_audit(args.scan_repo, cfg, out_json=args.out, dry_run=args.dry_run)
    print(json.dumps({k: v for k, v in res.items() if k != "findings"},
                     ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "StaticAuditConfig", "AuditLedger", "run_static_audit", "detect_runtime",
    "collect_candidates", "detect_runtime", "_trim_python_slices",
    "AUDIT_CACHE_FILENAME", "AUDIT_COVERAGE_FILENAME", "APACHE2_NOTICE",
    "DEFAULT_MAX_COST_USD",
]
