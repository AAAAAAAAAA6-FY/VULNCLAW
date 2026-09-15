# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)

# core/baseline.py
"""C3: 增量扫描基线 —— 扫描结果指纹的保存/加载/比较。

存在意义
--------
`core/report_diff.py` 只比对 (url, title) 有无，回答"多了哪几条"；但增量扫描需要
回答更多问题：**攻击面变了吗**（资产/路由/参数）、**老漏洞还在吗**（未复现 = 修复候选）、
**关过的洞又冒出来了吗**（reopen）、**响应形态变了吗**（status/长度/内容 hash）。
本模块给出统一的"扫描结果指纹"口径与确定性 compare 语义，作为增量扫描的判定基座。

设计约束
--------
1. **指纹是纯函数**：``fingerprint_scan`` 只消费入参，不含时钟/随机/网络，
   同输入必得同输出（可跨进程比对）。
2. **IO 最小**：只有 ``save_baseline`` / ``load_baseline`` 碰磁盘，JSON 落盘。
3. **fail-closed / 不编造**：非 dict 输入直接抛错；缺失字段按"空集合"处理而**不猜**；
   基线文件损坏/结构非法 → ``load_baseline`` 返回 None；compare 拿不到基线时
   **把 current 全量视为新增**（宁多报不漏报），并在 ``degraded`` 标记。
4. **只读复用**：finding 身份/状态一律复用 ``core.finding_schema``
   （``compute_finding_id`` / ``resolve_status``），本模块不改动 finding_schema。
5. **确定性输出**：所有集合排序后落盘（``sort_keys=True``），diff 顺序稳定。

指纹字段（schema_version=1）
---------------------------
  assets    资产：host 集合（来自 target / subdomains / alive_assets / 各 URL）
  routes    路由：path 集合（去 query 的 URL 路径）
  params    参数：path -> 参数名集合（finding.parameter + URL query）
  responses 响应摘要：规范化 URL -> {status, length, hash}（hash = sha256 前 8 位）
  engines   引擎结果：漏洞 type -> 条数
  findings  发现状态：finding_id -> {status, severity, type, url}

限制（详见 docs/INCREMENTAL_SCAN.md）
------------------------------------
- routes 只存 path（跨主机的同 path 会被视为同一路由）；responses 的 status/length/hash
  只在 finding 里确实带这些字段时才有值——**没有就留空，不编造**。
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
from urllib.parse import parse_qsl, urlsplit

from vulnclaw.core.finding_schema import (
    GOVERNANCE_STATUSES,
    STATUS_ACCEPTED,
    STATUS_CLOSED,
    STATUS_FALSE_POSITIVE,
    STATUS_FIXED,
    STATUS_REOPENED,
    compute_finding_id,
    resolve_status,
)

__all__ = [
    "FINGERPRINT_SCHEMA_VERSION",
    "BASELINE_MAGIC",
    "DEFAULT_BASELINE_DIR",
    "fingerprint_scan",
    "save_baseline",
    "load_baseline",
    "compare_with_baseline",
    "default_baseline_path",
    "diff_has_changes",
    "diff_summary_text",
]

#: 指纹结构版本（结构变更时递增；load 侧不认的版本一律当"无基线"）
FINGERPRINT_SCHEMA_VERSION = 1
#: 基线文件魔数（用于区分"基线文件"与"扫描报告"）
BASELINE_MAGIC = "vulnclaw.baseline"
#: 默认基线目录（调用方可传显式路径覆盖）
DEFAULT_BASELINE_DIR = os.path.join("_runtime_cache", "baselines")

#: 指纹必需键（load 侧结构校验用）
_REQUIRED_KEYS: Tuple[str, ...] = (
    "assets", "routes", "params", "responses", "engines", "findings",
)

#: 基线状态为"已处置"时，本次未出现 → removed（不再作为修复候选上报）
#: 基线状态为"活跃"时，本次未复现 → fixed（修复候选）
_REOPENABLE_STATUSES = frozenset({
    STATUS_FIXED, STATUS_ACCEPTED, STATUS_FALSE_POSITIVE, STATUS_CLOSED,
})

_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")
_WS_RE = re.compile(r"\s+")
_PARAM_SPLIT_RE = re.compile(r"[&,;]+")
#: 从 URL query 中提取参数名时忽略的噪声参数（无攻击语义）
_NOISE_PARAMS = frozenset({"", "utm_source", "utm_medium", "utm_campaign", "fbclid", "gclid"})

#: 响应摘要字段的候选键（按优先级）
_STATUS_KEYS = ("response_status", "status_code", "http_status", "resp_status", "status")
_LENGTH_KEYS = ("content_length", "response_length", "body_length", "response_size", "length")
_BODY_KEYS = ("response_body", "body", "response_text", "response_preview", "evidence", "response")


# ============================================================
# 基础工具（纯函数，无 IO）
# ============================================================
def _as_dict(obj: Any) -> Dict[str, Any]:
    """非 dict 一律当空 dict（不编造）。"""
    return obj if isinstance(obj, dict) else {}


def _text(value: Any) -> str:
    """通用文本归一：折叠空白 + 去首尾。"""
    return _WS_RE.sub(" ", str(value if value is not None else "")).strip()


def _iter_dicts(value: Any) -> List[Dict[str, Any]]:
    """把"可能是 list[dict] / dict / None / 标量"的字段收敛为 list[dict]。"""
    if isinstance(value, dict):
        return [value]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [v for v in value if isinstance(v, dict)]
    return []


def _item_url(item: Any) -> str:
    """从端点条目（dict 或裸字符串）取 URL。"""
    if isinstance(item, dict):
        return _text(item.get("url") or item.get("endpoint") or item.get("target") or item.get("path"))
    return _text(item)


def _collect_urls(value: Any) -> List[str]:
    """收集端点字段里的 URL（兼容 list[dict] / list[str] / 单值）。"""
    items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
    return [url for url in (_item_url(item) for item in items) if url]


def _sha8(text: str) -> str:
    """内容 hash 前 8 位（sha256；空文本返回空串，不编造）。"""
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:8]


def _int_or_none(value: Any) -> Optional[int]:
    """宽松整数解析：不可解析 → None（不编造 0）。"""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        text = _text(value)
        return int(float(text)) if text else None
    except (TypeError, ValueError):
        return None


def _host_of(url: Any) -> str:
    """URL/host 字符串取 host（netloc 小写，保留端口）。"""
    raw = _text(url)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    if parts.netloc:
        return parts.netloc.lower()
    # 无 scheme（如 sub.example.com / example.com:8080）
    if "/" not in raw and " " not in raw:
        return raw.lower()
    return ""


def _path_of(url: Any) -> str:
    """URL 取路径（去 query/fragment、去尾斜杠；空路径 → '/'）。"""
    raw = _text(url)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return ""
    path = parts.path or ("/" if (parts.netloc or parts.scheme) else "")
    if not path:
        return ""
    return path.rstrip("/") or "/"


def _norm_url(url: Any) -> str:
    """URL 身份归一：scheme://netloc/path（去 query/fragment/尾斜杠）。"""
    raw = _text(url)
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.scheme:
        return raw
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}{(parts.path or '').rstrip('/')}"


def _params_from_url(url: Any) -> List[str]:
    """从 URL query 提取参数名（排序，忽略噪声参数）。"""
    raw = _text(url)
    if "?" not in raw:
        return []
    try:
        query = urlsplit(raw).query
    except ValueError:
        return []
    names = {name.strip().lower() for name, _v in parse_qsl(query, keep_blank_values=True)}
    return sorted(n for n in names if n not in _NOISE_PARAMS)


def _params_of(finding: Dict[str, Any]) -> List[str]:
    """finding 的参数名集合：显式 parameter 字段 + URL query（排序去重）。"""
    names = set(_params_from_url(finding.get("url")))
    raw = finding.get("parameter")
    if isinstance(raw, dict):
        tokens = [str(k) for k in raw]
    elif isinstance(raw, (list, tuple, set, frozenset)):
        tokens = [str(v) for v in raw]
    else:
        text = _text(raw)
        tokens = _PARAM_SPLIT_RE.split(text) if text else []
    for tok in tokens:
        name = _text(tok).lower()
        if name and name not in _NOISE_PARAMS:
            names.add(name)
    return sorted(names)


def _response_summary(finding: Dict[str, Any]) -> Dict[str, Any]:
    """响应摘要 (status, length, hash)；三字段全缺 → 空 dict（不编造）。"""
    status = None
    for key in _STATUS_KEYS:
        status = _int_or_none(finding.get(key))
        if status is not None:
            break
    length = None
    for key in _LENGTH_KEYS:
        length = _int_or_none(finding.get(key))
        if length is not None:
            break
    body = ""
    for key in _BODY_KEYS:
        body = _text(finding.get(key))
        if body:
            break
    digest = _sha8(body)
    if status is None and length is None and not digest:
        return {}
    out: Dict[str, Any] = {}
    if status is not None:
        out["status"] = status
    if length is not None:
        out["length"] = length
    if digest:
        out["hash"] = digest
    return out


def _finding_status(finding: Dict[str, Any]) -> str:
    """finding 状态：优先显式 status（合法值），否则由 finding_schema 推导（只读）。"""
    explicit = _text(finding.get("status")).lower()
    if explicit in GOVERNANCE_STATUSES:
        return explicit
    try:
        return _text(resolve_status(finding)).lower()
    except Exception:  # noqa: BLE001  外部字段千奇百怪，推导失败一律 fail-closed
        return ""


def _finding_id(finding: Dict[str, Any]) -> str:
    """finding 身份：优先既有 finding_id，否则用 finding_schema 确定性哈希。"""
    existing = _text(finding.get("finding_id"))
    if existing:
        return existing
    try:
        return _text(compute_finding_id(finding))
    except Exception:  # noqa: BLE001
        return ""


# ============================================================
# 指纹（纯函数）
# ============================================================
def fingerprint_scan(scan_result: Any) -> Dict[str, Any]:
    """把一次扫描结果（报告 dict）归一为确定性指纹。

    fail-closed：``scan_result`` 非 dict → ``ValueError``（不猜测输入形态）。
    缺失字段按空集合处理——**不编造**任何资产/路由/状态。
    """
    if not isinstance(scan_result, dict):
        raise ValueError("scan_result 必须是 dict（fail-closed：不猜测输入形态）")

    target = _text(scan_result.get("target"))
    findings = _iter_dicts(scan_result.get("vulnerabilities"))
    if not findings:
        findings = _iter_dicts(scan_result.get("findings"))
    assets: set = set()
    routes: set = set()

    host = _host_of(target)
    if host:
        assets.add(host)
    for sub in scan_result.get("subdomains") or []:
        sub_host = _host_of(sub)
        if sub_host:
            assets.add(sub_host)

    urls: List[str] = [target] if target else []
    urls += [url for url in (_item_url(f) for f in findings) if url]
    urls += _collect_urls(scan_result.get("nuclei_results"))
    urls += _collect_urls(scan_result.get("js_endpoints"))
    urls += _collect_urls(scan_result.get("alive_assets"))
    urls += _collect_urls(scan_result.get("found_dirs"))

    for raw_url in urls:
        u_host = _host_of(raw_url)
        if u_host:
            assets.add(u_host)
        u_path = _path_of(raw_url)
        if u_path:
            routes.add(u_path)

    params: Dict[str, List[str]] = {}
    responses: Dict[str, Dict[str, Any]] = {}
    engines: Dict[str, int] = {}
    findings_map: Dict[str, Dict[str, Any]] = {}

    for finding in findings:
        vtype = _text(finding.get("type") or finding.get("vuln_type")).lower()
        if vtype:
            engines[vtype] = engines.get(vtype, 0) + 1

        fid = _finding_id(finding)
        if fid:
            findings_map[fid] = {
                "status": _finding_status(finding),
                "severity": _text(finding.get("severity")).lower(),
                "type": vtype,
                "url": _text(finding.get("url")),
            }

        path = _path_of(finding.get("url"))
        if path:
            names = set(params.get(path) or [])
            names.update(_params_of(finding))
            params[path] = sorted(names)

        norm = _norm_url(finding.get("url"))
        summary = _response_summary(finding)
        if norm and summary:
            responses[norm] = summary

    return {
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
        "target": target,
        "assets": sorted(assets),
        "routes": sorted(routes),
        "params": {k: params[k] for k in sorted(params)},
        "responses": {k: responses[k] for k in sorted(responses)},
        "engines": {k: engines[k] for k in sorted(engines)},
        "findings": {k: findings_map[k] for k in sorted(findings_map)},
    }


def _is_fingerprint(obj: Any) -> bool:
    """结构校验：是否为本模块产出的指纹（版本匹配 + 必需键齐全）。"""
    if not isinstance(obj, dict):
        return False
    try:
        if int(obj.get("schema_version") or 0) != FINGERPRINT_SCHEMA_VERSION:
            return False
    except (TypeError, ValueError):
        return False
    return all(isinstance(obj.get(key), (dict, list)) for key in _REQUIRED_KEYS)


def _coerce_fingerprint(obj: Any) -> Optional[Dict[str, Any]]:
    """把"基线文件 / 裸指纹 / 扫描报告 / 垃圾"统一收敛为指纹；不可解析 → None。"""
    if obj is None or not isinstance(obj, dict):
        return None
    inner = obj.get("fingerprint")
    if isinstance(inner, dict) and _is_fingerprint(inner):
        return inner
    if _is_fingerprint(obj):
        return obj
    try:
        return fingerprint_scan(obj)
    except (ValueError, TypeError):
        return None


# ============================================================
# IO（唯一碰磁盘的地方）
# ============================================================
def default_baseline_path(target: Any) -> str:
    """默认基线路径：``_runtime_cache/baselines/<safe_target>.json``（确定性文件名）。"""
    safe = _SAFE_RE.sub("_", _text(target)).strip("_")[:80] or "unknown"
    digest = hashlib.sha1(_text(target).encode("utf-8", "replace")).hexdigest()[:8]
    return os.path.join(DEFAULT_BASELINE_DIR, f"{safe}-{digest}.json")


def save_baseline(scan_result: Any, path: str = "", *, created_at: Optional[float] = None) -> str:
    """指纹落盘，返回实际写入路径；``path`` 为空则用 ``default_baseline_path``。"""
    fingerprint = fingerprint_scan(scan_result)
    out_path = _text(path) or default_baseline_path(fingerprint.get("target"))
    parent = os.path.dirname(os.path.abspath(out_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    payload = {
        "magic": BASELINE_MAGIC,
        "schema_version": FINGERPRINT_SCHEMA_VERSION,
        "created_at": float(created_at if created_at is not None else time.time()),
        "target": fingerprint.get("target") or "",
        "fingerprint": fingerprint,
    }
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=True, default=str)
    return out_path


def load_baseline(path: Any) -> Optional[Dict[str, Any]]:
    """加载基线指纹；文件缺失 / JSON 坏 / 结构非法 → None（不编造基线）。"""
    p = _text(path)
    if not p or not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError, UnicodeDecodeError):
        return None
    return _coerce_fingerprint(data)


# ============================================================
# compare（纯函数）
# ============================================================
def _empty_diff() -> Dict[str, Any]:
    return {
        "target": "",
        "added": [],
        "removed": [],
        "changed": [],
        "unchanged": [],
        "fixed": [],
        "reopened": [],
        "surface": {
            "assets": {"added": [], "removed": [], "unchanged": []},
            "routes": {"added": [], "removed": [], "unchanged": []},
            "params": {"added": [], "removed": [], "changed": [], "unchanged": []},
            "responses": {"added": [], "removed": [], "changed": [], "unchanged": []},
            "engines": {"added": [], "removed": [], "changed": [], "unchanged": []},
        },
        "degraded": False,
        "reason": "",
        "summary": {},
    }


def _finding_item(fid: str, entry: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "finding_id": fid,
        "type": _text(entry.get("type")),
        "url": _text(entry.get("url")),
        "status": _text(entry.get("status")),
        "severity": _text(entry.get("severity")),
    }


def _diff_findings(
    cur: Dict[str, Dict[str, Any]], base: Dict[str, Dict[str, Any]], out: Dict[str, Any]
) -> None:
    """发现级 compare：added / removed / changed / unchanged / fixed / reopened。"""
    for fid in sorted(cur):
        now = cur[fid]
        before = base.get(fid)
        if before is None:
            if _text(now.get("status")) == STATUS_REOPENED:
                out["reopened"].append(_finding_item(fid, now))
            else:
                out["added"].append(_finding_item(fid, now))
            continue
        prev_status = _text(before.get("status"))
        now_status = _text(now.get("status"))
        if prev_status in _REOPENABLE_STATUSES and now_status not in GOVERNANCE_STATUSES:
            out["reopened"].append(_finding_item(fid, now))
            continue
        if prev_status == now_status and _text(before.get("severity")) == _text(now.get("severity")):
            out["unchanged"].append(_finding_item(fid, now))
            continue
        item = _finding_item(fid, now)
        item["status_from"] = prev_status
        item["status_to"] = now_status
        item["severity_from"] = _text(before.get("severity"))
        item["severity_to"] = _text(now.get("severity"))
        out["changed"].append(item)

    for fid in sorted(base):
        if fid in cur:
            continue
        before = base[fid]
        item = _finding_item(fid, before)
        if _text(before.get("status")) in GOVERNANCE_STATUSES:
            out["removed"].append(item)
        else:
            out["fixed"].append(item)


def _diff_str_set(
    cur: Sequence[str], base: Sequence[str], bucket: Dict[str, List]
) -> None:
    cur_set, base_set = set(cur or []), set(base or [])
    bucket["added"] = sorted(cur_set - base_set)
    bucket["removed"] = sorted(base_set - cur_set)
    bucket["unchanged"] = sorted(cur_set & base_set)


def _diff_params(cur: Dict[str, List], base: Dict[str, List], bucket: Dict[str, List]) -> None:
    for path in sorted(set(cur) - set(base)):
        bucket["added"].append({"route": path, "params": list(cur.get(path) or [])})
    for path in sorted(set(base) - set(cur)):
        bucket["removed"].append({"route": path, "params": list(base.get(path) or [])})
    for path in sorted(set(cur) & set(base)):
        now, before = list(cur.get(path) or []), list(base.get(path) or [])
        if now == before:
            bucket["unchanged"].append({"route": path, "params": now})
        else:
            bucket["changed"].append({
                "route": path,
                "from": before,
                "to": now,
                "added_params": sorted(set(now) - set(before)),
                "removed_params": sorted(set(before) - set(now)),
            })


def _diff_responses(cur: Dict[str, Dict], base: Dict[str, Dict], bucket: Dict[str, List]) -> None:
    for url in sorted(set(cur) - set(base)):
        bucket["added"].append({"url": url, **dict(cur.get(url) or {})})
    for url in sorted(set(base) - set(cur)):
        bucket["removed"].append({"url": url, **dict(base.get(url) or {})})
    for url in sorted(set(cur) & set(base)):
        now, before = dict(cur.get(url) or {}), dict(base.get(url) or {})
        if now == before:
            bucket["unchanged"].append({"url": url, **now})
        else:
            bucket["changed"].append({"url": url, "from": before, "to": now})


def _diff_engines(cur: Dict[str, int], base: Dict[str, int], bucket: Dict[str, List]) -> None:
    for name in sorted(set(cur) - set(base)):
        bucket["added"].append({"type": name, "count": cur.get(name)})
    for name in sorted(set(base) - set(cur)):
        bucket["removed"].append({"type": name, "count": base.get(name)})
    for name in sorted(set(cur) & set(base)):
        now, before = cur.get(name), base.get(name)
        if now == before:
            bucket["unchanged"].append({"type": name, "count": now})
        else:
            bucket["changed"].append({"type": name, "from": before, "to": now})


def _summarize(out: Dict[str, Any]) -> Dict[str, Any]:
    """汇总计数（供 CLI 退出码与摘要使用）。"""
    surface = out.get("surface") or {}
    surface_changed = 0
    for name in ("assets", "routes", "params", "responses", "engines"):
        bucket = surface.get(name) or {}
        surface_changed += len(bucket.get("added") or [])
        surface_changed += len(bucket.get("removed") or [])
        surface_changed += len(bucket.get("changed") or [])
    counts = {key: len(out.get(key) or []) for key in
              ("added", "removed", "changed", "unchanged", "fixed", "reopened")}
    changes = counts["added"] + counts["removed"] + counts["changed"] + counts["fixed"] + counts["reopened"]
    summary = {
        "findings": counts,
        "surface_changed": surface_changed,
        "total_changes": changes + surface_changed,
        "has_changes": bool(changes or surface_changed),
        "degraded": bool(out.get("degraded")),
    }
    out["summary"] = summary
    return out


def compare_with_baseline(current: Any, baseline: Any) -> Dict[str, Any]:
    """当前扫描 vs 基线。

    current / baseline 可以是本模块的指纹、``save_baseline`` 的基线文件内容，
    或直接是一次扫描报告（自动取指纹）。

    fail-closed：
      - ``current`` 不可解析 → 空 diff + ``degraded``（无法判定，不产出假结论）；
      - ``baseline`` 不可解析 → **current 全量视为 added** + ``degraded``
        （保守：宁可多报新增，绝不静默吞掉真实发现）。

    fix 判定口径（两条都在同一 finding_id 上比较）：
      - 基线活跃、本次消失 → ``fixed``（修复候选）
      - 基线已处置、本次消失 → ``removed``（治理侧已关闭，不再追踪）
      - 基线已处置、本次又出现且状态活跃 → ``reopened``
    """
    out = _empty_diff()
    cur_fp = _coerce_fingerprint(current)

    if cur_fp is None:
        out["degraded"] = True
        out["reason"] = "current 不可解析（非 dict / 结构非法）→ 不产出任何判定"
        return _summarize(out)

    out["target"] = _text(cur_fp.get("target"))
    base_fp = _coerce_fingerprint(baseline)

    if base_fp is None:
        for fid in sorted(cur_fp.get("findings") or {}):
            out["added"].append(_finding_item(fid, (cur_fp.get("findings") or {})[fid]))
        surface = out["surface"]
        surface["assets"]["added"] = sorted(cur_fp.get("assets") or [])
        surface["routes"]["added"] = sorted(cur_fp.get("routes") or [])
        for path, names in sorted((cur_fp.get("params") or {}).items()):
            surface["params"]["added"].append({"route": path, "params": list(names or [])})
        for url, resp in sorted((cur_fp.get("responses") or {}).items()):
            surface["responses"]["added"].append({"url": url, **dict(resp or {})})
        for name, count in sorted((cur_fp.get("engines") or {}).items()):
            surface["engines"]["added"].append({"type": name, "count": count})
        out["degraded"] = True
        out["reason"] = "基线不可用（缺失/损坏/结构非法）→ current 全量视为新增（宁多报不漏报）"
        return _summarize(out)

    _diff_findings(
        cur_fp.get("findings") or {}, base_fp.get("findings") or {}, out
    )
    surface = out["surface"]
    _diff_str_set(cur_fp.get("assets") or [], base_fp.get("assets") or [], surface["assets"])
    _diff_str_set(cur_fp.get("routes") or [], base_fp.get("routes") or [], surface["routes"])
    _diff_params(cur_fp.get("params") or {}, base_fp.get("params") or {}, surface["params"])
    _diff_responses(cur_fp.get("responses") or {}, base_fp.get("responses") or {}, surface["responses"])
    _diff_engines(cur_fp.get("engines") or {}, base_fp.get("engines") or {}, surface["engines"])
    return _summarize(out)


def diff_has_changes(diff: Any) -> bool:
    """是否有变化（CLI 退出码用；degraded 一律视为"有变化"）。"""
    if not isinstance(diff, dict):
        return True
    if diff.get("degraded"):
        # 无法判定 → 必须按"有变化"处理，不可静默判成"无变化"（退出码会骗人）
        return True
    summary = diff.get("summary")
    if isinstance(summary, dict) and "has_changes" in summary:
        return bool(summary.get("has_changes"))
    return bool(_summarize(diff).get("summary", {}).get("has_changes"))


def diff_summary_text(diff: Dict[str, Any]) -> str:
    """人读摘要（CLI 输出；不依赖任何 IO）。"""
    if not isinstance(diff, dict):
        return "基线比对失败：结果不可解析"
    lines: List[str] = []
    target = _text(diff.get("target")) or "(未知目标)"
    lines.append(f"[baseline-diff] 目标 {target}")
    if diff.get("degraded"):
        lines.append(f"  ! 降级比对: {_text(diff.get('reason'))}")
    counts = (diff.get("summary") or {}).get("findings") or {}
    lines.append(
        "  发现: 新增 {added} / 消失(修复候选) {fixed} / 已处置关闭 {removed} / "
        "重开 {reopened} / 变化 {changed} / 未变 {unchanged}".format(
            added=counts.get("added", 0), fixed=counts.get("fixed", 0),
            removed=counts.get("removed", 0), reopened=counts.get("reopened", 0),
            changed=counts.get("changed", 0), unchanged=counts.get("unchanged", 0),
        )
    )
    surface = diff.get("surface") or {}
    for name, label in (
        ("assets", "资产"), ("routes", "路由"), ("params", "参数"),
        ("responses", "响应"), ("engines", "引擎类型"),
    ):
        bucket = surface.get(name) or {}
        added = len(bucket.get("added") or [])
        removed = len(bucket.get("removed") or [])
        changed = len(bucket.get("changed") or [])
        if added or removed or changed:
            lines.append(f"  攻击面·{label}: +{added} / -{removed} / ~{changed}")

    def _render_finding(item: Dict[str, Any]) -> str:
        return f"{_text(item.get('status')) or '-'} {_text(item.get('type')) or '-'} {_text(item.get('url')) or '-'}"

    for key, label in (("added", "新增"), ("fixed", "修复候选"), ("reopened", "重开")):
        items = diff.get(key) or []
        for item in items[:10]:
            if isinstance(item, dict):
                lines.append(f"  {label}: {_render_finding(item)}")
        if len(items) > 10:
            lines.append(f"  {label}: ...其余 {len(items) - 10} 条见 --json 输出")
    if not diff_has_changes(diff) and not diff.get("degraded"):
        lines.append("  结论: 与基线一致，无变化")
    return "\n".join(lines)
