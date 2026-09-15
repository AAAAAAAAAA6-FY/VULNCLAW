# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""声明式漏洞知识库：数据模型与校验。"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple


# oracle 类型
DETECT_REGEX = "regex"      # 响应文本命中正则
DETECT_REFLECT = "reflect"  # payload 被原样反射进响应
DETECT_TIME = "time"        # 相对基线出现显著延时
DETECT_DIFF = "diff"        # 与基线响应存在显著差异
DETECT_HEADER = "header"    # 检查**响应头**（CORS / 安全头缺失 / 重定向头等）
DETECT_COMPONENT = "component"  # 前端组件版本号 → 与已知脆弱阈值/CVE 对照
DETECT_IDOR = "idor_multisession"  # 多身份/多会话对比（属主 vs 非属主）→ 对象级越权（IDOR）证实
DETECT_FLOW = "flow"  # 多请求流程（写→读）→ 存储型 XSS / 二次注入等"有状态"漏洞
DETECT_DOM = "dom_xss"  # 浏览器执行（渲染页面捕获 dialog）→ DOM 型 XSS
DETECT_BIZ = "biz_logic"  # 业务不变量断言（非法业务值被接受 / 一次性操作可重复）→ 业务逻辑漏洞
DETECT_OOB = "oob"  # 带外回连（OOB）：注入回调地址 → 目标侧主动回连 → 证实盲漏洞（盲 SSRF/RCE/XXE）

_DETECT_TYPES = (DETECT_REGEX, DETECT_REFLECT, DETECT_TIME, DETECT_DIFF, DETECT_HEADER,
                 DETECT_COMPONENT, DETECT_IDOR, DETECT_FLOW, DETECT_DOM, DETECT_BIZ, DETECT_OOB)


def _version_nums(s: str) -> Tuple[int, ...]:
    """版本号 → 整数元组（逐段取前导数字段，非数字段处停止）。"""
    parts = re.split(r"[.\-_]", str(s))
    out: List[int] = []
    for p in parts:
        if str(p).isdigit():
            out.append(int(p))
        else:
            break
    return tuple(out)


def _version_lt(a: str, b: str) -> bool:
    """语义化版本比较：a < b ?"""
    return _version_nums(a) < _version_nums(b)


def _version_ge(a: str, b: str) -> bool:
    """语义化版本比较：a >= b ?"""
    return _version_nums(a) >= _version_nums(b)


def _version_in_range(ver: str, introduced: str, fixed: str, last_affected: str = "") -> bool:
    """OSV 区间语义判定。

    两种上界都要支持，否则会误报：
      - fixed: X          → 开区间 [introduced, X)，X 已修复
      - last_affected: X  → 闭区间 [introduced, X]，X 仍受影响（**含 X**）
    introduced 为空视为 0；两者都空视为无上界（至今未修）。
    """
    if introduced and not _version_ge(ver, introduced):
        return False
    if fixed and not _version_lt(ver, fixed):
        return False
    if last_affected and _version_nums(ver) > _version_nums(last_affected):
        return False
    return bool(introduced or fixed or last_affected)


# ------------------------------------------------------------------
# 正则编译缓存（DetectRule.compiled 用）
_MISS = object()
_RE_CACHE: Dict[str, Any] = {}

# ------------------------------------------------------------------
# 组件漏洞知识库（OSV 影响区间；由 scripts/build_component_kb.py 生成）
# ------------------------------------------------------------------
# 为什么需要：手写阈值宽度受限于人力且会过期；KB 让宽度 = 数据覆盖面。
# 缺失/损坏时一律返回空 → 判据自动降级为内置签名（**绝不会因 KB 出错而误报**）。
_KB_CACHE: Dict[str, Any] = {"path": "", "data": None}


def _load_component_kb(path: str) -> Dict[str, Any]:
    if not path:
        return {}
    try:
        if _KB_CACHE["path"] == path and _KB_CACHE["data"] is not None:
            return _KB_CACHE["data"]
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:  # noqa: BLE001
        return {}
    _KB_CACHE["path"], _KB_CACHE["data"] = path, data
    return data


def _kb_lookup(eco: str, pkg: str) -> List[Dict[str, str]]:
    """查 KB：生态 + 包名 → 影响区间列表。"""
    try:
        from vulnclaw.core.settings import settings  # 延迟导入，避免模型层耦合配置
        path = str(getattr(settings, "component_kb_path", "") or "")
    except Exception:  # noqa: BLE001
        return []
    kb = _load_component_kb(path)
    return ((kb.get("ecosystems") or {}).get(eco) or {}).get(pkg) or []

# 默认适用的注入位置（与 attack_surface.PointLocation 对齐）
ALL_LOCATIONS = ("query", "path", "header", "cookie", "body_form", "body_json")


@dataclass(frozen=True)
class DetectRule:
    """判定规则（oracle）。"""

    type: str
    patterns: Tuple[str, ...] = ()
    negative: bool = False      # True：命中 patterns 表示**安全**（如"无权限"页）
    threshold: float = 0.0      # time: 秒；diff: 差异比
    header_name: str = ""       # header 型：要检查的响应头（空=检查全部头）
    header_absent: bool = False # header 型：True 表示该头**缺失**即命中（如安全头缺失）
    # 上下文约束：非空则要求响应 Content-Type 包含该串才判定。
    # 例：XSS 只在 HTML 响应中有意义——JSON 里回显 <script> 并不会执行，
    #     不加此约束会对"原样回显输入的搜索框/echo 接口"大量误报。
    require_content_type: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
    # component 型：已知脆弱组件签名库（版本号 → 脆弱阈值 → CVE 对照）
    signatures: Tuple[Dict[str, Any], ...] = ()

    def compiled(self) -> List[re.Pattern]:
        """编译后的正则（**带缓存**）。

        为什么必须缓存：接入外部数据源后单条声明可能有上百个 pattern，
        而本方法每次判定都会被调用；逐次重编译会让扫描慢一个数量级。
        """
        out = []
        for p in self.patterns:
            rx = _RE_CACHE.get(p, _MISS)
            if rx is _MISS:
                try:
                    rx = re.compile(p, re.IGNORECASE)
                except re.error:
                    rx = None
                _RE_CACHE[p] = rx
            if rx is not None:
                out.append(rx)
        return out

    def component_hits(self, text: str) -> List[Tuple[str, str, str]]:
        """component 型判定：返回命中列表 [(lib, cve, evidence)]，空=未命中。
        逐签名：正则取版本号 → 与 vulnerable_below 阈值比较，低于阈值即脆弱（已修复则不报）。"""
        out: List[Tuple[str, str, str]] = []
        low = text or ""
        for sig in self.signatures:
            pat = sig.get("pattern")
            if not pat:
                continue
            try:
                rx = re.compile(pat, re.IGNORECASE)
            except re.error:
                continue
            m = rx.search(low)
            if not m:
                continue
            # KB（OSV 影响区间）型：取"包名 + 版本"两个捕获组 → 查表。
            # 与手写阈值的区别：宽度 = KB 覆盖的包数量（当前 Maven 三千余），且可随数据重生成而保鲜。
            kb_eco = str(sig.get("kb") or "")
            if kb_eco:
                pg = int(sig.get("kb_pkg_group") or 0)
                vg = int(sig.get("kb_ver_group") or 0)
                gg = int(sig.get("kb_groupid_group") or 0)
                # 注意：m.groups() 是**元组**（不是数量），别拿它和整数比较
                if len(m.groups()) >= max(pg, vg, gg or 0):
                    pkg, ver = m.group(pg), m.group(vg)
                    gid = m.group(gg) if gg else ""
                    # Maven 在 OSV 里的包名是 **groupId:artifactId**；
                    # 只取 artifactId 会查不到（实测：jackson-databind → 必须带 groupId）。
                    # 因此两个候选名都试：先精确带 groupId，再退化为裸 artifactId。
                    names = [f"{gid}:{pkg}", pkg] if gid else [pkg]
                    for nm in names:
                        hit_adv = None
                        for adv in _kb_lookup(kb_eco, nm):
                            intro = str(adv.get("i") or "")
                            fixed = str(adv.get("f") or "")
                            last_aff = str(adv.get("la") or "")
                            if _version_in_range(ver, intro, fixed, last_aff):
                                hit_adv = (nm, ver, intro, fixed or last_aff,
                                           str(adv.get("id") or ""))
                                break
                        if hit_adv:
                            nm, ver, intro, fixed, aid = hit_adv
                            lib = f"{kb_eco}:{nm}"
                            out.append((
                                lib, aid,
                                f"{lib} {ver} 落在 KB 影响区间 [ {intro or '0'} , {fixed or '未修复'} )"
                                + (f" [{aid}]" if aid else "")))
                            break
                continue
            ver = m.group(1) if m.groups() else ""
            below = str(sig.get("vulnerable_below") or "")
            if below and ver and not _version_lt(ver, below):
                continue  # 版本 >= 阈值视为已修复，不报
            lib = str(sig.get("lib") or "component")
            cve = str(sig.get("cve") or "")
            snippet = low[max(0, m.start() - 20): m.end() + 20].replace("\n", " ")
            ev = f"{lib} {ver} 落在脆弱区间(<{below})"
            if cve:
                ev += f" [{cve}]"
            ev += f": ...{snippet}..."
            out.append((lib, cve, ev))
        return out


@dataclass(frozen=True)
class VulnSpec:
    """一条漏洞声明。"""

    id: str
    name: str
    category: str
    payloads: Tuple[str, ...]
    detect: DetectRule
    locations: Tuple[str, ...] = ALL_LOCATIONS
    param_hints: Tuple[str, ...] = ()   # 为空表示不限参数名
    severity: str = "medium"
    cvss: float = 5.0
    confidence: str = "medium"
    remediation: str = ""
    recommendation: str = ""
    max_payloads: int = 5
    enabled: bool = True
    # 发送请求时附加的请求头（如 CORS 探测需要带 Origin）
    request_headers: Tuple[Tuple[str, str], ...] = ()

    def applies_to(self, location: str, param_name: str) -> bool:
        if location not in self.locations:
            return False
        if not self.param_hints:
            return True
        low = str(param_name or "").lower()
        return any(h.lower() in low for h in self.param_hints)


def from_dict(d: Dict[str, Any]) -> VulnSpec:
    """从字典构造（便于未来接 YAML/JSON 声明文件）。"""
    det = d.get("detect") or {}
    rule = DetectRule(
        type=str(det.get("type") or DETECT_REGEX),
        patterns=tuple(det.get("patterns") or ()),
        negative=bool(det.get("negative", False)),
        threshold=float(det.get("threshold", 0.0) or 0.0),
        header_name=str(det.get("header_name") or ""),
        header_absent=bool(det.get("header_absent", False)),
        require_content_type=str(det.get("require_content_type") or ""),
        extra=dict(det.get("extra") or {}),
        signatures=tuple(det.get("signatures") or ()),
    )
    return VulnSpec(
        id=str(d.get("id") or ""),
        name=str(d.get("name") or d.get("id") or ""),
        category=str(d.get("category") or "generic"),
        payloads=tuple(d.get("payloads") or ()),
        detect=rule,
        locations=tuple(d.get("locations") or ALL_LOCATIONS),
        param_hints=tuple(d.get("param_hints") or ()),
        severity=str(d.get("severity") or "medium"),
        cvss=float(d.get("cvss", 5.0) or 5.0),
        confidence=str(d.get("confidence") or "medium"),
        remediation=str(d.get("remediation") or ""),
        recommendation=str(d.get("recommendation") or ""),
        max_payloads=int(d.get("max_payloads", 5) or 5),
        enabled=bool(d.get("enabled", True)),
        request_headers=tuple((str(k), str(v))
                              for k, v in (d.get("request_headers") or {}).items()),
    )


def validate(spec: VulnSpec) -> List[str]:
    """返回问题列表（空 = 合法）。声明质量保障的基础（后续可配靶场回归）。"""
    errs: List[str] = []
    if not spec.id:
        errs.append("缺少 id")
    if spec.detect.type not in _DETECT_TYPES:
        errs.append(f"未知 detect.type: {spec.detect.type}")
    if spec.detect.type in (DETECT_REGEX,) and not spec.detect.patterns:
        errs.append("regex 型 detect 必须提供 patterns")
    if spec.detect.type == DETECT_HEADER:
        if not spec.detect.patterns and not spec.detect.header_absent:
            errs.append("header 型 detect 需提供 patterns 或 header_absent=True")
    if spec.detect.type == DETECT_COMPONENT and not spec.detect.signatures:
        errs.append("component 型 detect 必须提供 signatures")
    if spec.detect.type == DETECT_IDOR and not (spec.detect.extra or {}).get("owner_marker"):
        errs.append("idor_multisession 型 detect 需在 extra 提供 owner_marker")
    if spec.detect.type == DETECT_FLOW:
        _fl = (spec.detect.extra or {}).get("flow") or {}
        if not (_fl.get("write") or {}).get("path") or not (_fl.get("read") or {}).get("path"):
            errs.append("flow 型 detect 需在 extra.flow 提供 write.path 与 read.path")
    if spec.detect.type == DETECT_DOM and not (spec.detect.extra or {}).get("path"):
        errs.append("dom_xss 型 detect 需在 extra 提供 path（DOM sink 所在端点）")
    if spec.detect.type == DETECT_OOB and not (spec.detect.extra or {}).get("path"):
        errs.append("oob 型 detect 需在 extra 提供 path（盲漏洞所在端点）")
    if spec.detect.type == DETECT_BIZ:
        _lg = (spec.detect.extra or {}).get("logic") or {}
        if not _lg.get("path") or not (_lg.get("mode") or "violation"):
            errs.append("biz_logic 型 detect 需在 extra.logic 提供 path 与 mode")
    if spec.detect.type == DETECT_TIME and spec.detect.threshold <= 0:
        errs.append("time 型 detect 必须提供正的 threshold")
    if not spec.payloads:
        errs.append("缺少 payloads")
    for loc in spec.locations:
        if loc not in ALL_LOCATIONS:
            errs.append(f"未知 location: {loc}")
    return errs
