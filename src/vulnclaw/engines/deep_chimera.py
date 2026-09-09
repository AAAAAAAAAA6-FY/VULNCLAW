# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/deep_chimera.py
"""
深藏复合漏洞引擎（DeepChimeraEngine）主引擎
================================================

引擎定位
--------
针对"藏得极深、极其复杂、常规 payload 测不到"的注入点做地毯式检测。这类漏洞
特征：目标解析器会把输入逐层解码（URL 编码 -> HTML 实体 -> JSON 转义 -> Unicode/
UTF-8 变体），只有把所有层剥干净之后，写入的语义破坏载荷才会被某层解析器真正
接受并"还原成可执行形态"。

与现有引擎的差异化
------------------
- XSS/SQLi/SSTI 等单工引擎只对"单一语义平面"打一枪，遇到多层编码/多解析器堆叠
  的深藏点就脱靶。
- 本引擎以"多层编码剥离注入""Polyglot 语义破坏""多弱信号聚合确认"三大维度切入，
  先探测"响应是否把编码载荷还原成可执行形态"这个深藏注入点普适信号，再做严格筛选。

慎重原则（宁缺毋滥）
--------------------
深藏引擎天生误报率高于单工引擎（编码回显 / httpbin 回显 / 转义在引号内的无害
形态都可能被误当成注入）。故所有候选 finding 必须经过内置严格筛选器（sieve）：
  (a) 技术证据可复现：强语义回显 OR 两次独立 A/B 复核均 >0.25；
  (b) 非纯反射：剥掉 payload 后仍有本质差异（杜绝 httpbin 类原样回显）；
  (c) 负基线：不含 payload 的对照请求不出现该信号；
  (d) false 一票否决：仅 `%27` 反射 / 无任何执行语义 / 被转义不可逃逸 -> 丢弃。
多条候选筛完只剩 0 条，就是"这里没有深藏点"——宁缺毋滥，绝不硬凑。

网络自我保护
------------
- 所有请求 try/except 包裹，异常只记 debug，绝不 re-raise（引擎不能崩任务链）。
- 每个 URL 请求控制在 1 次正常（基类缓存）+ 攻击变体。
- 每轮 asyncio.sleep(0.05) 轻微限速，不依赖任何防封机制。
"""

import asyncio
import html
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, quote

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import async_get, build_attack_url
from vulnclaw.engines.base import BaseEngine


# 每个载荷族的强语义回显标记（只取"只有剥掉 HTML 实体层才会以字面形式出现"的
# 结构令牌，纯反射/编码回显中它们永远以 &lt; &quot; 等转义形态存在，不会误命中）。
MARKERS_BY_FAMILY: Dict[str, List[str]] = {
    "html_event": ["<img", "<svg"],
    "script_break": ["</script>", "<script"],
    "tag_break": ["<t>", "</t>", "<iframe"],
    "json_sql_polyglot": ["' OR '1'='1", "}' OR", "\\' OR"],
    "tag_polyglot": ["</t>", "<!--&{x", "'''--->"],
    "svg_onload": ["<svg"],
    "iframe_event": ["<iframe", "</script>"],
    "html_comment": ["</script>", "<script", "--><script"],
}

# 深藏检测载荷族：只保留"语义冲击强、跨解析器"的禁欲主义精选族（宁精勿滥）。
_DEEP_RAW_PAYLOADS: List[Tuple[str, str]] = [
    ("html_event", '<img src=x onerror="alert(1)">'),
    ("script_break", '</script><script>alert(1)</script>'),
    ("tag_break", '</t><t><img src=x onerror=alert(1)><t>'),
    ("json_sql_polyglot", '{"k":"v"}\' OR \'1\'=\'1'),
    ("tag_polyglot", "\"\'</t><t><!--&{x"),
    ("svg_onload", '<svg/onload=alert(1)>'),
    ("iframe_event", '<iframe srcdoc="<script>alert(1)</script>">'),
    ("html_comment", "--><script>alert(1)</script><!--"),
]


class DeepChimeraEngine(BaseEngine):
    """深藏复合漏洞引擎——多层编码剥离注入 / Polyglot 语义破坏 / 多弱信号聚合确认。"""

    name: str = "deep_chimera"
    description: str = "深藏复合漏洞引擎：多层编码剥离/复合语义破坏注入深度探测"
    max_payloads: int = 12

    # 严格筛选器：单个变体 diff 独立复核达到此差异才可作为"弱信号"参与聚合
    AGG_DIFF_THRESHOLD: float = 0.5
    AB_VERIFY_THRESHOLD: float = 0.25

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs,
    ) -> Optional[Dict]:
        """参数级深藏检测入口。

        对 8 个精选载荷族逐一注入"多层编码变体"，统计强语义回显与剥壳后 diff 弱信号，
        判定深藏注入点；若候选通过严格筛选器则返回 finding，否则返回 None。
        """
        variants = self._build_variants()

        # 真实正常基线：用基类缓存接口取实际端点响应，避免外部传入的占位 normal_resp
        # 与真实响应完全不同导致误报。逐变体 diff 均以它为准。
        normal = await self._get_normal_response(url, session)
        normal_text = normal[1] if isinstance(normal, tuple) else ""
        normal_status = normal[0] if isinstance(normal, tuple) else 0

        strong_families: List[str] = []
        diff_families: List[str] = []
        residual_diff_seen = False
        normal_has_marker = False
        evidence_parts: List[str] = []
        max_len_delta_ratio = 0.0  # 剥壳后与正常响应的长度相对差（滤纯反射编码残差）
        nlen = max(1, len(normal_text))

        for family, raw, variant in variants:
            attack_url = build_attack_url(url, param, variant, parsed_query)
            try:
                resp = await async_get(attack_url, session=session, timeout=10, no_retry=True)
            except Exception as exc:  # noqa: BLE001 - 网络异常绝不能崩任务链
                logger.debug(f"[{self.name}] 请求失败: {family}: {exc}")
                continue
            await asyncio.sleep(0.05)  # 轻微限速

            if not isinstance(resp, tuple) or len(resp) < 2:
                continue
            atk_status, atk_text = resp[0], resp[1] or ""

            marker = self._find_semantic_echo(atk_text, family)
            # 负基线：正常响应若已含该标记，说明是页面固有内容，信号失效
            if marker and marker in normal_text:
                normal_has_marker = True

            # 剥壳后 A/B：先去掉被回显的编码变体与原始载荷，再与真实基线 diff，
            # 杜绝 httpbin 类"回显的文本不同 → 天然不同"的假阳性。
            stripped = self.strip_payload_reflection(atk_text, variant, raw)
            _, ratio = self.has_response_diff(
                (normal_status, normal_text, {}),
                (atk_status, stripped, {}),
                threshold=self.AB_VERIFY_THRESHOLD,
            )
            _delta = abs(len(stripped) - len(normal_text)) / nlen
            if _delta > max_len_delta_ratio:
                max_len_delta_ratio = _delta

            if marker:
                if family not in strong_families:
                    strong_families.append(family)
                    evidence_parts.append(f"强语义回显重构: {marker}")
                residual_diff_seen = True
            elif ratio >= self.AGG_DIFF_THRESHOLD:
                residual_diff_seen = True
                # 连续两次独立 A/B 复核（每次都是独立请求）才认可该弱信号
                try:
                    resp2 = await async_get(
                        attack_url, session=session, timeout=10, no_retry=True
                    )
                    await asyncio.sleep(0.05)
                    if not isinstance(resp2, tuple) or len(resp2) < 2:
                        continue
                    atk2_status, atk2_text = resp2[0], resp2[1] or ""
                    stripped2 = self.strip_payload_reflection(atk2_text, variant, raw)
                    ok2, ratio2 = self.has_response_diff(
                        (normal_status, normal_text, {}),
                        (atk2_status, stripped2, {}),
                        threshold=self.AB_VERIFY_THRESHOLD,
                    )
                    if ok2 and ratio2 >= self.AGG_DIFF_THRESHOLD:
                        if family not in diff_families:
                            diff_families.append(family)
                except Exception as exc:  # noqa: BLE001 - 复核异常不影响其他族
                    logger.debug(f"[{self.name}] 二次复核失败: {family}: {exc}")
            # else: 无强回显且弱信号不达标 —— 该族无信号，跳过

        if not strong_families and len(diff_families) < 2:
            # 无强信号、无足量聚合弱信号：这里没有深藏点，宁缺毋滥
            return None

        candidate = self._assemble_finding(
            url=url,
            param=param,
            parsed_query=parsed_query,
            strong_families=strong_families,
            diff_families=diff_families,
            residual_diff_seen=residual_diff_seen,
            normal_has_marker=normal_has_marker,
            max_len_delta_ratio=max_len_delta_ratio,
            evidence_parts=evidence_parts,
        )

        violations = self._sieve_violations(candidate, candidate.get("evidence", ""))
        if violations:
            logger.debug(
                f"[{self.name}] 筛除候选 finding: {url} param={param} 违规={violations}"
            )
            return None
        return candidate

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        """端点级地毯式：遍历待测 URL 的全部 query 参数逐个做 check() 深藏检测。"""
        findings: List[Dict] = []
        try:
            parsed = urlparse(target)
            params_qs = parse_qs(parsed.query)
        except Exception:  # noqa: BLE001
            params_qs = {}
        if not params_qs:
            return findings
        for param in params_qs:
            try:
                normal = await self._get_normal_response(target, session)
                f = await self.check(
                    target, param, normal, parsed.query, session
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug(f"[{self.name}] scan 参数 {param} 异常: {exc}")
                continue
            if f:
                findings.append(f)
            await asyncio.sleep(0.05)
        logger.info(f"DeepChimeraEngine: {len(findings)} findings")
        return findings

    # ------------------------------------------------------------------
    # 内部实现
    # ------------------------------------------------------------------
    def _build_variants(self) -> List[Tuple[str, str, str]]:
        """生成 (family, raw, deep_encoded_variant) 三元组。

        多层编码堆叠顺序：JSON 字符串转义 -> HTML 实体 -> URL 编码（最后层由 URL 承载，
        服务端只做一次 querystring 解码后仍见不到原载荷语义字符，须再剥 HTML/JSON 层）。
        """
        variants: List[Tuple[str, str, str]] = []
        for family, raw in _DEEP_RAW_PAYLOADS[: self.max_payloads]:
            variants.append((family, raw, self._encode_variant_deep(raw)))
        return variants

    def _encode_variant_deep(self, raw: str) -> str:
        v = raw
        # 第 1 层：JSON 字符串转义（引号/反斜杠）
        v = v.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")
        # 第 2 层：HTML 实体编码（使纯反射永远呈现 &lt; &quot; 转义形态）
        v = (
            v.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        # 第 3 层：URL 编码（由 URL 承载）
        try:
            v = quote(v, safe="")
        except Exception:  # noqa: BLE001
            pass
        return v

    def _find_semantic_echo(self, text: str, family: str) -> Optional[str]:
        """在攻击响应里搜索"被还原成可执行形态"的原始语义标记。

        只有目标解析器真把多层编码剥干净、把载荷还原成原汁原味的语义结构时，
        这些字面标记才会出现；否则永远停在被转义形态而命中不了。
        """
        if not text:
            return None
        for marker in MARKERS_BY_FAMILY.get(family, []):
            if marker in text:
                return marker
        return None

    def _assemble_finding(
        self,
        url: str,
        param: str,
        parsed_query: str,
        strong_families: List[str],
        diff_families: List[str],
        residual_diff_seen: bool,
        normal_has_marker: bool,
        max_len_delta_ratio: float,
        evidence_parts: List[str],
    ) -> Dict:
        strong_count = len(strong_families)
        total_signal = len(set(strong_families) | set(diff_families))

        if strong_count >= 2:
            severity, confidence, cvss = "high", "high", 7.8
            title = "深藏复合注入点：多层编码剥离被解构为可执行形态（多载荷族确认）"
        elif strong_count == 1:
            severity, confidence, cvss = "medium", "high", 6.3
            title = "深藏注入点：多层编码载荷被解析器还原为可执行语义"
        elif len(diff_families) >= 2:
            severity, confidence, cvss = "medium", "medium", 5.0
            title = "深藏弱信号聚合：多载荷族差异方向一致（需人工复核）"
        else:
            severity, confidence, cvss = "low", "low", 3.1
            title = "深藏注入候选：单载荷族弱差异（低置信，建议复核）"

        src = ", ".join(sorted(set(strong_families))) or "（仅弱信号）"
        ev = (
            f"强语义回显族: {src}; "
            f"弱信号聚合族: {', '.join(sorted(set(diff_families))) or '无'}; "
            f"剥壳后存在本质差异: {'是' if residual_diff_seen else '否'}; "
        )
        if evidence_parts:
            ev += "; ".join(evidence_parts)

        finding: Dict = {
            "type": "deep_chimera_encoded_injection",
            "severity": severity,
            "title": title,
            "description": (
                f"参数 {param} 在 {url} 上表现出深藏注入特征：输入经多层编码（URL 编码/HTML "
                f"实体/JSON 转义）注入后，目标把载荷还原成可执行语义形态（载荷族: {src}）或 "
                f"累积了 ≥2 族方向一致的弱差异信号，提示存在被多层解析器堆叠掩盖的注入点。"
            ),
            "remediation": "对所有输入按最外层渲染上下文统一做白名单校验与上下文相关转义，禁用多层串联解码后直接拼接；对 JSON/HTML/XML/SQL 各解析层分别做严格转义并设置解析器严格模式。",
            "evidence": ev,
            "url": url,
            "parameter": param,
            "method": "GET",
            "confidence": confidence,
            "cvss": float(cvss),
            "reproduction_steps": (
                f"1. 对该参数注入多层编码载荷（URL+HTML+JSON 堆叠）；"
                f"2. 观察响应是否把载荷还原为可执行形态或出现一致差异方向；"
                f"3. 对照不含载荷的正常请求，确认信号不复现。"
            ),
            # 内部私有标记，供筛选器使用，返回前剥除
            "_dc_strong_families": strong_count,
            "_dc_signal_families": total_signal,
            "_dc_residual_diff": residual_diff_seen,
            "_dc_normal_has_marker": normal_has_marker,
            "_dc_len_delta_ratio": float(max_len_delta_ratio),
            "_dc_severity": severity,
        }
        return finding

    def _sieve_violations(self, finding_like: Dict, evidence_text: str) -> List[str]:
        """严格筛选器：返回被违反的规则名列表，为空才放行（false 一票否决）。

        规则：
          - sieve_not_reproducible   : (a) 既无强语义回显、聚合弱信号族又不足 2 -> 证据不可复现
          - sieve_pure_reflection    : (b) 无强回显且剥壳后无本质残余差异 -> 纯反射
          - sieve_negative_baseline  : (c) 同类强语义标记在正常对照请求中已存在 -> 负基线泄漏
          - sieve_harmless_reflection: (d) 证据仅无害反射（`%27`/被转义在引号内不可逃逸）-> false
        """
        violations: List[str] = []
        strong = int(finding_like.get("_dc_strong_families", 0) or 0)
        diff = int(finding_like.get("_dc_signal_families", 0) or 0)
        residual = bool(finding_like.get("_dc_residual_diff", False))

        # (a) 证据可复现
        if strong < 1 and diff < 2:
            violations.append("sieve_not_reproducible")

        # (b) 非纯反射：无强回显且剥壳后无本质差异 -> 一票否决
        if strong < 1 and not residual:
            violations.append("sieve_pure_reflection")
        # 补强：剥壳后残余差异仅是极小长度栅格（minified 页面上 has_response_diff
        # 的 .split() 会把整页当一个 token，1 字符改动也会算出 0.6 差异）——
        # 这类纯编码残差长度 δ 极小，视为纯反射拒绝。
        if strong < 1 and finding_like.get("_dc_len_delta_ratio", 1.0) < 0.03:
            violations.append("sieve_pure_reflection")

        # (c) 负基线：正常对照已含强语义标记
        if finding_like.get("_dc_normal_has_marker"):
            violations.append("sieve_negative_baseline")

        # (d) 无害反射一票否决：仅 %27/harmless 形态，无任何执行语义
        if strong < 1 and not residual:
            if re.search(r"%27|&quot;|\\x27", evidence_text or ""):
                violations.append("sieve_harmless_reflection")

        return violations


__all__ = ["DeepChimeraEngine"]