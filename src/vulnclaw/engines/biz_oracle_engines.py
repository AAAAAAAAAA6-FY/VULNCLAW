# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""B 方案: 双会话差分水平越权 oracle 引擎。

判据（fail-closed）：对候选 IDOR 端点用"身份 B（第二账号/匿名）"与"身份 A（登录态）"
并发差分同一请求。B 未授权拿到私有资源 → 水平越权实锤；B 被拦 → 安全；
A/B 同构且无私有数据 → 公开资源/SPA 壳排除。机器无法裁决一律不产出。

本引擎不进通用参数级调度池（global_engines / engine_priority），
仅在 extras 编排产线（phases_taskgen._run_idor_dual_session_line）按预算调用。
"""
from typing import Dict, List, Optional
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from vulnclaw.core.biz_oracle.diff_oracle import dual_session_probe, oracle_verdict
from vulnclaw.core.biz_oracle.identity_matrix import IdentityMatrix
from vulnclaw.core.logger import logger  # noqa: F401
from vulnclaw.core.settings import settings
from vulnclaw.engines.auth_engines import IDOREngine
from vulnclaw.engines.base import BaseEngine, enrich_finding


class DualSessionOracleEngine(BaseEngine):
    """双会话差分水平越权 oracle v1.0。"""

    name = "idor_dual_session"
    description = "双会话差分水平越权 oracle v1.0"

    def __init__(self, spa_detector=None):
        super().__init__(spa_detector=spa_detector)
        self._idor = IDOREngine()

    # ---------------------------------------------------- 候选判定
    def is_id_candidate(self, param: str, value: str) -> bool:
        if self._idor._is_id_value(value or ""):
            return True
        return any(p == str(param or "").lower() for p in self._idor.ID_PARAMS)

    @staticmethod
    def _replace_param(url: str, param: str, value: str) -> str:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        qs[param] = [value]
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, urlencode(qs, doseq=True), parsed.fragment))

    # ---------------------------------------------------- 差分诊断
    async def check(self, url, param, normal_resp=None, parsed_query="", session=None, **kwargs):
        """通用参数级管线入口：本引擎只跑差分线（diagnose），此处一律 fail-closed 不产出。"""
        return None

    async def diagnose(
        self,
        endpoint: str,
        param: str,
        own_value: str,
        identities: IdentityMatrix,
        session_mgr=None,  # 兼容挂载点签名（请求统一经 identities 分发）
        **opts,
    ) -> Optional[Dict]:
        """对单个候选端点做完整差分诊断。返回 finding 或 None（fail-closed）。"""
        id_a = identities.identity_a
        id_b = identities.identity_b
        if not id_a or not id_b:
            return None
        if not self.is_id_candidate(param, own_value):
            return None
        if not str(endpoint or "").startswith(("http://", "https://")):
            return None

        shell_sim = float(getattr(settings, "idor_shell_sim_threshold", 0.85) or 0.85)

        # 1) 自属基线：身份 B 能否直接拿走身份 A 的自身资源（最强证明）
        base_sig = await dual_session_probe(
            self._replace_param(endpoint, param, own_value), "GET", id_a, id_b, identities, timeout=10)
        if oracle_verdict(base_sig, shell_sim) != "horizontal_leak":
            # 已强制鉴权 / 公开壳 / 探针失败 → 含突变池整体跳过该候选（fail-closed）
            return None

        # 2) 突变 victim 池：邻近对象 ID（互补证明：B 可横扫邻接资源）
        leak_sigs: List[tuple] = []
        budget = int(getattr(settings, "idor_victim_mutations", 6) or 6)
        for mv in self._idor._generate_id_mutations(own_value)[:budget]:
            if not mv or mv == own_value:
                continue
            s = await dual_session_probe(
                self._replace_param(endpoint, param, mv), "GET", id_a, id_b, identities, timeout=10)
            if oracle_verdict(s, shell_sim) == "horizontal_leak":
                leak_sigs.append((mv, s))

        # 3) 证据择优：默认"自属被拿走"；突变更强（b_private 机器实锤）才升级
        proof_val, proof_sig = own_value, base_sig
        for mvv, s in leak_sigs:
            if s.get("b_private") and not proof_sig.get("b_private"):
                proof_val, proof_sig = mvv, s

        anon = bool(getattr(identities, "anon", False))
        b_private = proof_sig.get("b_private") or {}
        leak_url = self._replace_param(endpoint, param, proof_val)
        # 审计线 + AI 证据包：把身份类型写进差分观测
        diff = dict(proof_sig)
        diff["anon"] = anon

        finding = {
            "url": leak_url,
            "parameter": param,
            "value": own_value,
            "mutated_value": proof_val if proof_val != own_value else None,
            "type": "IDOR/BOLA-水平越权（双会话差分证实）",
            "severity": "High" if b_private else "Medium",
            "title": "水平越权：另一个身份未授权访问属主敏感资源",
            "description": (
                f"身份B（{'匿名' if anon else '第二账号'}）请求 {leak_url} 返回 {proof_sig.get('b_status')}，"
                f"命中私有标记 {', '.join(sorted(b_private)) if b_private else '（仅内容差分，需复核）'}；"
                f"身份A 对自属值 {own_value} 的同类请求为 {proof_sig.get('a_status')}。"
                f"body_sim={proof_sig.get('body_sim')}，判定为未授权访问他人资源（水平越权/BOLA）。"
            ),
            "evidence": (
                f"双会话差分证实：身份B（{'匿名' if anon else '第二账号'}，状态 {proof_sig.get('b_status')}）"
                f"访问 {param}={proof_val} 命中私有标记 "
                f"{', '.join(sorted(b_private)) if b_private else '（仅内容差分，需复核）'}；"
                f"身份A（状态 {proof_sig.get('a_status')}）自属值 {own_value}。body_sim={proof_sig.get('body_sim')}"
            ),
            "remediation": "服务端按资源属主对每个对象做 ACL/属主断言，禁止仅依赖前端隐藏或不可枚举性",
            "recommendation": "对 id 类参数做属主校验；改用不可预测对象引用（UUId/带签名的引用）；记录两次身份的访问审计",
            "ai_verdict": "待验证",
            "confidence": "high" if b_private else "medium",
            "cvss": ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" if anon
                     else "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
            "method": "idor_dual_session",
            "anonymity": "anonymous" if anon else "second_account",
            "oracle_diff": diff,
        }
        return enrich_finding(finding, method="GET")


__all__ = ["DualSessionOracleEngine"]
