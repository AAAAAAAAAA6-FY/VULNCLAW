# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/exposure_fingerprint_engine.py
"""通用中间件/平台未授权暴露检测引擎（引擎合并样板）。

背景：middleware_exposure_engines.py 中 Nacos / Solr / Confluence 三个引擎是
**同一套骨架**——「指纹路径 + 正则 → 命中 → 探测未授权面 → 正则匹配 → 出
finding」，差异只在路径、正则与文案。评审建议"砍掉 70% 引擎"，但直接删会丢
覆盖（且经盘点确认：零命中是靶场覆盖偏差，不是引擎无用）。

正确做法是把差异抽成**规则数据**，用一个通用引擎消费：

  - 规则数据：core/data/exposure_rules.yaml（新增中间件只需加一条 YAML）
  - 检测语义：与三个旧引擎**逐字一致**（同路径、同正则、同 severity/cvss/文案）
  - finding 字段：type 取 title，与旧引擎完全一致 → 验证链 / 去重 / 报告零回归

双跑期约定：旧引擎与本引擎**并存**，对比 finding 完全一致后再下线旧引擎，
在此之前不得删除任何旧引擎（质量红线）。

用法（引擎自动发现，无需手工登记）：
    引擎名为 exposure_fingerprint，由 scanner 的 glob 自动发现注册。
"""
import os
import re
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine

_RULES_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "core", "data", "exposure_rules.yaml",
)

# 进程内缓存（规则是静态数据，无需每次扫描重读）
_RULES_CACHE: Optional[List[Dict]] = None


def load_exposure_rules(path: str = "") -> List[Dict]:
    """加载暴露检测规则并预编译正则。

    任何加载失败（缺文件 / YAML 语法错 / 正则非法）都返回空列表并告警，
    **绝不抛异常阻断扫描**（fail-safe）。
    """
    global _RULES_CACHE
    if _RULES_CACHE is not None and not path:
        return _RULES_CACHE
    p = path or _RULES_PATH
    try:
        import yaml  # 局部导入：本模块被 glob 扫描时不应因缺依赖而炸

        with open(p, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        rules = [r for r in (data.get("rules") or []) if isinstance(r, dict)]
        for r in rules:
            fp = r.get("fingerprint") or {}
            if isinstance(fp, dict) and fp.get("pattern"):
                fp["_re"] = re.compile(fp["pattern"], re.I)
            for pr in r.get("probes") or []:
                if isinstance(pr, dict) and pr.get("pattern"):
                    pr["_re"] = re.compile(pr["pattern"], re.I)
        if not path:
            _RULES_CACHE = rules
        logger.debug(f"[ExposureFingerprint] 已加载 {len(rules)} 条暴露规则")
        return rules
    except Exception as exc:  # noqa: BLE001 - 规则加载失败只影响本引擎
        logger.warning(f"[ExposureFingerprint] 规则加载失败（该引擎跳过）: {exc}")
        return []


class ExposureFingerprintEngine(BaseEngine):
    """规则驱动的中间件/平台未授权暴露检测（合并 nacos/solr/confluence 等）。"""

    name = "exposure_fingerprint"
    description = "通用中间件/平台未授权暴露检测（规则驱动）"

    def __init__(self, *args, **kwargs):
        self._rules_path = kwargs.pop("rules_path", "")
        super().__init__(*args, **kwargs)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        rules = load_exposure_rules(self._rules_path)
        if not rules:
            return []
        base = str(target or "").split("?")[0].rstrip("/")
        if not base:
            return []
        findings: List[Dict] = []
        for rule in rules:
            try:
                findings.extend(await self._scan_rule(base, rule, session))
            except Exception as exc:  # noqa: BLE001 - 单规则异常不影响其他规则
                logger.debug(
                    f"[ExposureFingerprint] 规则 {rule.get('id')} 异常（跳过）: {exc}"
                )
        return findings

    async def _scan_rule(self, base: str, rule: Dict, session) -> List[Dict]:
        """单条规则：指纹 →（可选指纹本身即漏洞面）→ probes →（可选降级提示）。"""
        fp = rule.get("fingerprint") or {}
        fp_path = str(fp.get("path") or "")
        if not fp_path:
            return []
        fp_resp = await self._probe(base + fp_path, session)
        fp_re = fp.get("_re")
        if fp_re is None and fp.get("pattern"):
            fp_re = re.compile(fp["pattern"], re.I)
        want_status = int(fp.get("status", 200))
        # 铁律：指纹未命中直接跳过（防止通用页面误报）
        if not fp_resp or fp_resp[0] != want_status or not (fp_re and fp_re.search(fp_resp[1] or "")):
            return []

        self.log_info(
            f"[ExposureFingerprint] {rule.get('name') or rule.get('id')} 指纹命中 → 探测未授权面"
        )
        out: List[Dict] = []

        # 1) 指纹响应本身即构成漏洞面（Solr cores 未授权）
        if isinstance(rule.get("fingerprint_finding"), dict):
            out.append(self._build(base + fp_path, rule["fingerprint_finding"], fp_resp[1]))

        # 2) 漏洞面探测
        hit = False
        for pr in rule.get("probes") or []:
            if not isinstance(pr, dict):
                continue
            p_path = str(pr.get("path") or "")
            if not p_path:
                continue
            resp = await self._probe(base + p_path, session)
            p_re = pr.get("_re")
            if p_re is None and pr.get("pattern"):
                p_re = re.compile(pr["pattern"], re.I)
            if resp and resp[0] == 200 and p_re and p_re.search(resp[1] or ""):
                out.append(self._build(base + p_path, pr, resp[1]))
                hit = True
                if rule.get("stop_on_first_hit", True):
                    break

        # 3) 指纹命中但漏洞面均未命中 → 降级提示（Confluence AppLinks）
        if not hit and isinstance(rule.get("fallback_finding"), dict):
            out.append(self._build(base + fp_path, rule["fallback_finding"], fp_resp[1]))

        return out

    async def _probe(self, url: str, session) -> Optional[Tuple[int, str, Dict]]:
        try:
            return await async_get(url, session=session, timeout=settings.timeout, no_retry=True)
        except Exception as exc:  # noqa: BLE001
            self.log_debug(f"[ExposureFingerprint] 探测异常 {url}: {exc}")
            return None

    @staticmethod
    def _build(url: str, spec: Dict, evidence_snip: str) -> Dict:
        """构造 finding，字段与原三引擎的 _finding 保持一致（type 取 title）。"""
        severity = str(spec.get("severity") or "Medium")
        title = str(spec.get("title") or "")
        desc = str(spec.get("description") or "")
        rec = str(spec.get("recommendation") or "")
        try:
            desc = desc.format(url=url)
        except Exception:  # noqa: BLE001 - 占位符异常不阻断出 finding
            pass
        return {
            "url": url,
            "parameter": "",
            "method": "GET",
            "type": title,
            "title": title,
            "description": desc,
            "severity": severity,
            "cvss": str(spec.get("cvss") or ""),
            "confidence": "high",
            "ai_verdict": "高" if severity in ("Critical", "High") else "中",
            "evidence": (
                f"请求 {url} 返回 200，产品 JSON 特征命中"
                f"（{str(evidence_snip)[:120]}...）"
            ),
            "payload": url,
            "remediation": rec,
            "recommendation": rec,
        }

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


__all__ = ["ExposureFingerprintEngine", "load_exposure_rules"]
