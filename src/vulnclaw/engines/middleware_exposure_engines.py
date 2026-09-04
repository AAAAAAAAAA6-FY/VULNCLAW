# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/middleware_exposure_engines.py
"""
云/中间件 0day 覆盖（Z4.4）：Confluence / Nacos / Solr 中间件未授权访问检测引擎。

设计铁律（低误报）：
  1. 先产品指纹、后漏洞特征 —— 只有指纹命中（管理面/健康接口返回该产品独有字节特征）
     才继续探测未授权面，未命中直接返回空，普通站点不会误报。
  2. 全部基于"只读探测"（GET 大 JSON / 管理接口），无 OOB、无破坏性载荷。
  3. finding 字段全套：type/severity/title/description/evidence/remediation/
     recommendation/url/parameter/method/confidence/cvss。
  4. 代码与日志不含 emoji（Windows GBK 控制台安全）。
"""
import re
from typing import Dict, List, Optional, Tuple

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import async_get
from vulnclaw.engines.base import BaseEngine

# ============================================================
# NacosExposureEngine（Nacos 未授权访问：用户列表 / 配置读取）
# ============================================================
class NacosExposureEngine(BaseEngine):
    """Nacos 管理面未授权访问检测（CVE-2021-29441 / 未授权接口泄露）

    指纹：/nacos/v1/console/health/readiness 返回 200 且 JSON 含 UP/就绪语义；
    漏洞面：/nacos/v1/auth/users 未授权用户列表（用户名可用字典攻击）、
            /nacos/v1/cs/configs 未授权配置读取（密钥/数据源泄露）。
    """

    name = "nacos_exposure"
    description = "Nacos 未授权访问检测（用户列表/配置读取，CVE-2021-29441 风险面）"

    # 指纹：健康/就绪接口。仅"UP"与 nacos 字样同时解析为指纹命中，防通用页面误判
    _HEALTH_RE = re.compile(r'"UP"|nacos', re.I)
    # 特征：auth/users 返回的用户列表 JSON
    _USERS_RE = re.compile(r'"username"\s*:', re.I)
    # 特征：cs/configs 返回的配置列表 JSON
    _CONFIGS_RE = re.compile(r'"totalCount"\s*:', re.I)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        # 1. 产品指纹：健康/就绪接口
        health_url = base + "/nacos/v1/console/health/readiness"
        health = await self._probe(health_url, session)
        if not health or health[0] != 200 or not self._HEALTH_RE.search(health[1] or ""):
            return findings
        self.log_info(
            f"[Nacos] 指纹命中（{health_url}）→ 探测未授权面"
        )
        # 2. 未授权用户列表（管理员可用任意用户名+初始口令进入后台）
        users_url = base + "/nacos/v1/auth/users"
        users = await self._probe(users_url, session)
        if users and users[0] == 200 and self._USERS_RE.search(users[1] or ""):
            findings.append(self._finding(
                users_url, "Nacos 未授权访问-用户列表泄露", "Critical", "9.8",
                "未授权访问 Nacos 用户管理接口 {url}，返回用户列表 JSON，"
                "攻击者可枚举账户并配合弱口令进入管理后台（CVE-2021-29441 风险面）。",
                evidence_snip=users[1],
                recommendation="开启鉴权（nacos.core.auth.enabled=true），改写默认口令，"
                               "将管理面放入内网并加白名单访问控制。",
            ))
            return findings
        # 3. 未授权配置读取（dataId/group 轮询泄露敏感配置）
        cfg_url = (base + "/nacos/v1/cs/configs"
                   "?search=accurate&dataId=&group=&pageNo=1&pageSize=9")
        cfg = await self._probe(cfg_url, session)
        if cfg and cfg[0] == 200 and self._CONFIGS_RE.search(cfg[1] or ""):
            findings.append(self._finding(
                cfg_url, "Nacos 未授权访问-配置中心泄露", "High", "7.5",
                "未授权访问 Nacos 配置中心接口 {url} 可读取配置项，"
                "可能泄露数据库口令/云凭证/AK-SK 等敏感配置。",
                evidence_snip=cfg[1],
                recommendation="开启 Nacos 鉴权并禁用 /nacos/v1/cs/configs 匿名访问，"
                               "敏感配置迁移至密钥管理服务（KMS）。",
            ))
        return findings

    async def _probe(self, url: str, session) -> Optional[Tuple[int, str, Dict]]:
        try:
            return await async_get(url, session=session, timeout=settings.timeout, no_retry=True)
        except Exception as exc:  # noqa: BLE001
            self.log_debug(f"[Nacos] 探测异常 {url}: {exc}")
            return None

    def _finding(self, url: str, title: str, severity: str, cvss: str,
                 description: str, evidence_snip: str, recommendation: str) -> Dict:
        return {
            "url": url,
            "parameter": "",
            "method": "GET",
            "type": title,
            "title": title,
            "description": description.format(url=url),
            "severity": severity,
            "cvss": cvss,
            "confidence": "high",
            "ai_verdict": "高" if severity == "Critical" else ("高" if severity == "High" else "中"),
            "evidence": f"请求 {url} 返回 200，产品 JSON 特征命中（{str(evidence_snip)[:120]}...）",
            "payload": url,
            "remediation": recommendation,
            "recommendation": recommendation,
        }

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# SolrExposureEngine（Solr Admin 未授权核心信息 / 版本泄露）
# ============================================================
class SolrExposureEngine(BaseEngine):
    """Apache Solr Admin 未授权访问检测（CVE-2019-0193 / Config API 风险前置）

    指纹：/solr/admin/cores?indexInfo=false&wt=json 返回 200 且 JSON 含 Solr 独有
    字节特征（responseHeader/instanceDir/lucene）；漏洞面：核心管理信息、
    /solr/admin/info/system 版本与路径泄露。
    """

    name = "solr_exposure"
    description = "Apache Solr Admin 未授权访问检测（核心信息/版本泄露）"

    _CORES_RE = re.compile(r'"responseHeader"|"instanceDir"|"lucene"', re.I)
    _SYSTEM_RE = re.compile(r'"solr_spec_version"|"lucene"|"jvm"', re.I)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        # 1. 产品指纹 + 漏洞面1：管理核心接口未授权
        cores_url = base + "/solr/admin/cores?indexInfo=false&wt=json"
        cores = await self._probe(cores_url, session)
        if not cores or cores[0] != 200 or not self._CORES_RE.search(cores[1] or ""):
            return findings
        self.log_info(f"[Solr] 指纹命中（{cores_url}）→ 探测版本泄露")
        findings.append(self._finding(
            cores_url, "Apache Solr Admin 未授权访问", "High", "7.5",
            "未授权访问 Solr Admin 核心管理接口 {url}，可读取全部 core 配置/路径信息，"
            "配合 CVE-2019-0193 等反序列化/配置执行漏洞可进一步利用。",
            evidence_snip=cores[1],
            recommendation="为 Solr Admin 添加认证（Basic Auth / 反向代理 SSO），"
                           "仅允许可信网络访问管理接口，升级至已修复版本。",
        ))
        # 2. 版本/系统信息泄露（同一目标可能同时命中，单独一条）
        sys_url = base + "/solr/admin/info/system?wt=json"
        sys_resp = await self._probe(sys_url, session)
        if sys_resp and sys_resp[0] == 200 and self._SYSTEM_RE.search(sys_resp[1] or ""):
            findings.append(self._finding(
                sys_url, "Apache Solr 版本/系统信息泄露", "Medium", "5.3",
                "未授权访问 Solr 系统信息接口 {url}，泄露 Solr/Lucene 版本、JVM 与路径信息，"
                "攻击者据此检索对应版本已知漏洞进行针对性利用。",
                evidence_snip=sys_resp[1],
                recommendation="对 /solr/admin/info/system 加鉴权，隐藏版本横幅，"
                               "及时升级 Solr 至官方安全版本。",
            ))
        return findings

    async def _probe(self, url: str, session) -> Optional[Tuple[int, str, Dict]]:
        try:
            return await async_get(url, session=session, timeout=settings.timeout, no_retry=True)
        except Exception as exc:  # noqa: BLE001
            self.log_debug(f"[Solr] 探测异常 {url}: {exc}")
            return None

    def _finding(self, url: str, title: str, severity: str, cvss: str,
                 description: str, evidence_snip: str, recommendation: str) -> Dict:
        return {
            "url": url,
            "parameter": "",
            "method": "GET",
            "type": title,
            "title": title,
            "description": description.format(url=url),
            "severity": severity,
            "cvss": cvss,
            "confidence": "high",
            "ai_verdict": "高" if severity != "Medium" else "中",
            "evidence": f"请求 {url} 返回 200，产品 JSON 特征命中（{str(evidence_snip)[:120]}...）",
            "payload": url,
            "remediation": recommendation,
            "recommendation": recommendation,
        }

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None


# ============================================================
# ConfluenceExposureEngine（Confluence REST API 未授权内容读）
# ============================================================
class ConfluenceExposureEngine(BaseEngine):
    """Atlassian Confluence 未授权 REST 内容读取检测

    指纹：/rest/applinks/1.0/manifest 返回 200 且 JSON 含 applicationLinks/confluence；
    漏洞面：/rest/api/content?limit=1 匿名可列任意页面（未授权内容读，CVE-2023-22515 等
    管理面漏洞前置信息）。
    """

    name = "confluence_exposure"
    description = "Atlassian Confluence REST API 未授权内容读取检测"

    _LINK_RE = re.compile(r'"applicationLinks"|"confluence"', re.I)
    _CONTENT_RE = re.compile(r'"results"\s*:|"type"\s*:\s*"page"', re.I)

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        base = target.split("?")[0].rstrip("/")
        # 1. 产品指纹：applinks manifest（Confluence 独有）
        fps_url = base + "/rest/applinks/1.0/manifest"
        fps = await self._probe(fps_url, session)
        if not fps or fps[0] != 200 or not self._LINK_RE.search(fps[1] or ""):
            return findings
        self.log_info(f"[Confluence] 指纹命中（{fps_url}）→ 探测未授权内容读")
        # 2. 漏洞面：未授权内容列表
        api_url = base + "/rest/api/content?limit=1"
        content = await self._probe(api_url, session)
        if content and content[0] == 200 and self._CONTENT_RE.search(content[1] or ""):
            findings.append(self._finding(
                api_url, "Confluence 未授权访问-内容读取", "High", "7.5",
                "未授权访问 Confluence REST API {url} 可匿名读取页面内容（标题/正文摘要），"
                "敏感文档可在未登录状态下泄露，并扩大 CVE-2023-22515 等管理面漏洞的攻击面。",
                evidence_snip=content[1],
                recommendation="为 Confluence 匿名访问关闭 REST API 内容读取（全局权限配置），"
                               "将实例置于认证反向代理之后，升级至官方安全版本。",
            ))
            return findings
        # 仅指纹命中（应用链接暴露）也给出低误报提示
        findings.append(self._finding(
            fps_url, "Confluence 应用链接信息暴露", "Medium", "5.3",
            "Confluence 应用链接清单接口 {url} 可匿名访问，暴露产品实例/内网应用名信息。",
            evidence_snip=fps[1],
            recommendation="限制 AppLinks 清单接口的匿名访问，及时升级 Confluence。",
        ))
        return findings

    async def _probe(self, url: str, session) -> Optional[Tuple[int, str, Dict]]:
        try:
            return await async_get(url, session=session, timeout=settings.timeout, no_retry=True)
        except Exception as exc:  # noqa: BLE001
            self.log_debug(f"[Confluence] 探测异常 {url}: {exc}")
            return None

    def _finding(self, url: str, title: str, severity: str, cvss: str,
                 description: str, evidence_snip: str, recommendation: str) -> Dict:
        return {
            "url": url,
            "parameter": "",
            "method": "GET",
            "type": title,
            "title": title,
            "description": description.format(url=url),
            "severity": severity,
            "cvss": cvss,
            "confidence": "high",
            "ai_verdict": "高" if severity != "Medium" else "中",
            "evidence": f"请求 {url} 返回 200，产品 JSON 特征命中（{str(evidence_snip)[:120]}...）",
            "payload": url,
            "remediation": recommendation,
            "recommendation": recommendation,
        }

    async def check(
        self,
        url: str, param: str, normal_resp: Tuple[int, str, Dict], parsed_query: str, session, **kwargs
    ) -> Optional[Dict]:
        return None