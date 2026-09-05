# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Implementation functions for the v100 taskgen phase."""
import os
import re
import time
from typing import Dict, List, Optional
from vulnclaw.core.logger import logger
from vulnclaw.core.session_manager import get_session_manager
from vulnclaw.ai.v100.batch_processor import BatchProcessor
from vulnclaw.core.settings import settings
from vulnclaw.core.utils import cap

# 性能优化1：静态资源扩展名（源头丢弃，不进入引擎检测流程）
STATIC_RESOURCE_EXTENSIONS = frozenset({
    '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.bmp',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.mp4', '.webm', '.mp3', '.ogg', '.wav',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
    '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.map', '.webp', '.avif',
})


def _is_static_resource_url(url: str) -> bool:
    """判断 URL 是否指向静态资源文件（无参数可注入，检测收益≈0）。"""
    if not url:
        return False
    try:
        from urllib.parse import urlparse

        path = urlparse(url).path.lower()
    except Exception:  # noqa: BLE001
        path = url.split('?')[0].split('#')[0].lower()
    return any(path.endswith(ext) for ext in STATIC_RESOURCE_EXTENSIONS)


# 凭据类参数提示词：命中即视为鉴权/密钥材料，不应进入通用注入模糊循环
# （fuzzing API key / token 值做 SQLi/XSS 收益极低且易触发 WAF；token 类
# 专用引擎仍可在其自身逻辑里覆盖必要场景）。
CREDENTIAL_PARAM_HINTS = (
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key",
    "api-key", "authorization", "auth_token", "auth-token", "cookie",
    "session", "credential", "private_key", "access_key", "accesskey",
    "client_secret", "bearer", "jwt", "csrf_token", "xsrf_token",
)


def _is_credential_param(param: str) -> bool:
    """判断参数名是否属于凭据/密钥类，应跳过通用注入模糊。"""
    if not param:
        return False
    p = param.lower()
    return any(hint in p for hint in CREDENTIAL_PARAM_HINTS)


async def _scan_idor(self):
    try:
        from vulnclaw.modules.vuln_scanner import scan_idor
        session_mgr = get_session_manager()
        roles = session_mgr.get_roles()
        if len(roles) < 2:
            logger.info("ℹ️ [IDOR] skipped: at least two roles are required")
            return
        logger.info(f"🎯 [IDOR] 使用 {len(roles)} 个角色扫查...")
        all_params = self._recon_brief.get("url_params", [])
        if not all_params:
            all_params = ["id", "user", "page", "file"]
        idor_findings = []
        for param in cap(all_params, settings.max_idor_params):
            test_url = self.target
            if '?' not in test_url:
                test_url += f"?{param}=1"
            else:
                test_url += f"&{param}=1"
            try:
                results = await scan_idor(test_url, session_mgr, roles)
                idor_findings.extend(results)
            except Exception:
                logger.debug("suppressed exception (core audit)")
        for f in idor_findings:
            self._add_finding(f)
            self._idor_findings += 1
        logger.info(f"   ✅发现 {len(idor_findings)} 个IDOR漏洞")
    except Exception as e:
        logger.warning(f"⚠️ IDOR扫描失败: {e}")
async def _check_default_creds(self):
    try:
        from vulnclaw.modules.vuln_scanner import check_default_credentials
        logger.info("📬 [默认凭证] 检查...")
        creds = await check_default_credentials(
            self.target,
            self.session,
            self._recon_brief.get("tech_stack", []),
            timeout=10,
            max_attempts=20
        )
        for c in creds:
            self._add_finding(c)
            self._cred_findings += 1
        logger.info(f"   Found {len(creds)} default credentials")
    except Exception as e:
        logger.warning(f"⚠️ 默认凭证检查失败: {e}")
async def _generate_tasks(self):
    logger.info("🔎 [总指挥] 生成任务...")
    burp_params = self._recon_brief.get("burp_params", [])
    all_params = list(set(
        self._recon_brief.get("url_params", [])
        + self._recon_brief.get("forms", [])
        + burp_params
    ))
    if not all_params:
        all_params = ["id", "page", "user", "file", "q", "s", "cat", "product", "order", "view"]
    all_params = cap(all_params, settings.max_url_params)
    # A3.2: 目标画像增量——加载上次画像，未变资产相关任务不入队（只测变化面）
    # 兜底默认实现：增量关闭/画像不可用时，任何资产一律视为“已变化”→ 全量不跳过。
    def _a32_never_unchanged(*_args, **_kwargs):
        return False

    generic_asset_unchanged = _a32_never_unchanged
    crawl_asset_unchanged = _a32_never_unchanged
    _a32_prev = None
    _a32_assets = {}
    _a32_target_unchanged = False
    self._a32_skipped = 0
    if getattr(settings, "incremental_scan", False):
        try:
            from vulnclaw.core_modules.asset_profile import (
                crawl_asset_unchanged as crawl_asset_unchanged,
                generic_asset_unchanged as generic_asset_unchanged,
                load_prev_profile,
                profile_expired,
                surface_fp,
            )
            _a32_prev = load_prev_profile(self.target)
            if _a32_prev and not profile_expired(
                _a32_prev, float(getattr(settings, "asset_profile_ttl_hours", 168.0))
            ):
                _a32_assets = _a32_prev.get("assets") or {}
                _a32_target_unchanged = _a32_prev.get("surface_fp") == surface_fp(self._recon_brief)
                if _a32_target_unchanged:
                    logger.info("   [A3.2] 目标表面指纹与上次画像一致 → 参数级任务全部跳过（只测变化面）")
        except Exception as _a32_exc:  # noqa: BLE001
            logger.debug(f"   [A3.2] 画像加载失败（本次全量扫描）: {_a32_exc}")
    tech_stack = self._recon_brief.get("tech_stack", [])
    tech_lower = ' '.join(tech_stack).lower()
    engine_priority = {
        "sqli": 10 if any(t in tech_lower for t in ['php', 'java', 'python', 'asp.net']) else 8,
        "xss": 9,
        "lfi": 9 if 'php' in tech_lower else 7,
        "rfi": 8 if 'php' in tech_lower else 6,
        "cmdi": 8,
        "nosql": 7 if 'node' in tech_lower or 'java' in tech_lower else 5,
        "ssti": 8 if any(t in tech_lower for t in ['python', 'java', 'php']) else 6,
        "ssrf": 7,
        "xxe": 8 if 'java' in tech_lower else 6,
        "idor": 8,
        "jwt": 7,
        "oauth": 7,
        "graphql": 7 if '/graphql' in str(self._recon_brief.get('apis', [])) else 5,
        "file_upload": 8,
        "el_injection": 8 if 'java' in tech_lower else 6,
        "hpp": 7,
        "cors": 6,
        "security_headers": 5,
        "race_condition": 7,
        "open_redirect": 7,
        "crlf": 6,
        "ldap": 6,
        "host_header": 6,
        "info_leak": 7,
        "business_logic": 8,
        "cache_poison": 5,
        "session": 5,
        "deserialization": 7,
        "dotnet_deserialization": 6 if 'dotnet' in tech_lower or 'asp.net' in tech_lower else 4,
        "container_security": 5,
        "websocket_security": 6,
        "api_security": 6,
        "api_version": 5,
        "xpath_injection": 7 if any(t in tech_lower for t in ["xml", "java", "php"]) else 5,
        "ssi_injection": 7 if "apache" in tech_lower or "php" in tech_lower else 5,
        "prototype_pollution": 6 if ("node" in tech_lower or "express" in tech_lower) else 4,
        "csrf": 7,
        "web_cache_deception": 6,
        "jsonp_hijacking": 5,
        "log4shell": 8 if any(t in tech_lower for t in ["java", "log4j"]) else 5,
        "fastjson_deserialization": 8 if "java" in tech_lower else 4,
        "struts2_ognl": 7 if any(t in tech_lower for t in ["java", "struts"]) else 4,
        "spring4shell": 7 if "spring" in tech_lower or "java" in tech_lower else 4,
        "view_state": 6 if any(t in tech_lower for t in ["dotnet", "asp.net", "iis"]) else 4,
        "spring_actuator": 7 if "spring" in tech_lower or "java" in tech_lower else 5,
        "source_code_leak": 6,
        "auth_enumeration": 6,
        "shiro_rememberme": 6 if ("shiro" in tech_lower or "java" in tech_lower) else 4,
        "spring_cloud_gateway": 8 if ("spring" in tech_lower or "gateway" in tech_lower) else 4,
        "container_platform_exposure": 5,
        "admin_console_exposure": 6 if any(t in tech_lower for t in ["java","tomcat","jboss","weblogic","jenkins"]) else 4,
        "backup_file_leak": 6,
        "swagger_api_doc": 7 if "/api" in str(self._recon_brief.get('apis', [])) else 5,
        # 合并去重: graphql_introspection 为 graphql 引擎端点级内省探测的子集, 由 graphql 统一承接(见 net_engines.py GraphQLEngine.scan)
        "prometheus_metrics": 6 if ("spring" in tech_lower or "go" in tech_lower) else 4,
        "rate_limit": 5,
        "verb_tampering": 5
    }
    # P4-1: 情报驱动 —— 按 Shodan/Censys 标记的服务类型与开放端口提升对应引擎优先级
    intel = self._recon_brief.get("intel") or {}
    intel_hints = [str(h).lower() for h in (intel.get("service_hints") or [])]
    intel_ports = set(intel.get("ports") or [])
    intel_vuln_count = len(intel.get("vulns") or [])
    if getattr(settings, "tci_adaptive_planning", True) and (intel_hints or intel_ports):
        def _bump(engine: str, delta: int, cap: int = 10) -> None:
            engine_priority[engine] = min(cap, engine_priority.get(engine, 5) + delta)
        if intel_ports & {3306, 5432, 1433, 1521, 27017} or any(
            h in ("mysql", "postgresql", "mssql", "mongodb", "oracle") for h in intel_hints
        ):
            _bump("sqli", 3); _bump("nosql", 2)
        if any(h in ("java", "tomcat", "spring", "weblogic", "jboss", "jenkins", "elasticsearch") for h in intel_hints):
            _bump("el_injection", 3); _bump("xxe", 2); _bump("deserialization", 2)
        if any(h in ("redis", "memcached", "elasticsearch") for h in intel_hints):
            _bump("ssrf", 3)
        if any(h in ("php", "apache", "nginx", "wordpress", "joomla", "drupal") for h in intel_hints):
            _bump("lfi", 2); _bump("rfi", 2)
        if any(h in ("iis", "asp", "aspx", "dotnet") for h in intel_hints):
            _bump("dotnet_deserialization", 3)
        if 6379 in intel_ports or 11211 in intel_ports:
            _bump("ssrf", 3)
        if 22 in intel_ports or 21 in intel_ports:
            _bump("info_leak", 2)
        if intel_vuln_count > 0:
            # 目标存在历史 CVE → 专项校验类引擎整体加权
            for _eng in ("sqli", "cmdi", "deserialization", "file_upload", "ssrf"):
                _bump(_eng, 1)
        logger.info(
            f"🌐 [情报] 引擎优先级已按情报调整: ports={sorted(intel_ports)[:8]} "
            f"hints={intel_hints[:8]} CVE={intel_vuln_count}"
        )
    business_param_keywords = ["amount", "price", "total", "role", "status", "order", "coupon", "ids", "admin"]
    tasks_added = 0
    # Z1.2（=D2.4）：情报驱动——指纹组件命中 CVE 索引 → 生成高危 CVE 专项任务（数据腿闭环）
    # 索引：thirdparty/nuclei-templates/cve_index（Z1.1）；只取 critical/high，限定条数。
    try:
        cve_task = await self._gen_cve_task()
        if cve_task:
            await self.task_queue.add_task(cve_task, cve_task.get("priority", 10))
            tasks_added += 1
    except Exception as e:
        logger.debug(f"[CVE任务] 生成异常（不影响主流程）: {e}")
    enable_engine_bundle = os.getenv("ENABLE_ENGINE_BUNDLE", "true").lower() != "false"
    parameter_tasks = 0
    batch_pending = []  # P1-4: BatchProcessor 收集同参数多引擎任务
    # 覆盖率优化：原先每参数固定取静态优先级 top-3，第 4 名之后的引擎永远不执行。
    # 现改为 top-3 核心引擎 + 按参数序号轮换 1 个次优引擎（rotation），
    # 30 个参数即可让全部 32 类参数级引擎都获得至少一次执行机会。
    rotation_offset = 0
    self._rotation_offset = 0
    # B: 业务流建模/竞争条件总开关——关闭时从引擎池移除 business_logic/race_condition
    if not getattr(settings, "business_flow_modeling", True):
        engine_priority.pop("business_logic", None)
        engine_priority.pop("race_condition", None)
    for param in all_params:
        if _a32_target_unchanged:
            self._a32_skipped += 1
            continue
        skip, reason = self.local_filter.should_skip(self.target, param, "", 0)
        if skip:
            logger.debug(f"   [skip] 跳过参数 {param}: {reason}")
            continue
        if _is_credential_param(param):
            logger.debug(f"   [skip] 凭据类参数不进通用注入队列: {param}")
            continue
        is_business = any(kw in param.lower() for kw in business_param_keywords)
        engine_scores = []
        for engine_name, base_priority in engine_priority.items():
            priority = base_priority
            if is_business and engine_name == "business_logic":
                priority = 10
            if getattr(settings, "tci_adaptive_planning", True):
                if 'java' in tech_lower and engine_name in ['el_injection', 'xxe']:
                    priority += 2
                if 'php' in tech_lower and engine_name in ['lfi', 'ssti']:
                    priority += 2
                if 'python' in tech_lower and engine_name == 'ssti':
                    priority += 2
            engine_scores.append((engine_name, priority))
        engine_scores.sort(key=lambda x: x[1], reverse=True)
        top_engines = engine_scores[:3]
        # 轮换引擎：top-3 之外的引擎按参数序号轮流获得执行机会（覆盖率优化）
        remaining_engines = engine_scores[3:]
        selected_engines = [engine_name for engine_name, _ in top_engines]
        if remaining_engines:
            rotating_engine = remaining_engines[rotation_offset % len(remaining_engines)][0]
            if rotating_engine not in selected_engines:
                selected_engines.append(rotating_engine)
            rotation_offset += 1
        task_data = {
                "type": "engine_bundle",
                "engines": selected_engines,
                "target": self.target,
                "param": param,
                "priority": top_engines[0][1],
                "payload_limit": 12 if is_business else 10,
                "created_at": time.time(),
        }
        if not enable_engine_bundle:
            for engine_name in selected_engines:
                single_task = {
                    **task_data,
                    "type": "engine_check",
                    "engine": engine_name,
                }
                # P1-4: BatchProcessor 合并同参数多引擎任务（一次 AI 调用判定）
                batch_pending.append(single_task)
                tasks_added += 1
        else:
            await self.task_queue.add_task(task_data, top_engines[0][1])
            tasks_added += 1
        parameter_tasks += 1
    if enable_engine_bundle:
        original_count = parameter_tasks * 3
        saved = ((original_count - parameter_tasks) / original_count * 100) if original_count else 0
        logger.info(f"   📊 Bundle 模式: 生成 {parameter_tasks} 个引擎任务（原 {original_count} 个），AI 调用预计节省 {saved:.0f}%")
    else:
        logger.info("   Bundle mode disabled; falling back to individual engine tasks")
    # P1-4: BatchProcessor 接线——同参数多引擎任务合并为批量任务（一次 AI 调用判定）
    if batch_pending:
        bp = self.batch_processor
        if bp is None:
            bp = BatchProcessor(max_batch_size=5)
            self.batch_processor = bp
        merged = bp.merge_tasks(batch_pending)
        saved_n = bp.get_stats().get("api_calls_saved", 0)
        for t in merged:
            await self.task_queue.add_task(t, t.get("priority", 5))
        logger.info(f"📦 [Batch] 合并 {len(batch_pending)} 个单引擎任务 → {len(merged)} 个（节省 {saved_n} 次 AI 调用）")
        logger.info(f"   ✅生成 {tasks_added} 个参数级派生任务")
    static_skipped = 0
    for api in cap(self._recon_brief.get("apis", []), settings.max_api_endpoints):
        if _a32_target_unchanged or generic_asset_unchanged(_a32_assets, "api", api):
            self._a32_skipped += 1
            continue
        if _is_static_resource_url(api):
            static_skipped += 1
            continue
        if api.startswith('/'):
            full_api = self.target.rstrip('/') + api
            task_data = {
                "type": "api_check",
                "engine": "graphql" if '/graphql' in api else "sqli",
                "target": full_api,
                "param": "query",
                "priority": 8,
                "payload_limit": 10,
                "created_at": time.time()
            }
            await self.task_queue.add_task(task_data, 8)
            tasks_added += 1
    for js_api in cap(self._recon_brief.get("js_endpoints", []), settings.max_js_endpoints):
        if not isinstance(js_api, str) or not js_api:
            continue
        if _a32_target_unchanged or generic_asset_unchanged(_a32_assets, "js", js_api):
            self._a32_skipped += 1
            continue
        if js_api.startswith('http'):
            full_api = js_api
        elif js_api.startswith('/'):
            full_api = self.target.rstrip('/') + js_api
        else:
            continue
        if _is_static_resource_url(full_api):
            static_skipped += 1
            continue
        # 从端点自身 query 派生参数（修复 /xss?s=hello 的 s 永不被探测）；无 query 退化为 id
        _jq = full_api.split('?', 1)[1] if '?' in full_api else ''
        _jparams = [p.split('=')[0] for p in _jq.split('&') if '=' in p] or ["id"]
        _jl = full_api.lower()
        if '/api' in _jl or '/graphql' in _jl:
            _jengine = "sqli"
        elif re.search(r'/sqli|/sql|/inject', _jl):
            _jengine = "sqli"
        elif re.search(r'/xss|csp|/reflect', _jl):
            _jengine = "xss"
        else:
            _jengine = "xss"
        for _jp in cap(_jparams, settings.max_test_params_per_endpoint):
            if _is_credential_param(_jp):
                continue
            task_data = {
                "type": "api_check",
                "engine": _jengine,
                "target": full_api.split('?')[0],
                "param": _jp,
                "priority": 7,
                "payload_limit": 8,
                "created_at": time.time()
            }
            await self.task_queue.add_task(task_data, 7)
            tasks_added += 1
    # B: 同源链接爬虫发现的端点 → 喂进引擎循环（target=端点URL，param=端点自带参数）
    _crawled = self._recon_brief.get("crawled_endpoints", []) or []
    for _item in cap(_crawled, settings.max_crawl_endpoints):
        _ep_url = _item.get("url") if isinstance(_item, dict) else _item
        _ep_params = _item.get("params") if isinstance(_item, dict) else None
        if not _ep_url or _is_static_resource_url(_ep_url):
            continue
        _etarget = _ep_url.split('?')[0]  # 去掉 query，由 param 注入（避免 query 重复）
        _ep_params = [p for p in (_ep_params or []) if p and isinstance(p, str)]
        if _a32_target_unchanged or crawl_asset_unchanged(_a32_assets, _ep_url, _ep_params):
            self._a32_skipped += 1
            continue
        _test_params = cap(_ep_params, settings.max_test_params_per_endpoint) or ["id"]
        _el = _etarget.lower()
        _hint = []
        if re.search(r'/sqli|/sql|/inject', _el):
            _hint.append("sqli")
        if re.search(r'/xss|csp|/reflect', _el):
            _hint.append("xss")
        if re.search(r'/upload|/file', _el):
            _hint.append("file_upload")
        if re.search(r'/lfi|/include|/path', _el):
            _hint.append("lfi")
        for _p in _test_params:
            _skip, _reason = self.local_filter.should_skip(_etarget, _p, "", 0)
            if _skip:
                continue
            if _is_credential_param(_p):
                continue
            _es = sorted(engine_priority.items(), key=lambda x: x[1], reverse=True)
            _sel = [e for e, _ in cap(_es, settings.max_engines_per_param)]
            for _h in _hint:
                if _h not in _sel and _h in engine_priority:
                    _sel.append(_h)
            _remain = [e for e, _ in _es[3:] if e not in _sel]
            if _remain:
                _sel.append(_remain[self._rotation_offset % len(_remain)])
                self._rotation_offset += 1
            task_data = {
                "type": "engine_bundle",
                "engines": _sel,
                "target": _etarget,
                "param": _p,
                "priority": engine_priority.get(_sel[0], 8),
                "payload_limit": 10,
                "created_at": time.time(),
                "source": "crawl",
            }
            await self.task_queue.add_task(task_data, task_data["priority"])
            tasks_added += 1
    # C: param_mining（B 侧 recon.py 写入的 D3.5 参数挖掘结果）-> 参数池补测
    if getattr(settings, "scan_param_mining", True):
        _pmined = self._recon_brief.get("param_mining", []) or []
        for _item in cap(_pmined, getattr(settings, "max_param_mining", 0)):
            _pu = _item.get("url") if isinstance(_item, dict) else None
            _pp = _item.get("param") if isinstance(_item, dict) else None
            if not _pu or not _pp or _is_static_resource_url(_pu):
                continue
            _pm_target = _pu.split('?')[0]
            _pm_param = str(_pp)
            if _a32_target_unchanged or crawl_asset_unchanged(_a32_assets, _pu, [_pm_param]):
                self._a32_skipped += 1
                continue
            if _is_credential_param(_pm_param):
                continue
            _es = sorted(engine_priority.items(), key=lambda x: x[1], reverse=True)
            _sel = [e for e, _ in cap(_es, settings.max_engines_per_param)]
            task_data = {
                "type": "engine_bundle",
                "engines": _sel,
                "target": _pm_target,
                "param": _pm_param,
                "priority": engine_priority.get(_sel[0], 8),
                "payload_limit": 10,
                "created_at": time.time(),
                "source": "param_mining",
                "mining_signal": str(_item.get("signal", "") or ""),
                "mining_base_len": int(_item.get("base_len", 0) or 0),
            }
            await self.task_queue.add_task(task_data, task_data["priority"])
            tasks_added += 1
    if static_skipped:
        logger.info(f"   🗑️ [静态资源过滤] 源头丢弃 {static_skipped} 个静态资源 URL")
    if self._a32_skipped:
        logger.info(
            f"   🗃️ [A3.2] 增量扫描：跳过未变资产相关任务 {self._a32_skipped} 个"
            f"（画像 TTL {getattr(settings, 'asset_profile_ttl_hours', 168.0)}h，二次扫描只测变化面）"
        )
    global_engines = [
        "api_version_diff", "request_smuggling", "http2_ws",
        "cache_poison", "info_leak", "mobile_api",
        "websocket_security", "api_version", "graphql",
        "tls_security", "dns_security", "js_library_cve",
        "mass_assignment", "weak_credential",
        "password_reset", "cloud_container_exposure", "backend_component_cve",
        "open_redirect", "cors", "idor", "jwt", "oauth", "deserialization",
        "file_upload",
        "nacos_exposure", "solr_exposure", "confluence_exposure",
    ]
    for engine_name in global_engines:
        # 修复：info_leak 扫描路径数提升至 150
        if engine_name == "info_leak":
            await self.task_queue.add_task({
                "type": "global_scan",
                "engine": engine_name,
                "target": self.target,
                "priority": 6,
                "max_paths": 150  # 淇锛氬鍔犺矾寰勬暟
            }, priority=6)
        else:
            await self.task_queue.add_task({
                "type": "global_scan",
                "engine": engine_name,
                "target": self.target,
                "priority": 6
            }, priority=6)
        tasks_added += 1
    logger.info(f"   📋 总任务数: {tasks_added}")
async def _gen_cve_task(self) -> Optional[Dict]:
    """Z1.2（=D2.4）：读 CVE 索引，按指纹组件生成高危 CVE 专项任务。

    数据腿闭环：cve_index（Z1.1）→ phases_taskgen 读索引 → nuclei 专项扫描（cve_scan）。
    只取 critical/high，且限定条数（<=12），避免把整个 CVE 库拉进扫描。
    索引缺失/不可用时静默跳过（不误报、不阻断主流程）。
    """
    tech_stack = self._recon_brief.get("tech_stack", []) or []
    if not tech_stack:
        return None
    try:
        from vulnclaw.core.data.cve_index_builder import CVEIndex, build_index
        idx = CVEIndex()
        if not idx.load():
            # A8：索引缺失（全新克隆 / 未构建 / 被 .gitignore 忽略未入库）→ 离线从内置
            # cves.json 构建一次，闭合「指纹→CVE→nuclei -id」链路，避免静默跳过导致
            # CVE 专项精扫对所有人永久失效。
            logger.info("[CVE任务] CVE 索引未构建，尝试离线构建（内置 cves.json）")
            try:
                n = build_index()
                if not n or n <= 0:
                    logger.debug("[CVE任务] CVE 索引离线构建无数据，跳过")
                    return None
                idx = CVEIndex()
                if not idx.load():
                    logger.debug("[CVE任务] CVE 索引构建后仍无法加载，跳过")
                    return None
                logger.info(f"[CVE任务] CVE 索引离线构建成功（{n} 条）")
            except Exception as be:
                logger.debug(f"[CVE任务] CVE 索引离线构建失败，跳过: {be}")
                return None
    except Exception as exc:
        logger.debug(f"[CVE任务] CVE 索引加载失败，跳过: {exc}")
        return None

    # A8.4：情报源增量更新（NVD/ExploitDB/GitHub），仅当配置了相应环境变量才联网。
    try:
        import os as _os
        if (_os.environ.get("NVD_API_KEY") or _os.environ.get("EXPLOITDB_PATH")
                or _os.environ.get("GITHUB_TOKEN")):
            from vulnclaw.core.data.cve_index_builder import sync_intel_sources
            added = await sync_intel_sources()
            if added:
                logger.info(f"[CVE任务] 情报源增量更新索引 +{added} 条")
                idx = CVEIndex()
                idx.load()
    except Exception as ie:  # noqa: BLE001
        logger.debug(f"[CVE任务] 情报源同步失败（忽略）: {ie}")

    seen_ids: set = set()
    hits: List = []
    for comp in tech_stack[:8]:
        if not comp or not str(comp).strip():
            continue
        for candidate in (str(comp).strip(),):
            for rec in idx.search(candidate, min_severity="high", limit=8):
                if rec.cve_id in seen_ids:
                    continue
                seen_ids.add(rec.cve_id)
                hits.append(rec)
                if len(hits) >= 12:
                    break
            if len(hits) >= 12:
                break
        # 复合指纹（如 "Apache/2.4.41 (Ubuntu)"）再按 token 放宽匹配
        for tok in re.split(r"[^a-zA-Z0-9.\-]+", str(comp)):
            tok = tok.strip().lower()
            if len(tok) < 3 or tok in ("http", "https", "version", "server"):
                continue
            for rec in idx.search(tok, min_severity="high", limit=5):
                if rec.cve_id in seen_ids:
                    continue
                seen_ids.add(rec.cve_id)
                hits.append(rec)
                if len(hits) >= 12:
                    break
            if len(hits) >= 12:
                break
        if len(hits) >= 12:
            break

    if not hits:
        return None
    cve_ids = [r.cve_id for r in hits]
    meta = [
        {"cve_id": r.cve_id, "severity": r.severity, "template": r.file_path}
        for r in hits
    ]
    logger.info(
        f"🎯 [CVE任务] 指纹→CVE 命中 {len(cve_ids)} 个高危 CVE（{', '.join(cve_ids[:6])}...），生成 nuclei 专项任务"
    )
    return {
        "type": "cve_scan",
        "target": self.target,
        "cve_ids": cve_ids,
        "cve_meta": meta,
        "priority": 10,
        "created_at": time.time(),
    }
__all__ = ['_scan_idor', '_check_default_creds', '_generate_tasks', '_gen_cve_task']
