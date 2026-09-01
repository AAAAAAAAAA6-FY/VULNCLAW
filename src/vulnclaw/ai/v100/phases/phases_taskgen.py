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
        for param in all_params[:10]:
            test_url = self.target
            if '?' not in test_url:
                test_url += f"?{param}=1"
            else:
                test_url += f"&{param}=1"
            try:
                results = await scan_idor(test_url, session_mgr, roles)
                idor_findings.extend(results)
            except Exception:
                pass
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
    all_params = all_params[:30]
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
        "graphql_introspection": 6 if "/graphql" in str(self._recon_brief.get('apis', [])) else 4,
        "prometheus_metrics": 6 if ("spring" in tech_lower or "go" in tech_lower) else 4,
        "rate_limit": 5,
        "verb_tampering": 5
    }
    # P4-1: 情报驱动 —— 按 Shodan/Censys 标记的服务类型与开放端口提升对应引擎优先级
    intel = self._recon_brief.get("intel") or {}
    intel_hints = [str(h).lower() for h in (intel.get("service_hints") or [])]
    intel_ports = set(intel.get("ports") or [])
    intel_vuln_count = len(intel.get("vulns") or [])
    if intel_hints or intel_ports:
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
    for param in all_params:
        skip, reason = self.local_filter.should_skip(self.target, param, "", 0)
        if skip:
            logger.debug(f"   鈴笍 璺宠繃鍙傛暟 {param}: {reason}")
            continue
        is_business = any(kw in param.lower() for kw in business_param_keywords)
        engine_scores = []
        for engine_name, base_priority in engine_priority.items():
            priority = base_priority
            if is_business and engine_name == "business_logic":
                priority = 10
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
    for api in self._recon_brief.get("apis", [])[:10]:
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
    for js_api in self._recon_brief.get("js_endpoints", [])[:10]:
        if isinstance(js_api, str) and js_api.startswith('/'):
            full_api = self.target.rstrip('/') + js_api
            if _is_static_resource_url(full_api):
                static_skipped += 1
                continue
            task_data = {
                "type": "api_check",
                "engine": "sqli" if 'api' in js_api else "xss",
                "target": full_api,
                "param": "id",
                "priority": 7,
                "payload_limit": 8,
                "created_at": time.time()
            }
            await self.task_queue.add_task(task_data, 7)
            tasks_added += 1
    if static_skipped:
        logger.info(f"   🗑️ [静态资源过滤] 源头丢弃 {static_skipped} 个静态资源 URL")
    global_engines = [
        "api_version_diff", "request_smuggling", "http2_ws",
        "cache_poison", "info_leak", "mobile_api",
        "websocket_security", "api_version",
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
        from vulnclaw.core.data.cve_index_builder import CVEIndex
        idx = CVEIndex()
        if not idx.load():
            logger.debug("[CVE任务] CVE 索引未构建，跳过（可先跑 update_templates.py --sync-cve-index）")
            return None
    except Exception as exc:
        logger.debug(f"[CVE任务] CVE 索引加载失败，跳过: {exc}")
        return None

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
