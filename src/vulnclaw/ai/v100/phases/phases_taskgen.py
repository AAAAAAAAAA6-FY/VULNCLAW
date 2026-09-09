# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Implementation functions for the v100 taskgen phase."""
import os
import re
import time

from vulnclaw.ai.v100.batch_processor import BatchProcessor
from vulnclaw.core.logger import logger
from vulnclaw.core.auth.session_manager import get_session_manager
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


def _signer_augment(url: str):
    """K.3：SignerPool 命中则返回带合法签名的 URL，否则 None（绝不抛错）。"""
    try:
        from vulnclaw.ai.js_retriever.signer_pool import signer_pool
        return signer_pool.augment_url(url)
    except Exception:  # noqa: BLE001
        return None


def _is_credential_param(param: str) -> bool:
    """判断参数名是否属于凭据/密钥类，应跳过通用注入模糊。"""
    if not param:
        return False
    p = param.lower()
    return any(hint in p for hint in CREDENTIAL_PARAM_HINTS)


async def _scan_idor(self):
    # ---- B 方案差分线（2026-09-08）：双会话差分水平越权，单身份也自动配对匿名身份 ----
    await self._run_idor_dual_session_line()
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
def _collect_idor_candidates(brief, target: str = ""):
    """收集带 ID 类参数的候选端点 (url, param, value)。只使用真实观测端点（证据优先，宁缺毋滥）。"""
    from vulnclaw.engines.auth_engines import IDOREngine

    _id = IDOREngine()
    seen = set()
    out = []
    cands = [u for u in (brief or {}).get("crawled_endpoints", []) or []
             if isinstance(u, str) and u]
    if target and str(target).startswith(("http://", "https://")):
        cands.insert(0, str(target))
    for u in cands:
        for param, value in _id._extract_id_params(u):
            key = (u, param)
            if key in seen:
                continue
            seen.add(key)
            out.append((u, param, value))
    return out


async def _run_idor_dual_session_line(self) -> int:
    """B 方案差分线：双会话差分水平越权，单身份也自动配对匿名身份。返回产出 finding 数。"""
    if not getattr(settings, "idor_dual_session", True):
        return 0
    try:
        from urllib.parse import urlparse as _up

        from vulnclaw.core.auth.session_manager import get_session_manager as _gsm
        from vulnclaw.core.biz_oracle import IdentityMatrix
        from vulnclaw.engines.biz_oracle_engines import DualSessionOracleEngine
    except Exception as e:  # noqa: BLE001 - 模块缺失时不阻断 extras
        logger.warning(f"⚠️ [IDOR-双会话] 差分线初始化失败: {e}")
        return 0
    try:
        session_mgr = _gsm()
        im = IdentityMatrix(session_mgr)
        domain = _up(self.target or "").netloc or ""
        if await im.ensure_second_identity(domain) is None:
            logger.info("ℹ️ [IDOR-双会话] 无可用第二身份，跳过差分线（fail-closed，不降级猜测）")
            return 0
        oracle = DualSessionOracleEngine()
        cands = _collect_idor_candidates(self._recon_brief or {}, self.target or "")
        if not cands:
            logger.info("ℹ️ [IDOR-双会话] 无带 ID 参数的候选端点，跳过")
            return 0
        budget = int(getattr(settings, "idor_max_probes", 40) or 40)
        made = 0
        for ep, param, val in cands[:budget]:
            try:
                f = await oracle.diagnose(ep, param, val, im, session_mgr)
            except Exception:  # noqa: BLE001 - 单候选失败不阻断
                logger.debug("suppressed exception (core audit)")
                continue
            if f:
                self._add_finding(f)
                self._idor_findings = getattr(self, "_idor_findings", 0) + 1
                made += 1
            if made >= budget:
                break
        logger.info(f"🔑 [IDOR-双会话] 差分线完成：{len(cands)} 候选 → {made} 发现")
        return made
    except Exception as e:  # noqa: BLE001
        logger.warning(f"⚠️ [IDOR-双会话] 差分线异常: {e}")
        return 0


async def _run_nuclei_community_line(self) -> int:
    """C 方案社区线：Nuclei 社区模板通用检测（主域根 + 端点预算）。返回产出 finding 数。"""
    if not getattr(settings, "nuclei_community_line", True):
        logger.info("ℹ️ [Nuclei社区线] 已关闭（NUCLEI_COMMUNITY_LINE=false）")
        return 0
    try:
        from vulnclaw.modules.vuln_scanner import run_nuclei_community_line, verify_nuclei_with_ai_async
        severity = str(getattr(settings, "nuclei_line_severity", "critical,high") or "critical,high")
        timeout = int(getattr(settings, "nuclei_line_timeout", 180) or 180)
        budget = int(getattr(settings, "nuclei_line_endpoint_budget", 10) or 0)
        min_tpl = int(getattr(settings, "nuclei_line_min_templates", 300) or 300)
        logger.info("🧬 [Nuclei社区线] 通用检测外置：模板扫描启动（社区检测线）")
        results = await run_nuclei_community_line(
            self.target, self._recon_brief or {},
            severity=severity, timeout=timeout, budget=budget, min_templates=min_tpl,
        )
        if not results:
            logger.info("ℹ️ [Nuclei社区线] 无候选产出（模板健康失败或零命中，fail-closed）")
            return 0
        verified = await verify_nuclei_with_ai_async(results, self.target)
        made = 0
        for item in verified:
            if item.get("ai_verdict") != "真实漏洞":
                continue
            ftype = f"Nuclei社区: {item.get('template') or item.get('info') or '未知'}"
            if any(f.get('type') == ftype and f.get('url') == item.get('url', self.target)
                   for f in getattr(self, "findings", [])):
                continue
            self._add_finding({
                "type": ftype,
                "severity": item.get("severity", "High"),
                "evidence": str(item.get("matched") or "")[:300],
                "url": item.get("url", self.target),
                "parameter": "",
                "source": "nuclei_community",
                "template_id": item.get("template", ""),
                "line_target": item.get("line_target", self.target),
                "confidence": item.get("confidence", "中"),
                "ai_reason": item.get("ai_reason", ""),
            })
            self._nuclei_findings = getattr(self, "_nuclei_findings", 0) + 1
            made += 1
        logger.info(f"🧬 [Nuclei社区线] 完成：{len(verified)} 候选 → {made} 条真实漏洞入报告")
        return made
    except Exception as e:  # noqa: BLE001 - 社区线异常不阻断 extras
        logger.warning(f"⚠️ [Nuclei社区线] 异常（fail-closed 跳过）: {e}")
        return 0


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
    # 任务膨胀控制（2026-09-06 第1点）：生成侧总上限，超出截断端点级/参数挖掘尾部，
    # 保留参数级/api/js/global 核心与 B 段前部高价值端点。0=不限制（兼容旧行为）。
    _total_cap = int(getattr(settings, "max_total_tasks", 0) or 0)
    # 分段预算（2026-09-07 大站修复）：端点级(B)独立额度，不被参数级/参数挖掘挤爆。
    # 大站爬出的真实端点必须获得检测机会：B 额度 = max(全局上限, 端点量×单端点引擎数×2)，
    # 防爆上限 2000（仍受 max_scan_time 与任务消费自然收敛）。参数级/参数挖掘保持全局口径。
    _crawled_n = len(self._recon_brief.get("crawled_endpoints", []) or [])
    # 端点级每端点≈1 个 bundle 任务：额度跟随端点量×2 余量，封顶 5000（极端大站）。
    # 防爆由队列水位与 scan 阶段预算自然收敛兜底，不再虚高按 12 倍估算。
    _cap_b = (max(_total_cap, min(5000, max(200, _crawled_n * 2)))
              if (_total_cap and _crawled_n) else 0)
    if _total_cap:
        logger.info(f"   [任务上限] max_total_tasks={_total_cap}（端点级独立额度={_cap_b or '不限'}，端点候选={_crawled_n}）")
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
            )
            from vulnclaw.core_modules.asset_profile import (
                generic_asset_unchanged as generic_asset_unchanged,
            )
            from vulnclaw.core_modules.asset_profile import (
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
        "verb_tampering": 5,
        # 深藏/复杂/解析分歧三引擎（参数级）
        "deep_chimera": 7,
        "state_chain": 6,
        "parsing_shadow": 6,
    }
    # SP27: 指令重点(focus)提升对应引擎优先级（--instruction 直写账号密码时可顺带指定重点）
    _ins_ctx = getattr(settings, "instruction_context", None)
    if _ins_ctx:
        if _ins_ctx.focus:
            _fc = " ".join(str(x).lower() for x in _ins_ctx.focus)
            _focus_map = {
                "sql": "sqli", "注入": "sqli", "xss": "xss", "跨站": "xss",
                "越权": "idor", "bolt": "idor", "auth": "auth_enumeration",
                "登录": "auth_enumeration", "session": "session", "会话": "session",
                "csrf": "csrf", "上传": "file_upload", "upload": "file_upload",
                "ssti": "ssti", "ssrf": "ssrf", "文件": "lfi", "lfi": "lfi",
                "xml": "xxe", "api": "api_security", "graphql": "graphql",
                "cors": "cors", "重定向": "open_redirect", "redirect": "open_redirect",
            }
            for _kw, _eng in _focus_map.items():
                if _kw in _fc and _eng in engine_priority:
                    engine_priority[_eng] = min(10, engine_priority[_eng] + 4)
                    logger.info(f"   [SP27] 指令重点命中「{_kw}」→ {_eng} 优先级提高至 {engine_priority[_eng]}")
        if _ins_ctx.exclude:
            logger.info(f"   [SP27] 指令排除项（消费端过滤）: {_ins_ctx.exclude}")
        if _ins_ctx.has_credentials and len(_ins_ctx.accounts) > 1:
            logger.info(f"   [SP27] 多角色凭据就绪（IDOR/越权引擎将使用多角色会话）: {_ins_ctx.masked_summary}")
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
    # 现改为 top-3 核心引擎 + 按参数序号轮换 N 个次优引擎（rotation），
    # N 由「剩余引擎数 / 参数数」动态推导（见下方轮换逻辑），
    # 使参数量少的站点也能在本次扫描内覆盖到尾部引擎。
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
        # P0：轮换步长动态化——每参数额外带 k 个次优引擎，
        # k = ceil(剩余引擎数 / 参数数)，上限 max_extra_engines_per_param（默认 3）。
        # 旧实现固定 +1：参数级引擎池已达 59 个，需要 56 个参数才轮得完，
        # 参数量少的站点尾部引擎永远拿不到执行机会。
        remaining_engines = engine_scores[3:]
        selected_engines = [engine_name for engine_name, _ in top_engines]
        if remaining_engines:
            _remain_n = len(remaining_engines)
            _params_n = max(1, len(all_params))
            _max_extra = int(getattr(settings, "max_extra_engines_per_param", 3) or 3)
            _k = max(1, min(_max_extra, -(-_remain_n // _params_n)))  # ceil 除法
            for _i in range(_k):
                _eng = remaining_engines[(rotation_offset + _i) % _remain_n][0]
                if _eng not in selected_engines:
                    selected_engines.append(_eng)
            rotation_offset += _k
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
            _signed = _signer_augment(full_api)
            if _signed:
                task_data["signed_url"] = _signed
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
        if '/api' in _jl or '/graphql' in _jl or re.search(r'/sqli|/sql|/inject', _jl):
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
            _signed = _signer_augment(full_api.split('?')[0])
            if _signed:
                task_data["signed_url"] = _signed
            await self.task_queue.add_task(task_data, 7)
            tasks_added += 1
    # B: 同源链接爬虫发现的端点 → 喂进引擎循环（target=端点URL，param=端点自带参数）
    _crawled = self._recon_brief.get("crawled_endpoints", []) or []
    if not _crawled:
        # 检出率排查（2026-09-06）：recon 同源爬虫在真扫环境曾静默返回空（共享会话状态
        # 干扰，独立会话正常），导致端点级 bundle 整段缺失（/nosql /deser 漏检）。
        # 防御：此处用独立裸会话补爬一次，绕开 recon 侧会话状态；失败不阻断任务生成。
        logger.warning("   [TaskGen] crawled_endpoints 为空——使用独立裸会话补爬一次")
        try:
            from urllib.parse import urlparse as _up, parse_qs as _pq
            from vulnclaw.modules.recon import crawl_same_origin as _cso
            import aiohttp as _aio
            async with _aio.ClientSession() as _bare:
                _c2 = await _cso(
                    self.target, session=_bare, max_depth=2, max_urls=80, render=False,
                    crawl_hash_routing=settings.crawl_hash_routing,
                    crawl_websocket=settings.crawl_websocket,
                    ws_endpoints=set(),
                )
            if _c2:
                _crawled = [{"url": u, "params": sorted(p)} for u, p in _c2.items()]
                self._recon_brief["crawled_endpoints"] = _crawled  # 回填 brief 供 extras 等消费
                logger.info(f"   [TaskGen] 裸会话补爬成功: {len(_crawled)} 个端点已入端点级任务流")
        except Exception as _ce:  # noqa: BLE001
            logger.warning(f"   [TaskGen] 裸会话补爬失败（继续无端点级任务）: {_ce}")
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
        if not _ep_params:
            # 无参端点覆盖（线1.3）：不造默认 "id" 参数，按路径特征映射目标级引擎任务
            _el0 = _etarget.lower()
            _mapped_engine = None
            if re.search(r'/jwt', _el0):
                _mapped_engine = "jwt"
            elif re.search(r'/idor|/profile|/user|/account', _el0):
                _mapped_engine = "idor"
            elif re.search(r'/admin|/manage|/console', _el0):
                _mapped_engine = "weak_credential"
            elif re.search(r'/ssrf|/fetch|/proxy', _el0):
                # SSRF 型无参端点覆盖：侦察未抓到 url 参数时，补发 url 参数探测任务，
                # 由 SSRF 引擎 _is_ssrf_param 对 url 放行（防 /ssrf 整轮零任务）
                await self.task_queue.add_task({
                    "type": "engine_bundle",
                    "engines": ["ssrf"],
                    "target": _etarget,
                    "param": "url",
                    "priority": engine_priority.get("ssrf", 7),
                    "payload_limit": 10,
                    "created_at": time.time(),
                    "source": "crawl_noparam_ssrf",
                }, engine_priority.get("ssrf", 7))
                tasks_added += 1
            if _mapped_engine:
                await self.task_queue.add_task({
                    "type": "global_scan",
                    "engine": _mapped_engine,
                    "target": _etarget,
                    "priority": engine_priority.get(_mapped_engine, 8),
                    "payload_limit": 10,
                    "created_at": time.time(),
                    "source": "crawl_noparam",
                }, engine_priority.get(_mapped_engine, 8))
                tasks_added += 1
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
        if re.search(r'/nosql|/mongo', _el):
            _hint.append("nosql")
        if re.search(r'/deser|/unserial', _el):
            _hint.append("deserialization")
        if re.search(r'/ssrf|/fetch|/proxy|/redirect|/download|/load|/callback', _el):
            _hint.append("ssrf")
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
            if _cap_b and tasks_added >= _cap_b:
                logger.warning(f"   [任务上限] 端点级任务截断（额度 {_cap_b}，保留前序端点）")
                break
    # C: param_mining（B 侧 recon.py 写入的 D3.5 参数挖掘结果）-> 参数池补测
    if getattr(settings, "scan_param_mining", True):
        _pmined = self._recon_brief.get("param_mining", []) or []
        _pm_seen = set()
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
            _pm_seen_key = (_pm_target, _pm_param)
            if _pm_seen_key in _pm_seen:
                continue  # SP15.2 消费侧去重：同端点同参数只补测一次，防重复检测费钱
            _pm_seen.add(_pm_seen_key)
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
            if _total_cap and tasks_added >= _total_cap:
                logger.warning(f"   [任务上限] 已达 max_total_tasks={_total_cap}，参数挖掘任务截断")
                break
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
        "open_redirect", "cors", "idor", "jwt", "oauth",  # deserialization 改由端点级 B 段 hint 承接（避免 global 空 param 噪音任务）
        "file_upload",
        "nacos_exposure", "solr_exposure", "confluence_exposure",
        "deep_chimera", "parsing_shadow", "state_chain", "llm_injection",
    ]
    # P0-3：可达性自检——以 scanner 实际加载的引擎集（_ENGINE_MAP，按 name 索引）为权威，
    # 未进入任一调度池（engine_priority 参数级 / global_engines 目标级）者自动兜底入
    # 目标级池，杜绝"注册但不跑"。两个调度池 key 均为引擎 name，语义一致。
    try:
        from vulnclaw.core.scanner import get_all_engines
        _loaded = get_all_engines()  # 实际加载的引擎实例列表
        _loaded_names = {getattr(e, "name", None) or type(e).__name__ for e in _loaded}
        _param_set = set(engine_priority.keys())
        _global_set = set(global_engines)
        # 已知"有意不独立调度"的引擎（由其它引擎内部承接能力），不算漏调度，
        # 排除在兜底之外，避免重复执行。例：graphql_introspection 由 graphql 引擎端点级内省承接。
        _known_unscheduled = {"graphql_introspection"}
        _unreached = [n for n in _loaded_names
                      if n not in _param_set and n not in _global_set
                      and n not in _known_unscheduled]
        if _unreached:
            logger.warning(
                f"[engines] {len(_unreached)} 个引擎已注册但未入任何调度池，"
                f"自动兜底入目标级池以保证可达: {sorted(_unreached)}"
            )
            global_engines = list(global_engines) + _unreached
    except Exception as _re_exc:  # noqa: BLE001 - 引擎集不可用时跳过自检，不影响调度
        logger.debug(f"[engines] 可达性自检跳过（引擎集不可用）: {_re_exc}")
    for engine_name in global_engines:
        # 修复：info_leak 扫描路径数提升至 150
        if engine_name == "info_leak":
            await self.task_queue.add_task({
                "type": "global_scan",
                "engine": engine_name,
                "target": self.target,
                "priority": 6,
                "max_paths": 150  # 修复：增加路径数
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
    # 子域资产级任务（2026-09-07）：recon 发现的子域进入引擎任务池，弥合大站"子域零消费"漏洞。
    # 每个子域派发轻量全局引擎子集（scan 型、根路径探测）；数量按 max_subdomain_targets 分摊预算，
    # 并遵守 max_total_tasks 总上限截断（与端点级/参数挖掘段口径一致）。
    if getattr(settings, "enable_subdomain_taskgen", True):
        # 优先消费存活资产（recon 存活探测结果），空则回退全量子域，避免打死域发探测
        _subdomains = (
            self._recon_brief.get("alive_assets")
            or self._recon_brief.get("subdomains")
            or []
        )
        if _subdomains:
            try:
                from urllib.parse import urlparse as _sup
                _main_host = (_sup(self.target).netloc or "").lower()
            except Exception:  # noqa: BLE001
                _main_host = ""
            _sub_engines = [
                "security_headers", "tls_security", "dns_security",
                "cors", "open_redirect", "api_version", "info_leak",
                "source_code_leak", "backup_file_leak", "admin_console_exposure",
                "swagger_api_doc", "cloud_container_exposure",
            ]
            _sub_targets = []
            for _sd in _subdomains:
                # 2026-09-08: alive_assets 是 dict 列表（{url,status,...}），
                # 子域收集是字符串列表；统一提取 url/host 再归一，避免 str(dict) 畸形 URL
                if isinstance(_sd, dict):
                    _h = str(_sd.get("url") or _sd.get("host") or "").strip()
                else:
                    _h = str(_sd).strip()
                _h = _h.rstrip('/')
                if '://' in _h:
                    _h = _sup(_h).netloc or _h
                if not _h:
                    continue
                _hl = _h.lower()
                # 跳过主目标自身（www 归一比较），避免对主域重复全扫
                if _main_host and (
                    _hl == _main_host
                    or _hl == (_main_host[4:] if _main_host.startswith("www.") else _main_host)
                    or _main_host == (_hl[4:] if _hl.startswith("www.") else _hl)
                ):
                    continue
                _sub_targets.append(_h)
            _sub_targets = list(dict.fromkeys(_sub_targets))  # 保序去重
            _cap_subs = int(getattr(settings, "max_subdomain_targets", 10) or 0)
            if _cap_subs and len(_sub_targets) > _cap_subs:
                logger.info(
                    f"   [子域任务] 发现 {len(_sub_targets)} 个子域，按 max_subdomain_targets={_cap_subs} "
                    "取前部分（其余留待增量轮/后续补齐）"
                )
                _sub_targets = _sub_targets[:_cap_subs]
            _scheme = "https" if str(self.target).lower().startswith("https") else "http"
            for _st in _sub_targets:
                _sub_url = f"{_scheme}://{_st}/"
                for _eng in _sub_engines:
                    if _total_cap and tasks_added >= _total_cap:
                        logger.warning(f"   [任务上限] 已达 max_total_tasks={_total_cap}，子域任务截断")
                        break
                    _sd_task = {
                        "type": "global_scan",
                        "engine": _eng,
                        "target": _sub_url,
                        "priority": 5,
                        "source": "subdomain",
                    }
                    if _eng == "info_leak":
                        _sd_task["max_paths"] = 40  # 子域目录爆破预算收敛（主目标 150）
                    await self.task_queue.add_task(_sd_task, priority=5)
                    tasks_added += 1
                if _total_cap and tasks_added >= _total_cap:
                    break
            if _sub_targets:
                logger.info(
                    f"   🌐 [子域任务] {len(_sub_targets)} 个子域 × {len(_sub_engines)} 个全局引擎"
                    f" → {len(_sub_targets) * len(_sub_engines)} 个任务入队"
                )
    # S3.1c: 召回 VectorMemory 历史经验，命中高价值组合时给任务追加 memory_hint/memory_boost
    _mem_injector = getattr(self, "_inject_task_memory_hints", None)
    if _mem_injector is not None:
        await _mem_injector()
async def _gen_cve_task(self) -> dict | None:
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
    hits: list = []
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
# ==================================================================
# S3.1c: 记忆读取注入——召回 VectorMemory 相似历史经验，命中高价值组合
# （引擎 / URL 模式 / 参数）时给队列内任务追加 memory_hint / memory_boost。
# 仅在既有任务结构上追加字段，不改任何已有键；任何失败都静默跳过。
# ==================================================================
_MEMORY_ENGINE_KEYWORDS = {
    "sqli": ("sqli", "sql", "注入", "inject", "database"),
    "xss": ("xss", "跨站", "script", "reflect"),
    "lfi": ("lfi", "文件包含", "path traversal", "路径遍历"),
    "rfi": ("rfi", "远程包含", "remote include"),
    "cmdi": ("cmdi", "命令注入", "command", "rce"),
    "ssti": ("ssti", "模板注入", "template"),
    "ssrf": ("ssrf", "服务端请求伪造", "server-side"),
    "xxe": ("xxe", "xml external", "xml 外部实体"),
    "idor": ("idor", "越权", "authorization bypass", "权限绕过"),
    "jwt": ("jwt", "json web token"),
    "oauth": ("oauth",),
    "graphql": ("graphql",),
    "file_upload": ("file_upload", "upload", "上传"),
    "el_injection": ("el_injection", "ognl", "spel"),
    "nosql": ("nosql", "mongodb", "mongo"),
    "csrf": ("csrf",),
    "open_redirect": ("open_redirect", "redirect", "重定向"),
    "info_leak": ("info_leak", "信息泄露", "sourcemap", "源码泄露"),
    "nuclei": ("nuclei",),
}


def _normalize_engine_name(vuln_type: str) -> str:
    """把历史经验的 vuln_type（可能是中文/别名）归一化为引擎名，未命中返回空串。"""
    v = str(vuln_type or "").lower()
    for engine, keywords in _MEMORY_ENGINE_KEYWORDS.items():
        if any(k in v for k in keywords):
            return engine
    return ""


def _extract_url_patterns(text: str) -> list[str]:
    """从 payload/evidence 中提取 URL 路径模式（如 /admin），去重限长。"""
    out = []
    for m in re.findall(r'(/[a-zA-Z0-9_][a-zA-Z0-9_\-./]{2,})', str(text or "")):
        p = m.rstrip('/')
        if p and len(p) >= 3 and p not in out:
            out.append(p)
    return out[:8]


def _extract_param_name(payload: str, evidence: str) -> str:
    """从 payload/evidence 中提取参数名（query 形如 ?id= 或 param=xxx）。"""
    text = f"{payload or ''!s} {evidence or ''!s}"
    m = re.search(r'[?&]([a-zA-Z_][a-zA-Z0-9_]{1,32})=', text)
    if m:
        return m.group(1)
    m = re.search(r'\b(?:param|parameter)s?\s*[=:]\s*([a-zA-Z_][a-zA-Z0-9_]{1,32})', text, re.IGNORECASE)
    if m:
        return m.group(1)
    return ""


def _match_task_memory(task_data: dict, engine_hits: dict, url_hits: dict, param_hits: dict):
    """命中判定：返回 (boost, hint_text, hint_confidence)，boost<=0 表示未命中。

    优先级：URL 模式（最具体，且模式关联引擎在任务引擎池内）> 引擎 > 参数。
    """
    boost = 0.0
    hint_conf = 0.0
    hint_text = ""
    td_type = str(task_data.get("type", "") or "")
    engines: list[str] = []
    if td_type == "engine_bundle":
        engines = [str(e) for e in (task_data.get("engines") or [])]
    elif td_type in ("engine_check", "api_check", "global_scan") and task_data.get("engine"):
        engines = [str(task_data["engine"])]
    target_url = str(task_data.get("target", "") or "")
    param = str(task_data.get("param", "") or "")
    for pattern, (conf, pattern_engine) in url_hits.items():
        if pattern not in target_url:
            continue
        if pattern_engine and engines and pattern_engine not in engines:
            continue
        if conf > boost:
            boost = conf
            hint_conf = conf
            hint_text = f"历史对 {pattern} 的 {pattern_engine or '漏洞'} 命中率高"
    if boost <= 0:
        for engine in engines:
            conf = engine_hits.get(engine, 0.0)
            if conf > boost:
                boost = conf
                hint_conf = conf
                hint_text = f"历史对 {engine} 引擎命中率高"
    if boost <= 0 and param and param in param_hits:
        boost = param_hits[param]
        hint_conf = param_hits[param]
        hint_text = f"历史对参数 {param} 命中率高"
    return boost, hint_text, hint_conf


async def _inject_task_memory_hints(self):
    """S3.1c: taskgen 收尾——召回 VectorMemory 相似历史经验并注入任务字段。

    命中高价值组合（引擎/URL 模式/参数）时给队列内任务追加 memory_hint
    （如 {"hint": "历史对 /admin 的 sqli 命中率高", "confidence": 0.8}）与
    memory_boost（0-1）。查询失败 / 空库 / 开关关闭一律静默跳过，绝不抛错、
    绝不改变既有任务结构。
    """
    if not getattr(settings, "scan_memory_enabled", True):
        return
    try:
        memory = getattr(self, "memory", None)
        if memory is None:
            return
        target = str(getattr(self, "target", "") or "")
        if not target:
            return
        brief = getattr(self, "_recon_brief", None)
        tech_stack = brief.get("tech_stack", []) if isinstance(brief, dict) else []
        query = f"{target} {' '.join(str(t) for t in tech_stack[:5])}".strip()
        topk = int(getattr(settings, "memory_recall_topk", 8))
        recalled = await memory.recall(query, n_results=topk)
        if not recalled:
            return
        import json as _json

        engine_hits: dict = {}
        url_hits: dict = {}
        param_hits: dict = {}
        for rank, raw in enumerate(recalled):
            try:
                entry = _json.loads(raw) if isinstance(raw, str) else (raw or {})
            except Exception:  # noqa: BLE001,S112
                continue
            if not isinstance(entry, dict):
                continue
            conf = max(0.5, round(1.0 - 0.1 * rank, 2))
            vt = str(entry.get("vuln_type", "") or "")
            engine = _normalize_engine_name(vt)
            if engine:
                engine_hits[engine] = max(engine_hits.get(engine, 0.0), conf)
            payload = str(entry.get("payload", "") or "")
            evidence = str(entry.get("evidence", "") or "")
            for pattern in _extract_url_patterns(payload + " " + evidence):
                if pattern not in url_hits or conf > url_hits[pattern][0]:
                    url_hits[pattern] = (conf, engine)
            pname = _extract_param_name(payload, evidence)
            if pname:
                param_hits[pname] = max(param_hits.get(pname, 0.0), conf)
        if not (engine_hits or url_hits or param_hits):
            return
        queue = getattr(self, "task_queue", None)
        if queue is None:
            return
        pending = getattr(queue, "_pending_tasks", None) or {}
        injected = 0
        for task in pending.values():
            td = getattr(task, "task_data", None)
            if not isinstance(td, dict):
                continue
            boost, hint_text, hint_conf = _match_task_memory(td, engine_hits, url_hits, param_hits)
            if boost <= 0:
                continue
            td["memory_hint"] = {"hint": hint_text, "confidence": round(hint_conf, 2)}
            td["memory_boost"] = round(min(1.0, max(0.0, boost)), 2)
            injected += 1
        if injected:
            logger.info(f"   [TaskMem] 历史经验注入 {injected} 个任务（memory_hint/memory_boost）")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[TaskMem] 记忆召回/注入失败（不影响任务生成）: {exc}")


__all__ = ['_check_default_creds', '_gen_cve_task', '_generate_tasks', '_collect_idor_candidates', '_inject_task_memory_hints', '_run_idor_dual_session_line', '_run_nuclei_community_line', '_scan_idor']

