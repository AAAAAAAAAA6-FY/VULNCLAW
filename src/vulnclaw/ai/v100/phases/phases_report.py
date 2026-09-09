# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Implementation functions for the v100 report phase."""
import time
from typing import Dict, List, Tuple
from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings

# ============================================================
# 轨道2 2.3: 漏洞类型 → CWE / OWASP Top 10 2021 / 修复建议 静态映射表
# 匹配方式为"包含匹配"，因此 key 需覆盖引擎输出的子类型（如 sqli_error）。
# 每条建议尽量可执行（能直接交给研发落地），而非泛泛而谈。
# ============================================================
VULN_TYPE_CWE_MAP: Dict[str, Tuple[str, str, List[str]]] = {
    "sqli": ("CWE-89", "A03:2021 – Injection", [
        "改用预编译语句（PreparedStatement / 参数化查询），禁止字符串拼接 SQL",
        "对输入做严格类型与白名单校验（如 id 必须为整数、排序字段限定枚举）",
        "数据库账号最小化权限，禁用堆叠查询与 FILE / 写文件权限",
        "统一错误处理，禁止把数据库原始报错回显到前端",
    ]),
    "nosql": ("CWE-943", "A03:2021 – Injection", [
        "禁止把用户输入直接拼进查询对象，使用驱动提供的参数化查询",
        "对输入类型做强校验（字符串不得被解析为对象/操作符）",
        "禁用 $where / $eval / mapReduce 等可执行表达式的能力",
    ]),
    "xss": ("CWE-79", "A03:2021 – Injection", [
        "输出编码：按上下文使用 HTML / 属性 / JS / URL 编码器（勿只过滤关键字）",
        "启用 CSP（Content-Security-Policy）并禁用 unsafe-inline",
        "敏感 Cookie 设置 HttpOnly + Secure + SameSite",
        "富文本场景使用白名单消毒库（如 DOMPurify 服务端版）",
    ]),
    "cmdi": ("CWE-78", "A03:2021 – Injection", [
        "移除命令拼接，改用语言原生 API 或受控的库函数",
        "必须使用子进程数组传参（禁止 shell=True / 字符串命令）",
        "参数走白名单校验，禁止 ; | & $ ` 换行等元字符",
        "执行进程使用低权限账号并置于沙箱/容器中",
    ]),
    "rce": ("CWE-94", "A03:2021 – Injection", [
        "禁止将用户输入传入 eval / exec / 反序列化 / 模板求值等危险函数",
        "升级存在已知 RCE 的组件到官方修复版本",
        "启用最小权限运行与出站网络限制，降低利用后影响",
    ]),
    "lfi": ("CWE-22", "A01:2021 – Broken Access Control", [
        "禁止用用户输入直接拼接文件路径，改为 ID → 路径的映射表",
        "对最终路径做 realpath 规范化并校验必须在根目录内（前缀白名单）",
        "过滤 ../ 及其各种编码变体（%2e%2e%2f、..%2f、..%5c 等）",
        "关闭目录列表，运行账号仅授予必要文件读权限",
    ]),
    "rfi": ("CWE-98", "A03:2021 – Injection", [
        "禁用 allow_url_include / 远程文件包含相关配置",
        "包含路径使用白名单常量，禁止用户可控",
        "限制服务端出网（防远程拉取恶意文件）",
    ]),
    "ssrf": ("CWE-918", "A10:2021 – SSRF", [
        "URL 只允许 http/https，禁用 file:// gopher:// dict:// 等协议",
        "目标地址走白名单（域名/IP 双校验，解析后校验 IP 防 DNS rebinding）",
        "禁止访问 169.254.169.254 等元数据与内网私有网段",
        "统一出网代理，禁止跟随重定向到内网",
    ]),
    "xxe": ("CWE-611", "A05:2021 – Security Misconfiguration", [
        "关闭 XML 外部实体解析（setFeature 禁用 DTD / 外部实体）",
        "改用 JSON 等更安全的数据格式",
        "使用修复版本 XML 解析库并限制出网",
    ]),
    "ssti": ("CWE-1336", "A03:2021 – Injection", [
        "禁止用用户输入拼接模板，改用模板变量传参",
        "使用沙箱环境渲染，移除危险对象与内建函数访问",
        "对模板语法字符做严格转义",
    ]),
    "el_injection": ("CWE-917", "A03:2021 – Injection", [
        "禁止把用户输入作为表达式求值（SpEL / OGNL / EL）",
        "表达式解析使用 SimpleEvaluationContext 等受限上下文",
        "对 ${} #{} 等特殊结构做输入校验",
    ]),
    "deserialization": ("CWE-502", "A08:2021 – Software and Data Integrity Failures", [
        "禁止反序列化不可信数据，改用 JSON 等数据格式",
        "必须使用时启用类白名单校验（JEP 290 filter）",
        "对序列化数据做完整性签名，密钥妥善保管",
    ]),
    "idor": ("CWE-639", "A01:2021 – Broken Access Control", [
        "每个对象访问都做归属校验（当前用户是否有权操作该资源）",
        "资源 ID 使用不可枚举的随机值（UUID）",
        "统一在服务端鉴权，禁止依赖前端隐藏字段",
    ]),
    "jwt": ("CWE-347", "A02:2021 – Cryptographic Failures", [
        "服务端强制校验签名算法（固定 HS256/RS256，禁止 alg=none）",
        "使用高强度密钥并定期轮换，禁止硬编码密钥",
        "校验 exp / nbf / iss / aud 声明，登出时使用黑名单",
    ]),
    "oauth": ("CWE-346", "A01:2021 – Broken Access Control", [
        "redirect_uri 使用精确匹配白名单（禁止前缀/通配匹配）",
        "强制校验 state 参数并绑定一次性会话",
        "授权码一次性使用并短时效，token 绑定客户端",
    ]),
    "graphql": ("CWE-200", "A05:2021 – Security Misconfiguration", [
        "生产环境关闭内省（Introspection）与 GraphiQL",
        "限制查询深度与复杂度，启用请求限流",
        "在 GraphQL 层复用与 REST 一致的鉴权与字段级权限",
    ]),
    "file_upload": ("CWE-434", "A04:2021 – Insecure Design", [
        "校验文件类型（魔数 + 扩展名白名单），禁止仅依赖 Content-Type",
        "存储在非 Web 根目录并随机重命名，禁止保留用户可控路径",
        "存储目录禁止执行权限，图片走二次渲染/压缩",
    ]),
    "session": ("CWE-384", "A02:2021 – Cryptographic Failures", [
        "登录成功后轮换 Session ID（防会话固定）",
        "登出/改密时服务端立即失效会话",
        "Cookie 设置 HttpOnly + Secure + SameSite，设置合理超时",
    ]),
    "cors": ("CWE-942", "A05:2021 – Security Misconfiguration", [
        "Access-Control-Allow-Origin 使用精确白名单，禁止反射任意 Origin",
        "如无需凭证不要同时开启 Allow-Credentials: true",
        "预检请求限制方法与头部，禁止通配",
    ]),
    "csrf": ("CWE-352", "A01:2021 – Broken Access Control", [
        "为状态变更操作加入 CSRF Token 并服务端校验",
        "Cookie 设置 SameSite=Lax/Strict",
        "校验 Origin / Referer 头",
    ]),
    "open_redirect": ("CWE-601", "A01:2021 – Broken Access Control", [
        "跳转目标使用白名单或相对路径，禁止用户可控绝对 URL",
        "必须跳转外网时增加中间确认页",
    ]),
    "crlf": ("CWE-93", "A03:2021 – Injection", [
        "过滤或编码输入中的 CR/LF（%0d%0a）后再写入响应头",
        "使用框架提供的响应头设置 API，避免字符串拼接",
    ]),
    "host_header": ("CWE-644", "A05:2021 – Security Misconfiguration", [
        "服务端校验 Host 头白名单，禁止未知名义访问",
        "生成绝对链接时使用配置的规范域名，而非请求 Host",
        "缓存键不要直接使用 Host 头",
    ]),
    "cache_poison": ("CWE-444", "A05:2021 – Security Misconfiguration", [
        "明确声明缓存键，避免未键控输入（Header/Cookie）影响缓存",
        "正确配置 Vary，对不可缓存内容进行标记",
        "CDN 与源站解析行为保持一致",
    ]),
    "smuggling": ("CWE-444", "A05:2021 – Security Misconfiguration", [
        "统一前后端对 Content-Length / Transfer-Encoding 的解析规则",
        "禁用连接复用歧义，升级中间件到修复版本",
        "在边界网关拒绝含双重长度头的请求",
    ]),
    "race_condition": ("CWE-362", "A04:2021 – Insecure Design", [
        "关键操作加锁或使用数据库事务/乐观锁（版本号）",
        "额度校验与扣减放在同一原子操作中",
        "增加幂等键，防止重复提交",
    ]),
    "business_logic": ("CWE-840", "A04:2021 – Insecure Design", [
        "所有金额/数量/权限校验必须在服务端完成",
        "补充业务规则层校验与异常行为监控告警",
        "关键流程增加二次确认与审计日志",
    ]),
    "info_leak": ("CWE-200", "A01:2021 – Broken Access Control", [
        "关闭调试模式与详细错误回显，使用统一错误页",
        "清理备份文件、源码目录、.git 与示例文件",
        "移除响应中的版本指纹与内部路径信息",
    ]),
    "security_headers": ("CWE-693", "A05:2021 – Security Misconfiguration", [
        "补齐 CSP、X-Content-Type-Options、X-Frame-Options、Referrer-Policy",
        "全站 HTTPS 并启用 HSTS（含 preload）",
        "定期用安全基线扫描校验响应头配置",
    ]),
    "ldap": ("CWE-90", "A03:2021 – Injection", [
        "使用 LDAP 转义函数处理特殊字符（* ( ) \\ NUL）",
        "采用参数化 LDAP 查询（LDAP 过滤器编码）",
        "绑定账号使用最小权限",
    ]),
    "xpath": ("CWE-643", "A03:2021 – Injection", [
        "使用参数化 XPath 表达式（预编译 + 变量绑定）",
        "对用户输入中的 XPath 元字符做转义",
    ]),
    "hpp": ("CWE-235", "A03:2021 – Injection", [
        "显式指定取参数的方式（单值），拒绝同名多参数请求",
        "在网关层规范化 query string",
    ]),
    "cred": ("CWE-1392", "A07:2021 – Identification and Authentication Failures", [
        "立即修改默认/弱口令，接入强密码策略",
        "关键系统启用 MFA 与登录失败锁定",
        "定期做弱口令与撞库检测",
    ]),
    "container_security": ("CWE-250", "A05:2021 – Security Misconfiguration", [
        "容器以非 root 运行，删除不必要的 capabilities",
        "禁止挂载宿主机敏感目录（如 /var/run/docker.sock）",
        "镜像定期扫描并升级基础镜像",
    ]),
    "websocket_security": ("CWE-346", "A01:2021 – Broken Access Control", [
        "WebSocket 握手阶段校验 Origin 与会话身份",
        "消息内容按 HTTP 同等标准做鉴权与输入校验",
        "启用 wss 并设置消息大小与频率限制",
    ]),
    "api_version": ("CWE-1059", "A04:2021 – Insecure Design", [
        "下线旧版本 API 或补齐同等鉴权与限流",
        "统一网关管理版本，避免绕过新版本安全校验",
    ]),
    "path_traversal": ("CWE-22", "A01:2021 – Broken Access Control", [
        "对最终路径做 realpath 规范化并校验必须在根目录内",
        "禁止用户输入直接拼接路径，使用映射表",
    ]),
}

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0}


def _match_cwe(vuln_type: str):
    """2.3: 按漏洞类型匹配 (CWE, OWASP, 修复建议列表)。"""
    vtype = str(vuln_type or "").lower()
    for key, val in VULN_TYPE_CWE_MAP.items():
        if key in vtype:
            return val
    return None


def _confidence_rank(vuln: Dict) -> int:
    """2.2: 置信度排序权重（100/高 > 中 > 低）。"""
    conf = vuln.get("confidence")
    if conf == 100:
        return 3
    text = str(conf or "").lower()
    if "high" in text or "高" in text:
        return 3
    if "medium" in text or "中" in text:
        return 2
    if "low" in text or "低" in text:
        return 1
    return 0


def _sigma_score(vuln: Dict) -> 'tuple[int, str]':
    """D3: 证据运营——置信度量化 + 分档。

    权重：实锤类证据 +3/+2，AI 背书 +2，多源证据 +1；降级（pending_review/Info）减分。
    分档：>=5 实锤高优先复核 / 3-4 中（需人工确认）/ <3 低（批量复核）。
    """
    s = 0
    if vuln.get('exploited') or vuln.get('exploit_verified'):
        s += 3
    for _k in ("burp_verified", "cross_confirmed", "cross_tool_confirmed",
               "oob", "oob_verified", "sqlmap_confirmed"):
        if vuln.get(_k):
            s += 2
    _verdict = str(vuln.get("ai_verdict", "")).lower()
    # 审计K1: 评分口径——"真实漏洞（本地规则确认）"是 LLM 降级/失败后的本地规则
    # 兜底，无 AI 实调背书；若按 AI 背书 +2，零调用降级场景会把规则单源证据批量
    # 抬成"高优先复核（实锤）"，淹没人工。规则兜底降为 +1，AI 多模型投票背书维持 +2。
    if "真实" in _verdict and "本地规则确认" in _verdict:
        s += 1
    elif "真实" in _verdict or "高置信" in _verdict or _verdict == "real":
        s += 2
    _sources = [k for k in ("evidence", "nuclei_result", "sqlmap_extracted", "burp_evidence", "oob_evidence")
                 if vuln.get(k)]
    if len(_sources) >= 2:
        s += 1
    if vuln.get('pending_review'):
        s -= 2
    if str(vuln.get("severity", "")).strip().capitalize() == "Info":
        s -= 3
    if s >= 5:
        return s, "★ 高优先复核（实锤）"
    if s >= 3:
        return s, "★ 中（需人工确认）"
    return s, "低（批量复核）"


def _build_evidence_chain(vuln: Dict, cap_len: int = 4000) -> List[str]:
    """D3: 多源证据合并为单一证据链（按来源前缀分段，总长截断）。"""
    parts: List[str] = []
    order = (
        ("evidence", "引擎证据"),
        ("nuclei_result", "Nuclei 原始输出"),
        ("cross_tool_evidence", "开源对照"),
        ("sqlmap_extracted", "sqlmap"),
        ("ai_verdict", "AI 裁决"),
        ("burp_evidence", "Burp"),
        ("oob_evidence", "OOB 回调"),
    )
    for key, label in order:
        raw = vuln.get(key)
        if not raw:
            continue
        text = str(raw).strip()
        if not text or text in ("无", "N/A", "n/a"):
            continue
        parts.append(f"[{label}] {text}"[:cap_len])
        if sum(len(p) for p in parts) >= cap_len:
            break
    total = 0
    out: List[str] = []
    for p in parts:
        total += len(p)
        if total > cap_len:
            p = p[: max(0, cap_len - (total - len(p)))]
            out.append(p)
            break
        out.append(p)
    return out


async def _generate_report(self) -> Dict:
    elapsed = int(time.time() - self._start_time)
    severity_count = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for v in self.findings:
        # 归一化：各引擎可能输出 "high"/"HIGH" 等大小写不一致的值
        sev = str(v.get("severity", "Low")).strip().capitalize()
        if sev in severity_count:
            severity_count[sev] += 1

    # 轨道2 2.3: 为每条 finding 注入 CWE / OWASP / 修复建议，并汇总成 Remediation 段
    remediation_index: Dict[str, Dict] = {}
    remediated = 0
    for v in self.findings:
        matched = _match_cwe(v.get("type", ""))
        if not matched:
            continue
        cwe, owasp, suggestions = matched
        v.setdefault("cwe", cwe)
        v.setdefault("owasp", owasp)
        v.setdefault("remediation", list(suggestions))
        remediated += 1
        entry = remediation_index.setdefault(
            cwe,
            {"cwe": cwe, "owasp": owasp, "vuln_types": [], "suggestions": list(suggestions)},
        )
        vtype = str(v.get("type", ""))
        if vtype and vtype not in entry["vuln_types"]:
            entry["vuln_types"].append(vtype)

    # 轨道2 2.2: 双引擎交叉确认优先展示（严重度 → 交叉确认 → 置信度 → 原始顺序）
    # 轨道2 2.2 + D3: 实锤证据最高优先 → 严重度 → 交叉确认 → sigma → 置信度 → 原始顺序
    ordered = sorted(
        enumerate(self.findings),
        key=lambda pair: (
            0 if (pair[1].get("exploited") or pair[1].get("exploit_verified")) else 1,
            -_SEVERITY_RANK.get(str(pair[1].get("severity", "Low")).strip().capitalize(), 0),
            0 if pair[1].get("cross_confirmed") else 1,
            -int(pair[1].get("sigma_score") or 0),
            -_confidence_rank(pair[1]),
            pair[0],
        ),
    )
    findings_ordered = [v for _i, v in ordered]
    # D3: 证据链合并 + sigma 分档注入（可控开关，默认开）
    sigma_stats: Dict = {}
    if getattr(settings, "report_sigma_enable", True):
        for _v in findings_ordered:
            _sc, _bucket = _sigma_score(_v)
            _v["sigma_score"] = _sc
            _v["sigma_bucket"] = _bucket
            _v.setdefault("evidence_chain", _build_evidence_chain(_v))
            sigma_stats[_bucket] = sigma_stats.get(_bucket, 0) + 1
    cross_confirmed_count = sum(1 for v in self.findings if v.get("cross_confirmed"))

    rate_stats = await self.get_rate_stats_cached()
    filter_stats = self.local_filter.get_stats()
    batch_stats = self.batch_processor.get_stats()
    queue_stats = self.task_queue.get_stats()
    balancer_stats = self.balancer.get_stats()
    model_stats = await self.get_model_stats_cached()
    report = {
        "target": self.target,
        "scan_time": __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "elapsed_seconds": elapsed,
        "total_tasks": queue_stats.get("total_added", 0),
        "processed_tasks": queue_stats.get("total_processed", 0),
        "total_engine_calls": self._total_engine_calls,
        "direct_findings": self._direct_findings,
        "burp_findings": self._burp_findings,
        "nuclei_findings": self._nuclei_findings,
        "idor_findings": self._idor_findings,
        "cred_findings": self._cred_findings,
        "business_findings": self._business_findings,
        "api_version_findings": self._api_version_findings,
        "smuggling_findings": self._smuggling_findings,
        "http2_ws_findings": self._http2_ws_findings,
        "cache_poison_findings": self._cache_poison_findings,
        "verified_findings": len(self.findings),
        "vulnerabilities": findings_ordered,
        "severity_stats": severity_count,
        "pending_review": list(getattr(self, "_pending_review", []) or []),
        # 轨道2 2.2: 双引擎交叉确认统计
        "cross_confirmed_count": cross_confirmed_count,
        # 轨道2 2.3: 按 CWE 去重的修复建议（报告 Remediation 段）
        "remediation": list(remediation_index.values()),
        "tech_stack": self._recon_brief.get("tech_stack", []),
        "subdomains": self._recon_brief.get("subdomains", []),
        "alive_assets": self._recon_brief.get("alive_assets", []),
        "nuclei_results": self._recon_brief.get("nuclei_results", []),
        "js_endpoints": self._recon_brief.get("js_endpoints", []),
        "open_ports": self._recon_brief.get("open_ports", []),
        "found_dirs": self._recon_brief.get("found_dirs", []),
        "burp_params": self._recon_brief.get("burp_params", []),
        "burp_cookies": bool(self._recon_brief.get("burp_cookies")),
        "burp_tokens": bool(self._recon_brief.get("burp_tokens")),
        "collaborator_domain": self._collaborator_domain,
        "ai_model_usage": model_stats,
        "sigma_stats": sigma_stats,
        "performance": {
            "rate_limiter": rate_stats,
            "local_filter": filter_stats,
            "batch_processor": {"enabled": True, **batch_stats},
            "smart_queue": queue_stats,
            "balancer": balancer_stats
        },
        "summary": {
            "total_findings": len(self.findings),
            "critical": severity_count.get("Critical", 0),
            "high": severity_count.get("High", 0),
            "medium": severity_count.get("Medium", 0),
            "low": severity_count.get("Low", 0),
            "info": severity_count.get("Info", 0)
        }
    }
    logger.info("=" * 70)
    logger.info("Scan completed")
    logger.info(f"   ⏱️ 耗时: {elapsed}s")
    logger.info(f"   Tasks: {queue_stats.get('total_processed', 0)}")
    logger.info(f"   Engine calls: {self._total_engine_calls}")
    logger.info(f"   Findings: {len(self.findings)}")
    logger.info(f"      Nuclei: {self._nuclei_findings}")
    logger.info(f"      IDOR: {self._idor_findings}")
    logger.info(f"      Default credentials: {self._cred_findings}")
    logger.info(f"      Burp: {self._burp_findings}")
    logger.info(f"      Business logic: {self._business_findings}")
    logger.info(f"      API version: {self._api_version_findings}")
    logger.info(f"      Request smuggling: {self._smuggling_findings}")
    logger.info(f"      HTTP2/WS: {self._http2_ws_findings}")
    logger.info(f"      Cache poisoning: {self._cache_poison_findings}")
    other = len(self.findings) - self._nuclei_findings - self._idor_findings - self._cred_findings - self._burp_findings - self._business_findings - self._api_version_findings - self._smuggling_findings - self._http2_ws_findings - self._cache_poison_findings
    logger.info(f"      Other engines: {other}")
    logger.info("   🤖 AI模型调用统计:")
    for model, count in model_stats.get('per_model', {}).items():
        failures = model_stats.get('failures', {}).get(model, 0)
        logger.info(f"      {model}: {count} 次（失败: {failures}）")
    logger.info(f"   Critical: {severity_count.get('Critical', 0)}")
    logger.info(f"   High: {severity_count.get('High', 0)}")
    # 轨道2 2.2/2.3 交付物概览
    logger.info(f"   🔁 双引擎交叉确认: {cross_confirmed_count} 条")
    logger.info(
        f"   🛠️ 修复建议覆盖: {remediated} 条 / {len(remediation_index)} 类 CWE"
    )
    logger.info("=" * 70)
    # P4-5: 高危漏洞卡片告警（未配置 webhook 时自动跳过）
    try:
        from vulnclaw.core_modules.alerting import alert_findings

        await alert_findings(self.findings, min_severity="high")
    except Exception as e:
        logger.debug(f"告警发送跳过: {e}")
    # E1.3: 攻击图 + TOP 攻击路径（构建失败不阻塞主报告，降级为跳过）
    try:
        from vulnclaw.core.attack_graph import AttackGraph

        _ag = AttackGraph().build_from_report(report)
        report["attack_graph"] = _ag.to_json()
        report["attack_paths"] = _ag.top_attack_paths(top_k=5)
        logger.info(f"   E1 攻击图: {len(report['attack_paths'])} 条 TOP 攻击路径")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"E1 攻击图构建失败，报告降级跳过: {exc}")
    # P1-6：去重收口——报告生成统一先经 deterministic_dedupe 合并同指纹 findings
    # （每指纹保留强度最高者），消除跨引擎/多路径产生的重复 finding；歧义簇单独留存
    # 供 LLM 裁决，不污染主 findings。这是去重的唯一权威入口，避免 phases_verify /
    # verification_gateway 各自去重导致口径不一致。
    try:
        from vulnclaw.core.dedupe import deterministic_dedupe
        _raw = list(report.get("vulnerabilities") or [])
        _kept, _ambiguous = deterministic_dedupe(_raw)
        report["vulnerabilities"] = _kept
        if _ambiguous:
            report["dedupe_ambiguous"] = _ambiguous
            for _ag in _ambiguous:
                for _c in _ag.get("candidates", []):
                    _c["llm_pending"] = True  # 歧义簇未接入运行时 LLM 裁决，标记留待人工
            logger.warning(
                f"   [去重] 合并 {len(_raw) - len(_kept)} 条重复；{len(_ambiguous)} 簇语义疑似"
                f"（暂未接入 LLM 裁决，全部保留备查，报告命中 dedupe_ambiguous 字段）"
            )
        else:
            logger.info(f"   [去重] 合并 {len(_raw) - len(_kept)} 条重复 finding")
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[去重] 失败，跳过（保留原始 findings）: {exc}")
    # SP10: finding 生命周期台账 + 对比分组（失败不阻塞主报告）
    from vulnclaw.core.finding_lifecycle import apply_lifecycle

    report = apply_lifecycle(report)
    return report
__all__ = ['_generate_report']
from typing import Dict
