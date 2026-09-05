# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# report/report_generator.py
"""
报告生成器 - 精简版
修复：JSON 序列化添加 default=str
"""

import datetime
import os
from pathlib import Path
from typing import Dict, List, Optional

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import ensure_scheme

CONFIDENCE_ORDER = {"Critical": 0, "High": 1, "Medium": 3, "Low": 5, "Info": 7}
SEVERITY_COLORS = {
    "Critical": ("#E74856", "🔴 严重"),
    "High": ("#E74856", "🔴 高"),
    "Medium": ("#C19C00", "🟡 中"),
    "Low": ("#2E7D32", "🟢 低"),
    "Info": ("#327FBA", "🔵 信息"),
}

MAX_EVIDENCE_LENGTH = 5000

# --- P2-5: OWASP 修复建议映射（类型关键字 → CWE / OWASP 2021 / 修复要点） ---
OWASP_REMEDIATION = {
    "sqli": {"cwe": "CWE-89", "owasp": "A03:2021-Injection",
             "fix": "使用参数化查询/预编译语句，禁止拼接 SQL；输入白名单校验；数据库使用最小权限账户"},
    "sql_injection": {"cwe": "CWE-89", "owasp": "A03:2021-Injection",
                      "fix": "使用参数化查询/预编译语句，禁止拼接 SQL；输入白名单校验；数据库使用最小权限账户"},
    "sql": {"cwe": "CWE-89", "owasp": "A03:2021-Injection",
            "fix": "使用参数化查询/预编译语句，禁止拼接 SQL；输入白名单校验；数据库使用最小权限账户"},
    "xss": {"cwe": "CWE-79", "owasp": "A03:2021-Injection",
            "fix": "按上下文输出编码（HTML/JS/URL/属性）；启用 CSP；Cookie 设 HttpOnly+Secure"},
    "ssrf": {"cwe": "CWE-918", "owasp": "A10:2021-SSRF",
             "fix": "服务端 URL 域名/IP 白名单；禁止跟随重定向；拦截回环/私网/链路本地地址（含 169.254.169.254）"},
    "lfi": {"cwe": "CWE-98", "owasp": "A03:2021-Injection",
            "fix": "使用文件路径白名单映射；禁止用户输入直接拼接路径；对 ../ 与编码变体做规范化"},
    "文件": {"cwe": "CWE-98", "owasp": "A03:2021-Injection",
             "fix": "使用文件路径白名单映射；禁止用户输入直接拼接路径；对 ../ 与编码变体做规范化"},
    "rce": {"cwe": "CWE-78", "owasp": "A03:2021-Injection",
            "fix": "避免拼接系统命令；用安全 API 替代 shell 调用；输入白名单校验；沙箱运行"},
    "command_injection": {"cwe": "CWE-78", "owasp": "A03:2021-Injection",
                          "fix": "避免拼接系统命令；用安全 API 替代 shell 调用；输入白名单校验；沙箱运行"},
    "cmdi": {"cwe": "CWE-78", "owasp": "A03:2021-Injection",
             "fix": "避免拼接系统命令；用安全 API 替代 shell 调用；输入白名单校验；沙箱运行"},
    "命令": {"cwe": "CWE-78", "owasp": "A03:2021-Injection",
             "fix": "避免拼接系统命令；用安全 API 替代 shell 调用；输入白名单校验；沙箱运行"},
    "idor": {"cwe": "CWE-639", "owasp": "A01:2021-Broken Access Control",
             "fix": "服务端校验资源属主关系；使用不可预测引用标识；基于会话的访问控制"},
    "越权": {"cwe": "CWE-639", "owasp": "A01:2021-Broken Access Control",
             "fix": "服务端校验资源属主关系；使用不可预测引用标识；基于会话的访问控制"},
    "jwt": {"cwe": "CWE-345", "owasp": "A07:2021-Identification and Authentication Failures",
            "fix": "签名算法白名单校验，禁止 alg:none；kid 仅允许白名单公钥；使用高熵密钥"},
    "oauth": {"cwe": "CWE-346", "owasp": "A07:2021-Identification and Authentication Failures",
              "fix": "授权服务器精确匹配 redirect_uri；强制 state 参数防 CSRF；scope 最小化"},
    "session": {"cwe": "CWE-384", "owasp": "A07:2021-Identification and Authentication Failures",
                "fix": "登录成功重新生成 Session ID；Cookie 设 HttpOnly/Secure/SameSite；合理过期时间；注销后服务端使会话失效"},
    "会话": {"cwe": "CWE-384", "owasp": "A07:2021-Identification and Authentication Failures",
             "fix": "登录成功重新生成 Session ID；Cookie 设 HttpOnly/Secure/SameSite；合理过期时间；注销后服务端使会话失效"},
    "csrf": {"cwe": "CWE-352", "owasp": "A01:2021-Broken Access Control",
             "fix": "使用 CSRF Token；SameSite Cookie；双重提交 Cookie 校验"},
    "xxe": {"cwe": "CWE-611", "owasp": "A05:2021-Security Misconfiguration",
            "fix": "禁用外部实体解析；XML 解析器禁止 DTD/外部实体"},
    "deserialization": {"cwe": "CWE-502", "owasp": "A08:2021-Software and Data Integrity Failures",
                        "fix": "拒绝不可信反序列化输入；使用安全序列化格式；增加完整性校验"},
    "default": {"cwe": "CWE-710", "owasp": "A05:2021-Security Misconfiguration",
                "fix": "参考 OWASP ASVS / WSTG 针对漏洞类型进行加固"}
}


def _build_curl_command(vuln: Dict) -> str:
    """P2-5/B5: 由 finding 字段生成可执行的 curl 复现命令（支持 method/body/headers）。"""
    url = str(vuln.get("url", ""))
    url = ensure_scheme(url)
    param = str(vuln.get("parameter", "") or "")
    payload = str(vuln.get("payload", "") or vuln.get("attack_payload", "") or "")
    method = str(vuln.get("method", "") or "GET").upper()
    parts = ["curl", "-s", "-i"]
    if method and method != "GET":
        parts += ["-X", method]
    headers = vuln.get("headers") or {}
    if isinstance(headers, dict):
        for k, v in headers.items():
            parts.append('-H "{}: {}"'.format(k, v))
    if param and payload:
        from urllib.parse import quote
        sep = "&" if "?" in url else "?"
        target = url + sep + param + "=" + quote(payload, safe="")
    else:
        target = url
    parts.append('"{}"'.format(target))
    data = vuln.get("data")
    if data is not None and method in ("POST", "PUT", "PATCH"):
        parts.append("--data " + _json_body(data))
    return " ".join(parts)


def _json_body(data) -> str:
    """把 data 序列化为可嵌入 curl --data 的字符串。"""
    import json as _json
    if isinstance(data, str):
        if data.strip().startswith(("{", "[")):
            try:
                return _json.dumps(_json.loads(data), ensure_ascii=False, default=str)
            except Exception:
                return _json.dumps(data, ensure_ascii=False, default=str)
        return _json.dumps(data, ensure_ascii=False, default=str)
    return _json.dumps(data, ensure_ascii=False, default=str)


def _build_reproduction_steps(vuln: Dict) -> List[str]:
    """P2-5: 生成漏洞复现步骤。"""
    steps = []
    curl_cmd = _build_curl_command(vuln)
    param = str(vuln.get("parameter", "") or "")
    steps.append(f"1. 发送请求：`{curl_cmd}`")
    if param:
        steps.append(f"2. 在参数 `{param}` 中注入恶意载荷，观察响应是否符合漏洞特征（见上方证据）。")
    else:
        steps.append("2. 观察响应是否符合漏洞特征（见上方证据）。")
    steps.append("3. 与正常请求对比响应差异，确认漏洞可复现。")
    steps.append("4. 复现成功后，参考『修复建议』评估加固方案。")
    repro = vuln.get("reproduce_cmd")
    if repro:
        steps.append(f"5. 一键复现（nuclei PoC）：`{repro}`")
    return steps


# ============================================================
# A8.3：漏报率回归基线（已知靶场命中率持续监控）
# 通过环境变量 REGRESSION_BASELINE 指向基线 JSON（{"expect":[{cve_id,url?}...]}），
# 扫描报告生成时计算漏报率并附段；未设置则完全无副作用。
# ============================================================
def _extract_cve_ids(finding: Dict) -> List[str]:
    """从 finding 抽取包含的 CVE 编号（用于回归基线比对）。"""
    import re as _re
    text = " ".join(str(finding.get(k, "")) for k in
                    ("type", "url", "evidence", "ai_reason", "reproduce_cmd"))
    poc = finding.get("cve_poc")
    if isinstance(poc, dict):
        text += " " + str(poc.get("cve_id", ""))
    return _re.findall(r"CVE-\d{4}-\d+", text, _re.IGNORECASE)


def compute_false_negative(expected: List[Dict], actual: List[Dict]) -> Dict:
    """已知靶场基线 -> 漏报率统计。

    expected: [{cve_id, url?}, ...]；actual: 本次扫描发现列表。
    返回 {total, detected, missed, fn_rate, missed_list}。
    """
    actual_cves = set()
    for f in (actual or []):
        for c in _extract_cve_ids(f):
            actual_cves.add(c.upper())
    detected = 0
    missed = []
    for e in (expected or []):
        cid = str(e.get("cve_id") or e.get("cve") or "").upper()
        if not cid:
            continue
        if cid in actual_cves:
            detected += 1
        else:
            missed.append(e)
    total = len(expected or [])
    fn_rate = round((total - detected) / total, 4) if total else 0.0
    return {
        "total": total, "detected": detected, "missed": len(missed),
        "fn_rate": fn_rate, "missed_list": missed[:50],
    }


def evaluate_regression_baseline(baseline_path: str, findings: List[Dict]) -> Optional[Dict]:
    """读基线文件（JSON: {"expect":[...]}），计算漏报率；失败返回 None。"""
    try:
        import json
        with open(baseline_path, encoding="utf-8") as f:
            data = json.load(f)
        expect = data.get("expect") or data.get("expected") or []
        if not isinstance(expect, list):
            return None
        return compute_false_negative(expect, findings)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"[回归基线] 读取/计算失败: {e}")
        return None


def _regression_block(report_data: Dict) -> str:
    """A8.3：若设置 REGRESSION_BASELINE，返回漏报率 Markdown 段（否则空串）。"""
    path = os.environ.get("REGRESSION_BASELINE", "").strip()
    if not path:
        return ""
    findings = report_data.get("vulnerabilities", []) or []
    metrics = evaluate_regression_baseline(path, findings)
    if not metrics:
        return ""
    return (
        f"\n## 漏报率回归基线（A8.3）\n"
        f"- 基线文件: `{path}`\n"
        f"- 已知漏洞总数: {metrics['total']}\n"
        f"- 本次命中: {metrics['detected']}\n"
        f"- 漏报: {metrics['missed']}（漏报率 {metrics['fn_rate'] * 100:.1f}%）\n"
    )



_AG_D3_CDN = "https://cdn.jsdelivr.net/npm/d3@7"
_AG_D3_BODY = r"""
<script>
var __data = window.__AG_DATA__;
if (__data && __data.nodes && __data.nodes.length) {
    var box = document.getElementById('attackGraphBox');
    var width = Math.max(box ? box.clientWidth : 600, 600);
    var height = 520;
    var nodes = __data.nodes.slice();
    var nodeById = {};
    nodes.forEach(function(n, i){ n.index = i; nodeById[n.id] = i; });
    var links = (__data.edges || []).map(function(l){
        return {source: nodeById[l.source], target: nodeById[l.target], label: l.label || '', prob: l.prob || ''};
    }).filter(function(l){ return l.source !== undefined && l.target !== undefined; });
    var svg = d3.select('#attackGraphSvg').attr('viewBox', [0, 0, width, height]);
    svg.selectAll('*').remove();
    var color = {asset: '#28a745', vuln: '#dc3545', gate: '#fd7e14'};
    var simulation = d3.forceSimulation(nodes)
        .force('link', d3.forceLink(links).distance(75))
        .force('charge', d3.forceManyBody().strength(-280))
        .force('center', d3.forceCenter(width / 2, height / 2))
        .force('collide', d3.forceCollide(35));
    var link = svg.append('g').selectAll('line').data(links).join('line')
        .attr('stroke', '#adb5bd').attr('stroke-width', 1.2);
    var node = svg.append('g').attr('stroke', '#fff').attr('stroke-width', 1.5)
        .selectAll('circle').data(nodes).join('circle')
        .attr('r', 24)
        .attr('fill', function(d){ return color[d.kind] || '#888'; })
        .call(d3.drag().on('start', function(e, d){ if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
                       .on('drag', function(e, d){ d.fx = e.x; d.fy = e.y; })
                       .on('end', function(e, d){ if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; }));
    node.append('title').text(function(d){ return d.kind === 'vuln' ? d.type + ' [' + d.severity + '] p=' + d.prob : d.id; });
    var label = svg.append('g').selectAll('text').data(nodes).join('text')
        .attr('text-anchor', 'middle').attr('dy', '.35em').attr('font-size', 10).attr('fill', '#fff')
        .text(function(d){ var s = d.kind === 'asset' ? d.id : (d.type || d.id || ''); return s && s.length > 14 ? s.slice(0, 14) + '...' : s; });
    simulation.on('tick', function(){
        link.attr('x1', function(d){ return d.source.x; }).attr('y1', function(d){ return d.source.y; })
            .attr('x2', function(d){ return d.target.x; }).attr('y2', function(d){ return d.target.y; });
        node.attr('cx', function(d){ return d.x; }).attr('cy', function(d){ return d.y; });
        label.attr('x', function(d){ return d.x; }).attr('y', function(d){ return d.y; });
    });
} else {
    var fb = document.getElementById('attackGraphFallback');
    if (fb) { fb.style.display = 'block'; fb.textContent = '当前已无攻击图数据（无资产/漏洞节点）'; }
}
</script>
"""

def _build_attack_graph_block(report_data):
    """E1.3: 由报告攻击图生成 HTML 段（交互 D3 图 + 离线可见的 TOP 路径列表）。"""
    import html as html_escape
    import json as _json
    ag = report_data.get("attack_graph") or {}
    paths = report_data.get("attack_paths") or []
    paths_html = ""
    if paths:
        items = []
        for i, p in enumerate(paths, 1):
            chain = html_escape.escape(" -> ".join(p.get("path") or []))
            end = html_escape.escape(str(p.get("end_type", "")))
            prob = float(p.get("probability") or 0)
            items.append(
                '<li><strong>Path %d:</strong> <code>%s</code><br>'
                '<span style="color:#666;">终点: %s, 综合权重: %d, 成功率: %.1f%%</span></li>'
                % (i, chain, end, int(p.get("total_weight") or 0), prob * 100)
            )
        paths_html = (
            '<h3 style="margin-top:16px;">TOP 攻击路径</h3><ol style="line-height:1.8;">%s</ol>'
            % "".join(items)
        )
    nodes = ag.get("nodes") or []
    if not nodes:
        return paths_html, ""
    ag_json = _json.dumps({"nodes": nodes, "edges": ag.get("edges") or []}, ensure_ascii=False)
    script_html = (
        '<script src="%s" '
        "onerror=\"var _fb=document.getElementById('attackGraphFallback'); if(_fb){_fb.style.display='block';"
        " _fb.textContent='D3 CDN 不可用，交互攻击图渲染失败（TOP 路径列表可见）。';}\"></script>"
        % _AG_D3_CDN
    )
    script_html += '<script>window.__AG_DATA__ = %s;</script>' % ag_json
    script_html += _AG_D3_BODY
    return paths_html, script_html


def generate_html_report(report_data, html_file="report.html"):
    """生成 HTML 报告 - 同步版本"""
    try:
        # C1.4: 渲染前先落盘 PoC 产物并标注 finding（异常隔离，绝不影响报告主流程）
        try:
            _base_dir = os.path.dirname(os.path.abspath(html_file)) or "."
            generate_poc_artifacts(report_data, _base_dir)
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"[C1.4] PoC 产物生成失败（忽略）: {exc}")
        html_content = render_html(report_data)
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        # A8.3：漏报率回归基线（仅当 REGRESSION_BASELINE 设置）
        reg = _regression_block(report_data)
        if reg:
            report_data["regression_baseline"] = reg
            logger.info(f"📊 [回归基线] {reg.strip().splitlines()[-1]}")
        logger.info(f"📄 HTML 报告已保存至 {html_file}")
        return True
    except Exception as e:
        logger.error(f"❌ 生成 HTML 报告失败: {e}")
        try:
            txt_file = Path(html_file).with_suffix(".txt")
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"扫描报告 - {report_data.get('target', 'Unknown')}\n")
                f.write(f"生成时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"漏洞总数: {len(report_data.get('vulnerabilities', []))}\n\n")
                f.write("漏洞明细:\n")
                for v in report_data.get('vulnerabilities', []):
                    f.write(f"- [{v.get('severity', 'Unknown')}] {v.get('type')}: {v.get('url', '')}\n")
                    if v.get('evidence'):
                        evidence = v.get('evidence', '')
                        if len(evidence) > MAX_EVIDENCE_LENGTH:
                            evidence = evidence[:MAX_EVIDENCE_LENGTH] + "\n... [证据过长，请查看 JSON 报告]"
                        f.write(f"  证据: {evidence}\n")
            logger.info(f"📄 纯文本报告已保存至 {txt_file}")
        except Exception as e2:
            logger.error(f"❌ 降级报告也失败: {e2}")
        return False


# ===== 报告预处理：跨引擎去重 + 严重度排序（提升报告可用性）=====
SEVERITY_RANK = {
    'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4,
    '严重': 0, '高': 1, '中': 2, '低': 3, '信息': 4,
}


def normalize_vulns(vulns):
    """渲染前统一处理漏洞列表。

    1) 去重：按 (url, type, parameter) 去重，避免多引擎对同一点位重复刷屏；
    2) 排序：按严重度（Critical > High > Medium > Low > Info）升序 + CVSS 降序，
       保证高危问题排在报告最前面，便于优先处置。
    """
    seen = set()
    unique = []
    for v in vulns or []:
        key = (
            str(v.get('url', '')),
            str(v.get('type', '')),
            str(v.get('parameter', '') or ''),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(v)

    def rank(v):
        severity = str(v.get('severity', '')).strip().lower()
        try:
            cvss = float(v.get('cvss') or 0)
        except (TypeError, ValueError):
            cvss = 0.0
        return (SEVERITY_RANK.get(severity, 5), -cvss)

    unique.sort(key=rank)
    return unique


# ============================================================
# SP17.4 企业级报告增强（A 线）：
#   - suggest_remediation：按严重级返回分级修复建议（可单测）
#   - build_distribution：按 (type, severity) 交叉统计漏洞分布
#   - enrich_report：为报告 dict 注入 distribution 与逐条 remediation_tier
# 只增不改既有字段；空 findings 给出空结构不抛错；可幂等重复调用。
# ============================================================
_REMEDIATION_TIER_TEMPLATES = {
    "critical": "立即修复：漏洞已对系统核心资产构成即时威胁，请立即下线受影响组件/封堵入口并部署直接缓解动作",
    "high": "限期修复：请在近期安排补丁更新或配置动作（参数化查询/访问控制/最小权限等），完成后回归验证",
    "medium": "计划修复：纳入加固计划，逐步落实输入校验、安全配置与纵深防御加固动作",
    "low": "观察项：持续评估该风险，定期复核研判并跟踪处置阈值",
}


def suggest_remediation(severity, existing_remediation=""):
    """SP17.4：按严重级返回分级修复建议文本。

    - 已有 remediation 文本时在其后追加模板（不覆盖，原有内容保留在前）；
    - 否则以分级模板为主。
    """
    sev = str(severity or "").strip().lower()
    template = _REMEDIATION_TIER_TEMPLATES.get(sev, _REMEDIATION_TIER_TEMPLATES["medium"])
    existing = str(existing_remediation or "").strip()
    if existing:
        return existing + "；" + template
    return template


def _target_host(url) -> str:
    """从 URL 提取主机名（用于排名目标统计）；无有效主机返回空串。"""
    u = str(url or "").strip()
    if not u:
        return ""
    u = u.split("://", 1)[-1]
    return (u.split("/", 1)[0] or "").strip()


def build_distribution(findings):
    """SP17.4：按 (type, severity) 交叉统计漏洞分布。

    返回 {"by_type": {type: {severity: count}}, "by_severity": {severity: count},
          "ranked_targets": [{"host":.., "count":n}, ...]}。
    """
    by_type = {}
    by_severity = {}
    target_counter = {}
    for f in findings or []:
        ftype = str(f.get("type") or "unknown")
        sev = str(f.get("severity") or "").strip().lower() or "unknown"
        inner = by_type.setdefault(ftype, {})
        inner[sev] = inner.get(sev, 0) + 1
        by_severity[sev] = by_severity.get(sev, 0) + 1
        host = _target_host(f.get("url"))
        if host:
            target_counter[host] = target_counter.get(host, 0) + 1
    ranked_targets = [
        {"host": h, "count": c}
        for h, c in sorted(target_counter.items(), key=lambda kv: (-kv[1], kv[0]))
    ]
    return {
        "by_type": by_type,
        "by_severity": by_severity,
        "ranked_targets": ranked_targets,
    }


def enrich_report(report_data):
    """SP17.4：为报告 dict 注入 distribution 与逐条 remediation_tier。

    仅新增额外字段（report_data["distribution"]、finding["remediation_tier"]），
    不改写任何既有键；幂等可重复调用。返回原 report_data（便于链式/单测）。
    """
    vulns = report_data.get("vulnerabilities") or []
    report_data["distribution"] = build_distribution(vulns)
    for f in vulns:
        f["remediation_tier"] = suggest_remediation(
            str(f.get("severity") or "").lower(), f.get("remediation")
        )
    return report_data


def _is_pending_review(vuln: Dict) -> bool:
    """判定 finding 是否处于“待人工复核”状态（验证层未能 AI 确认但保留）。"""
    text = " ".join(str(vuln.get(k, "")) for k in
                    ("ai_verdict", "confidence", "verification_method"))
    return any(k in text for k in ("待人工复核", "待复核", "已跳过验证", "预算已满"))


def render_pending_review_section(vulns: List[Dict]) -> str:
    """渲染“待人工复核”分组：把验证层保留但未 AI 确认的漏洞集中列出，便于人工判别。"""
    pending = [v for v in vulns if _is_pending_review(v)]
    if not pending:
        return "<p>✅ 无待人工复核项（所有保留漏洞均已确认或已排除）。</p>"
    import html as html_escape
    parts = [f"<p>共 <strong>{len(pending)}</strong> 条待人工复核（验证层保留但 AI/技术验证未能 100% 确认，需人工判别是否真实漏洞）：</p>", "<ul>"]
    for v in pending:
        vt = html_escape.escape(str(v.get("type", "未知")))
        vu = html_escape.escape(str(v.get("url", "")))
        vp = html_escape.escape(str(v.get("parameter", "") or ""))
        verdict = html_escape.escape(str(v.get("ai_verdict", "") or v.get("confidence", "")))
        ev = str(v.get("evidence", ""))
        if len(ev) > 600:
            ev = ev[:600] + "\n... [证据过长，请查看 JSON 报告]"
        ev = html_escape.escape(ev)
        parts.append(f'''
        <li style="border-left:4px solid #fd7e14; padding-left:10px; margin:8px 0;">
            <div><strong>类型:</strong> {vt} &nbsp; <strong>严重性:</strong> {html_escape.escape(str(v.get('severity', '')))}</div>
            <div><strong>URL:</strong> <a href="{vu}" target="_blank">{vu}</a></div>
            {f'<div><strong>参数:</strong> {vp}</div>' if vp else ''}
            <div><strong>复核原因:</strong> {verdict}</div>
            <div><strong>证据:</strong>
                <pre style="background:#f8f9fa; padding:6px; border-radius:4px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; max-height:150px; font-size:12px; margin:4px 0;">{ev}</pre>
            </div>
        </li>''')
    parts.append("</ul>")
    return "".join(parts)


def render_html(enhanced_report):
    """渲染 HTML 报告内容 - 修复：证据截断"""
    import html as html_escape

    # SP17.4：注入 distribution 与逐条 remediation_tier（只增不改既有字段）
    enrich_report(enhanced_report)

    target = enhanced_report.get('target', '')
    vulns = normalize_vulns(enhanced_report.get('vulnerabilities', []))
    vuln_count = len(vulns)
    critical = len([v for v in vulns if v.get('severity') == 'Critical'])
    high = len([v for v in vulns if v.get('severity') == 'High'])
    medium = len([v for v in vulns if v.get('severity') == 'Medium'])
    low = len([v for v in vulns if v.get('severity') == 'Low'])
    info = len([v for v in vulns if v.get('severity') == 'Info'])
    pending_review = len([v for v in vulns if _is_pending_review(v)])

    # 漏洞类型分布（Chart.js 饼图数据，Top 8）
    import json
    from collections import Counter
    type_counter = Counter(str(v.get('type', '未知')) for v in vulns)
    top_types = type_counter.most_common(8)
    type_labels = [label for label, _ in top_types] or ['暂无数据']
    type_values = [count for _, count in top_types] or [0]

    vuln_items_html = []
    # P2-5: 按漏洞类型映射 OWASP 修复建议
    for v in vulns[:50]:
        severity = v.get('severity', 'unknown')
        sev_class = severity.lower()
        vuln_type_raw = str(v.get('type', '未知'))
        vuln_type = html_escape.escape(vuln_type_raw)
        vuln_url = html_escape.escape(str(v.get('url', '')))
        vuln_severity = html_escape.escape(str(severity))
        vuln_param = html_escape.escape(str(v.get('parameter', '') or ''))
        vuln_confidence = html_escape.escape(str(v.get('confidence', '') or ''))

        evidence_raw = v.get('evidence', '') or ''
        if len(evidence_raw) > MAX_EVIDENCE_LENGTH:
            evidence = html_escape.escape(str(evidence_raw[:MAX_EVIDENCE_LENGTH]))
            evidence += "\n... [证据过长，已截断，请查看 JSON 报告获取完整内容]"
        else:
            evidence = html_escape.escape(str(evidence_raw))

        # P2-5: OWASP 修复建议 + CWE 映射
        remediation = OWASP_REMEDIATION.get("default")
        for key, entry in OWASP_REMEDIATION.items():
            if key != "default" and key.lower() in vuln_type_raw.lower():
                remediation = entry
                break
        curl_cmd = html_escape.escape(_build_curl_command(v))
        repro_steps = _build_reproduction_steps(v)
        repro_html = "".join(f"<li>{html_escape.escape(s)}</li>" for s in repro_steps)
        # R2-A S2: 来源溯源徽标（param_mining / live:*）
        source_badge = _source_badge(v)
        # C1.4: 已落盘 PoC 产物 → 该漏洞条目内附产物链接
        poc_link_html = ""
        if v.get('poc_file'):
            _pf = html_escape.escape(str(v.get('poc_file')))
            _po = html_escape.escape(str(v.get('poc_origin', '') or ''))
            poc_link_html = (f'<p style="margin:6px 0;"><strong>PoC 产物 (C1.4):</strong> '
                             f'<a href="{_pf}" download>{_pf}</a> '
                             f'<span style="color:#666;">[{_po}]</span></p>')
        # SP14.3: OOB 回调证据段（有则渲染，无则留空）
        oob_html = ""
        _oob = v.get("oob_evidence")
        if isinstance(_oob, dict) and (_oob.get("ts") or _oob.get("detail")):
            oob_html = (f'<p style="margin:6px 0;"><strong>带外回调证据 (OOB):</strong> '
                        f'通道 {html_escape.escape(str(_oob.get("channel", "dns")))} · '
                        f'时间 {html_escape.escape(str(_oob.get("ts", "")))}'
                        f'{(" · token " + html_escape.escape(str(_oob.get("token", "")))) if _oob.get("token") else ""}</p>')
            if _oob.get("detail"):
                oob_html += (f'<pre style="background:#f8f9fa; padding:8px; border-radius:4px; overflow-x:auto; '
                             f'white-space:pre-wrap; word-wrap:break-word; font-size:12px; margin:4px 0;">'
                             f'{html_escape.escape(str(_oob.get("detail")))}</pre>')
            if _oob.get("curl"):
                oob_html += (f'<pre style="background:#263238; color:#cddc39; padding:8px; border-radius:4px; '
                             f'overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; font-size:12px; '
                             f'margin:4px 0;">{html_escape.escape(str(_oob.get("curl")))}</pre>')

        vuln_items_html.append(f'''
        <div class="vuln-item vuln-{sev_class}" data-severity="{sev_class}" data-type="{html_escape.escape(vuln_type_raw.lower())}">
            <strong>🔹 {vuln_type}</strong>
            <br>
            <span style="color:#666;">URL: </span><a href="{vuln_url}" target="_blank">{vuln_url}</a>
            <br>
            <span style="color:#666;">严重性: </span><strong>{vuln_severity}</strong>
            {f'<br><span style="color:#666;">参数: </span>{vuln_param}' if vuln_param else ''}
            {f'<br><span style="color:#666;">置信度: </span><strong>{vuln_confidence}</strong>' if vuln_confidence else ''}
            {source_badge}
            <br>
            <span style="color:#666;">证据: </span>
            <pre style="background:#f8f9fa; padding:8px; border-radius:4px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; max-height:300px; font-size:12px; margin:4px 0;">{evidence}</pre>
            <details style="margin-top:6px;">
                <summary style="cursor:pointer; color:#007bff;">🧪 复现步骤 / PoC</summary>
                <p style="margin:6px 0;"><strong>curl 命令:</strong></p>
                <pre style="background:#263238; color:#cddc39; padding:8px; border-radius:4px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; font-size:12px; margin:4px 0;">{curl_cmd}</pre>
                <ol style="margin:6px 0;">{repro_html}</ol>
                {poc_link_html}
                {oob_html}
            </details>
            <details style="margin-top:6px;">
                <summary style="cursor:pointer; color:#007bff;">🛡️ 修复建议（{remediation["cwe"]} / {remediation["owasp"]}）</summary>
                <p style="margin:6px 0;">{html_escape.escape(remediation["fix"])}</p>
            </details>
        </div>
        ''')

    vuln_section = ''.join(vuln_items_html)

    attack_paths_html, attack_graph_script = _build_attack_graph_block(enhanced_report)
    if len(vulns) > 50:
        vuln_section += f'<p style="color:#666; font-style:italic;">... 共 {len(vulns)} 个漏洞，仅显示前 50 个。请查看 JSON 报告获取完整列表。</p>'

    lifecycle_block = _render_lifecycle_block(enhanced_report)
    # C1.4: PoC 产物清单段（generate_poc_artifacts 已在 generate_html_report 前置落盘）
    poc_artifacts_html = _render_poc_artifacts_section(enhanced_report)
    # R2-A S2: 溯源来源分布段
    source_attribution_html = _render_source_attribution_section(vulns)

    html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>渗透测试报告 - {html_escape.escape(target)}</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; }}
        h1 {{ color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }}
        .summary {{ display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }}
        .summary-card {{ background: #f8f9fa; padding: 15px 25px; border-radius: 8px; flex: 1; min-width: 100px; text-align: center; }}
        .summary-card .number {{ font-size: 28px; font-weight: bold; color: #007bff; }}
        .charts {{ display: flex; gap: 30px; flex-wrap: wrap; margin: 20px 0; }}
        .chart-box {{ flex: 1; min-width: 320px; background: #fff; padding: 15px; border: 1px solid #e9ecef; border-radius: 8px; }}
        .vuln-item {{ padding: 12px 15px; margin: 8px 0; border-radius: 4px; border-left: 4px solid #ffc107; background: #fff8e1; }}
        .vuln-critical {{ border-left-color: #dc3545; background: #f8d7da; }}
        .vuln-high {{ border-left-color: #dc3545; background: #f8d7da; }}
        .vuln-medium {{ border-left-color: #ffc107; background: #fff3cd; }}
        .vuln-low {{ border-left-color: #17a2b8; background: #d1ecf1; }}
        .vuln-info {{ border-left-color: #6c757d; background: #e2e3e5; }}
        .vuln-item pre {{ background: #f8f9fa; padding: 8px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; max-height: 300px; font-size: 12px; margin: 4px 0; border: 1px solid #e9ecef; }}
        .vuln-item a {{ color: #007bff; text-decoration: none; word-break: break-all; }}
        .vuln-item a:hover {{ text-decoration: underline; }}
        .filter-bar {{ margin: 12px 0; padding: 10px 14px; background: #f1f3f5; border-radius: 6px; }}
        .filter-bar select {{ margin: 0 8px 0 4px; padding: 4px 6px; border-radius: 4px; border: 1px solid #ced4da; }}
        .review-section {{ margin-top: 30px; }}
        .review-section ul {{ list-style-type: none; padding-left: 0; }}
        .review-section li {{ background: #f8f9fa; margin: 8px 0; padding: 12px; border-radius: 6px; }}
        .review-section details {{ margin-top: 8px; }}
        .review-section summary {{ cursor: pointer; color: #007bff; }}
        .review-section pre {{ background: #f8f9fa; padding: 8px; border-radius: 4px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; max-height: 200px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔎 渗透测试报告 - {html_escape.escape(target)}</h1>
        <p><strong>生成时间:</strong> {enhanced_report.get('scan_time', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>

        <div class="summary">
            <div class="summary-card"><div class="number">{enhanced_report.get('alive', 0)}</div>存活资产</div>
            <div class="summary-card"><div class="number">{enhanced_report.get('high_value', 0)}</div>高价值资产</div>
            <div class="summary-card"><div class="number">{vuln_count}</div>漏洞总数</div>
            <div class="summary-card"><div class="number" style="color:red">{critical}</div>严重</div>
            <div class="summary-card"><div class="number" style="color:red">{high}</div>高</div>
            <div class="summary-card"><div class="number" style="color:orange">{medium}</div>中</div>
            <div class="summary-card"><div class="number">{low}</div>低</div>
            <div class="summary-card"><div class="number">{info}</div>信息</div>
            <div class="summary-card"><div class="number" style="color:#fd7e14">{pending_review}</div>待人工复核</div>
        </div>

        {lifecycle_block}

        <h2>📊 可视化统计</h2>
        <div class="charts">
            <div class="chart-box">
                <h3 style="text-align:center; margin-top:0;">严重性分布</h3>
                <canvas id="severityChart"></canvas>
            </div>
            <div class="chart-box">
                <h3 style="text-align:center; margin-top:0;">漏洞类型 Top {len(type_labels)}</h3>
                <canvas id="typeChart"></canvas>
            </div>
        </div>

        <h2>🕸️ 攻击图（E1）</h2>
        <div id="attackGraphBox" style="background:#fff; border:1px solid #e9ecef; border-radius:8px; padding:12px;">
            <svg id="attackGraphSvg" width="100%" height="520"></svg>
            <p id="attackGraphFallback" style="display:none; color:#fd7e14; font-style:italic;">
                交互图不可用（CDN 离线或数据为空），请参考下方 TOP 攻击路径列表。
            </p>
        </div>
        {attack_paths_html}
        {attack_graph_script}
        <h2>📋 漏洞明细</h2>
        <div class="filter-bar">
            <label>严重性筛选:
                <select id="sevFilter" onchange="applyFilter()">
                    <option value="all">全部</option>
                    <option value="critical">严重</option>
                    <option value="high">高</option>
                    <option value="medium">中</option>
                    <option value="low">低</option>
                    <option value="info">信息</option>
                </select>
            </label>
            <label>类型筛选:
                <select id="typeFilter" onchange="applyFilter()">
                    <option value="all">全部类型</option>
                    {render_type_filter_options(vulns)}
                </select>
            </label>
            <span id="filterCount" style="margin-left:12px; color:#666;"></span>
        </div>
        <div id="vulnList">{vuln_section}</div>

        {poc_artifacts_html}

        {source_attribution_html}

        <h2>🟠 待人工复核漏洞</h2>
        {render_pending_review_section(vulns)}

        <h2>🧑‍💻 人工审核清单</h2>
        {render_review_section(enhanced_report)}

        {render_owasp_summary(vulns)}
    </div>
    <script>
        const severityLabels = ['严重', '高', '中', '低', '信息'];
        const severityValues = [{critical}, {high}, {medium}, {low}, {info}];
        const severityColors = ['#dc3545', '#E74856', '#ffc107', '#17a2b8', '#6c757d'];
        new Chart(document.getElementById('severityChart'), {{
            type: 'bar',
            data: {{
                labels: severityLabels,
                datasets: [{{
                    label: '漏洞数量',
                    data: severityValues,
                    backgroundColor: severityColors,
                    borderRadius: 4,
                }}],
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{ y: {{ beginAtZero: true, ticks: {{ precision: 0 }} }} }},
            }},
        }});

        const typeLabels = {json.dumps(type_labels, ensure_ascii=False)};
        const typeValues = {json.dumps(type_values)};
        const typeColors = ['#4e79a7', '#f28e2b', '#e15759', '#76b7b2', '#59a14f', '#edc948', '#b07aa1', '#ff9da7'];
        new Chart(document.getElementById('typeChart'), {{
            type: 'pie',
            data: {{
                labels: typeLabels,
                datasets: [{{
                    data: typeValues,
                    backgroundColor: typeColors.slice(0, typeLabels.length),
                }}],
            }},
            options: {{
                responsive: true,
                plugins: {{ legend: {{ position: 'right' }} }},
            }},
        }});

        // P2-5: 按严重性 / 类型筛选漏洞明细
        function applyFilter() {{
            const sev = document.getElementById('sevFilter').value;
            const typ = document.getElementById('typeFilter').value;
            const items = document.querySelectorAll('.vuln-item');
            let shown = 0;
            items.forEach(function (item) {{
                const s = item.getAttribute('data-severity');
                const t = item.getAttribute('data-type');
                const okSev = sev === 'all' || s === sev;
                const okTyp = typ === 'all' || t === typ;
                item.style.display = (okSev && okTyp) ? '' : 'none';
                if (okSev && okTyp) shown++;
            }});
            document.getElementById('filterCount').textContent = '当前显示 ' + shown + ' / ' + items.length + ' 个漏洞';
        }}
        applyFilter();
    </script>
</body>
</html>
    """
    return html_content


def render_type_filter_options(vulns):
    """P2-5: 类型筛选下拉选项（按漏洞类型去重）。"""
    seen = []
    for v in vulns:
        t = str(v.get('type', '未知')).lower()
        if t and t not in seen:
            seen.append(t)
    if not seen:
        return ""
    import html as html_escape
    return "".join(
        f'<option value="{html_escape.escape(t)}">{html_escape.escape(t)}</option>'
        for t in seen
    )


def render_owasp_summary(vulns):
    """P2-5: 报告末尾 OWASP 修复建议汇总表（按漏洞类型去重）。"""
    from collections import OrderedDict
    grouped = OrderedDict()
    for v in vulns:
        t = str(v.get('type', '未知')).lower()
        entry = OWASP_REMEDIATION.get("default")
        for key, e in OWASP_REMEDIATION.items():
            if key != "default" and key in t:
                entry = e
                break
        if t and t not in grouped:
            grouped[t] = entry
    if not grouped:
        return ""
    import html as html_escape
    parts = [
        '<h2>🛡️ OWASP 修复建议映射</h2>',
        '<table style="width:100%; border-collapse:collapse; font-size:13px;">',
        '<tr style="background:#f1f3f5;"><th style="padding:8px; text-align:left;">漏洞类型</th>'
        '<th style="padding:8px; text-align:left;">CWE</th>'
        '<th style="padding:8px; text-align:left;">OWASP 2021</th>'
        '<th style="padding:8px; text-align:left;">修复要点</th></tr>',
    ]
    for t, e in grouped.items():
        parts.append(
            f'<tr>'
            f'<td style="padding:8px; border-bottom:1px solid #eee;">{html_escape.escape(t)}</td>'
            f'<td style="padding:8px; border-bottom:1px solid #eee;">{e["cwe"]}</td>'
            f'<td style="padding:8px; border-bottom:1px solid #eee;">{e["owasp"]}</td>'
            f'<td style="padding:8px; border-bottom:1px solid #eee;">{html_escape.escape(e["fix"])}</td>'
            f'</tr>'
        )
    parts.append('</table>')
    return "".join(parts)


def render_review_section(report_data):
    """渲染人工审核清单部分 - 修复：证据截断"""
    manifest = report_data.get('review_manifest')
    if not manifest or not manifest.get('clues'):
        return "<p>✅ 无可疑线索，无需人工审核。</p>"

    clues = manifest['clues']
    priority_labels = {'high': '🔴 高', 'medium': '🟡 中', 'low': '🟢 低'}
    priority_colors = {'high': '#dc3545', 'medium': '#fd7e14', 'low': '#28a745'}

    html_parts = []
    html_parts.append(f'<h3>共 {len(clues)} 条线索</h3>')

    for priority in ['high', 'medium', 'low']:
        priority_clues = [c for c in clues if c.get('priority') == priority]
        if not priority_clues:
            continue

        label = priority_labels.get(priority, priority)
        color = priority_colors.get(priority, '#6c757d')
        html_parts.append(f'<h4>{label} 优先级（{len(priority_clues)} 条）</h4>')
        html_parts.append('<ul>')

        displayed = priority_clues[:30]
        for clue in displayed:
            clue_url = clue.get('url', '')
            clue_type = clue.get('type', '')
            clue_evidence = clue.get('evidence', '') or ''
            if len(clue_evidence) > MAX_EVIDENCE_LENGTH:
                clue_evidence = clue_evidence[:MAX_EVIDENCE_LENGTH] + "\n... [证据过长，已截断]"
            clue_suggestion = clue.get('suggestion', '') or ''

            html_parts.append(f'''
            <li style="border-left:4px solid {color}; padding-left:10px;">
                <div><strong>URL:</strong> <a href="{clue_url}" target="_blank">{clue_url}</a></div>
                <div><strong>类型:</strong> {clue_type}</div>
                <div><strong>证据:</strong>
                    <pre style="background:#f8f9fa; padding:6px; border-radius:4px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; max-height:150px; font-size:12px; margin:4px 0;">{clue_evidence}</pre>
                </div>
                <div><strong>建议:</strong> {clue_suggestion}</div>
                {render_ai_test_guide(clue)}
            </li>
            ''')

        if len(priority_clues) > 30:
            html_parts.append(f'<p style="color:#666; font-style:italic;">... 共 {len(priority_clues)} 条线索，仅显示前 30 条，请查看 JSON 报告获取完整列表。</p>')

        html_parts.append('</ul>')

    return ''.join(html_parts)


def render_ai_test_guide(clue):
    """渲染 AI 测试指南"""
    ai = clue.get('ai_analysis')
    if not ai:
        return ""

    test_steps = ai.get('test_steps', [])
    expected = ai.get('expected_results', [])
    tools = ai.get('tools', [])
    recommendation = ai.get('recommendation', '')
    is_real = ai.get('is_real_vulnerability', '未知')
    reason = ai.get('reason', '')

    return f'''
    <details>
        <summary>🤖 AI 测试指南</summary>
        <p><strong>判断:</strong> {is_real} - {reason}</p>
        <p><strong>测试步骤:</strong></p>
        <ol>{''.join([f'<li>{step}</li>' for step in test_steps])}</ol>
        <p><strong>预期结果:</strong></p>
        <ul>{''.join([f'<li>{exp}</li>' for exp in expected])}</ul>
        <p><strong>推荐工具:</strong> {', '.join(tools) if tools else '无'}</p>
        <p><strong>建议操作:</strong> {recommendation}</p>
    </details>
    '''


def generate_markdown_report(report_data, output_path):
    """生成 Markdown 报告"""
    lines = []
    enrich_report(report_data)  # SP17.4：注入 distribution 与 remediation_tier
    lines.append(f"# 渗透测试报告 - {report_data.get('target', 'Unknown')}")
    lines.append("")
    lines.append(f"**生成时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**目标**: {report_data.get('target', '')}")
    lines.append("")
    lines.append("## 概览统计")
    lines.append("")
    lines.append(f"- **子域名总数**: {len(report_data.get('subdomains', []))}")
    lines.append(f"- **存活资产**: {report_data.get('alive', 0)}")
    lines.append(f"- **漏洞总数**: {len(normalize_vulns(report_data.get('vulnerabilities', [])))}")
    lines.append("")

    vulns = normalize_vulns(report_data.get("vulnerabilities", []))
    if vulns:
        lines.append("## 漏洞明细")
        for v in vulns[:30]:
            vuln_type = v.get('type', 'Unknown')
            severity = v.get('severity', 'Low')
            url = v.get('url', '')
            evidence = v.get('evidence', '') or ''
            if len(evidence) > MAX_EVIDENCE_LENGTH:
                evidence = evidence[:MAX_EVIDENCE_LENGTH] + "\n... [证据过长，请查看 JSON 报告]"
            lines.append("")
            lines.append(f"### {vuln_type}")
            lines.append(f"- **严重性**: {severity}")
            lines.append(f"- **URL**: {url}")
            lines.append("- **证据**:")
            lines.append("```")
            lines.append(evidence)
            lines.append("```")
            _oob = v.get("oob_evidence")
            if isinstance(_oob, dict) and (_oob.get("ts") or _oob.get("detail")):
                lines.append("")
                lines.append("**带外回调证据 (OOB)**:")
                lines.append(f"- 通道: {_oob.get('channel', 'dns')}")
                lines.append(f"- 时间: {_oob.get('ts', '')}")
                if _oob.get("token"):
                    lines.append(f"- token: {_oob.get('token')}")
                if _oob.get("detail"):
                    lines.append("- detail:")
                    lines.append("```")
                    lines.append(str(_oob.get("detail"))[:MAX_EVIDENCE_LENGTH])
                    lines.append("```")
            _src = str(v.get("source") or "").strip()
            if _src:  # R2-A S2: 单条溯源标记
                _label, _ = _source_label(_src)
                lines.append(f"- **溯源来源**: {_label}（`{_src}`）")
            lines.append("---")
        if len(vulns) > 30:
            lines.append(f"\n... 共 {len(vulns)} 个漏洞，仅显示前 30 个。请查看 JSON 报告获取完整列表。")
    else:
        lines.append("✅ 未发现安全漏洞。")

    pending = [v for v in vulns if _is_pending_review(v)]
    if pending:
        lines.append("")
        lines.append(f"## 🟠 待人工复核漏洞（{len(pending)} 条）")
        lines.append("")
        lines.append("验证层保留但 AI/技术验证未能 100% 确认，需人工判别是否真实漏洞：")
        for v in pending[:30]:
            lines.append(f"- **{v.get('type', '未知')}** @ `{v.get('url', '')}` "
                         f"(参数: {v.get('parameter', '') or '-'}) — "
                         f"{v.get('ai_verdict', v.get('confidence', ''))}")

    # R2-A S2: 溯源来源分布段
    _src_counter = {}
    for _v in vulns:
        _s = str((_v or {}).get("source") or "").strip()
        if _s:
            _src_counter[_s] = _src_counter.get(_s, 0) + 1
    if _src_counter:
        _total = sum(_src_counter.values())
        lines.append("")
        lines.append("## 溯源来源分布（S2）")
        lines.append("")
        for _s, _n in sorted(_src_counter.items(), key=lambda kv: (-kv[1], kv[0])):
            _label, _ = _source_label(_s)
            _pct = round(_n / _total * 100, 1) if _total else 0.0
            lines.append(f"- **{_label}**（`{_s}`）：{_n} 条（{_pct}%）")

    # C1.4: PoC 产物清单段
    arts = report_data.get("poc_artifacts") or []
    if arts:
        lines.append("")
        lines.append(f"## 可运行 PoC 产物（C1.4，共 {len(arts)} 份）")
        lines.append("")
        lines.append("产物位于报告同目录 `poc/` 子目录，可直接 `python poc_xx.py` 运行复现：")
        lines.append("")
        for a in arts[:30]:
            lines.append(f"- `{a.get('file', '')}` — {a.get('type', '')} [{a.get('origin', '')}]")

    # A8.3：漏报率回归基线段（仅当 REGRESSION_BASELINE 设置）
    reg = _regression_block(report_data)
    if reg:
        lines.append(reg)
        logger.info(f"📊 [回归基线] {reg.strip().splitlines()[-1]}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info(f"📄 Markdown 报告已保存至 {output_path}")




# ============================================================
# B5: 高危跨平台可运行 PoC 脚本（不依赖 curl，python 内置库）
# ============================================================
def _build_poc_python(vuln: Dict) -> str:
    """B5/H1: 高危漏洞必带可运行 Python PoC 脚本（urllib 实现，规避 curl/环境依赖）。"""
    url = ensure_scheme(str(vuln.get("url", "")))
    param = str(vuln.get("parameter", "") or "")
    payload = str(vuln.get("payload", "") or vuln.get("attack_payload", "") or "")
    method = str(vuln.get("method", "") or "GET").upper()
    target = url
    if param and payload:
        from urllib.parse import quote, urlsplit, urlunsplit
        parts = urlsplit(url)
        sep = "&" if parts.query else "?"
        target = urlsplit(url)._replace(query=parts.query + sep + urllib_quote(param) + "=" + quote(payload, safe="")).geturl()
    return _POC_TEMPLATE.format(
        method=method,
        target=target,
        note=payload or param or url,
    )


def urllib_quote(s):
    from urllib.parse import quote as _q
    return _q(s, safe="")


_POC_TEMPLATE = """import sys
import urllib.request
import urllib.error

# Auto-generated functional PoC by VULNCLAW (B5). Run: python poc.py
TARGET = {target!r}
METHOD = {method!r}
NOTE = {note!r}

def main():
    req = urllib.request.Request(TARGET, method=METHOD)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            print("STATUS:", resp.status)
            print("HAS_MARKER:", NOTE in body or TARGET in body)
            print(body[:2000])
    except urllib.error.HTTPError as e:
        print("HTTP_ERROR:", e.code)
    except Exception as exc:
        print("ERROR:", exc)

if __name__ == "__main__":
    main()
"""


# ============================================================
# C1.4: PoC 产物落盘 + 报告挂接
# 每个确认漏洞自动生成可运行 PoC 产物文件（<报告目录>/poc/），报告内附链接。
# 内容来源优先级：A8.2 cve_poc.poc_script > POCGenerator 模板渲染 > B5 urllib 骨架。
# 不主动触发 LLM 生成路径（成本不可控）；全链异常隔离，绝不影响报告主流程。
# ============================================================
_POC_GEN = None


def _get_poc_generator():
    """惰性单例 POCGenerator（函数内 import，避免模块加载期依赖）。"""
    global _POC_GEN
    if _POC_GEN is None:
        from vulnclaw.deepsec.poc_generator import POCGenerator
        _POC_GEN = POCGenerator()
    return _POC_GEN


def _run_poc_coro(coro):
    """同步报告流程中执行 async PoC 生成；已处于事件循环内时落到独立线程。"""
    import asyncio
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(asyncio.run, coro).result()


# 中文漏洞类型 → POCGenerator 模板（真实扫描 type 串为中文，TEMPLATE_MAP 英文键覆盖不到）
_CN_TYPE_TEMPLATE = [
    ("sql注入", "sqli.py.j2"), ("sql 注入", "sqli.py.j2"), ("sqli", "sqli.py.j2"),
    ("跨站脚本", "xss.html.j2"), ("xss", "xss.html.j2"),
    ("文件包含", "lfi.py.j2"), ("路径遍历", "lfi.py.j2"), ("目录遍历", "lfi.py.j2"),
    ("命令注入", "rce.py.j2"), ("命令执行", "rce.py.j2"),
    ("代码执行", "rce.py.j2"), ("rce", "rce.py.j2"),
]


def _poc_template_name(vuln: Dict) -> Optional[str]:
    """漏洞类型命中 POCGenerator 静态模板则返回模板名（不走 LLM 路径）。"""
    vtype = str(vuln.get("type", "")).lower()
    try:
        from vulnclaw.deepsec.poc_generator import TEMPLATE_MAP
        for key, tpl in TEMPLATE_MAP.items():
            if key in vtype:
                return tpl
    except Exception:  # noqa: BLE001
        pass
    for key, tpl in _CN_TYPE_TEMPLATE:
        if key in vtype:
            return tpl
    return None


def _safe_poc_stem(idx: int, vuln: Dict) -> str:
    import re as _re
    vtype = _re.sub(r"[^0-9A-Za-z]+", "_", str(vuln.get("type", "vuln"))).strip("_")[:40] or "vuln"
    return "poc_{:02d}_{}".format(idx, vtype)


def generate_poc_artifacts(report_data: Dict, base_dir: str, max_artifacts: int = 20) -> List[Dict]:
    """C1.4: 为漏洞生成可运行 PoC 产物文件，并在 finding 上标注相对路径。

    - 产物写入 <base_dir>/poc/；finding 增 poc_file / poc_origin 字段；
      report_data["poc_artifacts"] 汇总清单（HTML/Markdown 据此渲染链接）。
    - 优先 Critical/High，上限 max_artifacts（默认 20）防产物爆炸。
    - 全链异常隔离：单条失败只跳过该条，绝不上抛。
    """
    vulns = normalize_vulns(report_data.get("vulnerabilities", [])) or []
    if not vulns:
        return []
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    candidates = sorted(
        enumerate(vulns),
        key=lambda kv: (order.get(str(kv[1].get("severity", "Info")), 5), kv[0]),
    )[:max_artifacts]
    poc_dir = os.path.join(base_dir, "poc")
    try:
        os.makedirs(poc_dir, exist_ok=True)
    except Exception as exc:  # noqa: BLE001
        logger.warning(f"[C1.4] PoC 产物目录创建失败，跳过: {exc}")
        return []
    artifacts: List[Dict] = []
    used_names = set()
    for seq, (_idx, v) in enumerate(candidates):
        try:
            content, origin, ext = None, "b5_skeleton", "py"
            cve_poc = v.get("cve_poc")
            if isinstance(cve_poc, dict) and str(cve_poc.get("poc_script", "") or "").strip():
                content, origin = str(cve_poc["poc_script"]), "cve_index"
            if content is None:
                tpl = _poc_template_name(v)
                if tpl:
                    content = _run_poc_coro(_get_poc_generator().generate(dict(v)))
                    origin = "template:" + tpl
                    ext = "html" if tpl.endswith(".html.j2") else "py"
            if not content or not str(content).strip():
                content = _build_poc_python(v)
            stem = _safe_poc_stem(seq, v)
            fname, k = f"{stem}.{ext}", 1
            while fname in used_names:
                k += 1
                fname = f"{stem}_{k}.{ext}"
            used_names.add(fname)
            with open(os.path.join(poc_dir, fname), "w", encoding="utf-8") as f:
                f.write(str(content))
            rel = f"poc/{fname}"
            v["poc_file"] = rel
            v["poc_origin"] = origin
            artifacts.append({
                "file": rel, "type": str(v.get("type", "")),
                "severity": str(v.get("severity", "")), "origin": origin,
            })
        except Exception as exc:  # noqa: BLE001
            logger.debug(f"[C1.4] PoC 产物生成跳过（{v.get('type', '')}）: {exc}")
    if artifacts:
        report_data["poc_artifacts"] = artifacts
        logger.info(f"[C1.4] PoC 产物 {len(artifacts)} 份已落盘 {poc_dir}")
    return artifacts


def _render_poc_artifacts_section(report_data: Dict) -> str:
    """C1.4: HTML 报告中的 PoC 产物清单段（无产物返回空串）。"""
    arts = report_data.get("poc_artifacts") or []
    if not arts:
        return ""
    import html as html_escape
    rows = "".join(
        "<li><a href=\"%s\" download>%s</a> — %s <span style=\"color:#666;\">[%s]</span></li>" % (
            html_escape.escape(str(a.get("file", ""))),
            html_escape.escape(str(a.get("file", ""))),
            html_escape.escape(str(a.get("type", ""))),
            html_escape.escape(str(a.get("origin", ""))),
        ) for a in arts
    )
    return ('<div style="background:#f0f7ff;border:1px solid #c8dcf0;border-radius:8px;padding:12px;margin:16px 0;">'
            '<h3 style="margin:0 0 8px;">PoC 产物（C1.4，可运行脚本随报告交付）</h3>'
            '<ul style="margin:0;padding-left:18px;line-height:1.9;">%s</ul></div>') % rows


# ============================================================
# R2-A S2: 漏洞来源溯源可视化（source=param_mining / live:* ）
# 让"这条洞是从哪条采集/挖掘链路来的"在报告里一眼可见：
#   条目内徽标（单条溯源） + 列表后汇总段（各来源检出占比）。
# 无 source 字段的历史 finding 不渲染（向后兼容，零噪音）。
# ============================================================
_SOURCE_LABELS = {
    "param_mining": ("参数挖掘 D3.5", "#6f42c1"),
    "live:crawl": ("实时采集 · 爬虫", "#0d6efd"),
    "live:render": ("实时采集 · 渲染", "#0d6efd"),
    "live:burp": ("实时采集 · Burp", "#0d6efd"),
}
_SOURCE_COLORS = {"live": "#0d6efd"}


def _source_label(src: str) -> tuple:
    """来源串 → (中文标签, 颜色)。未登记来源按原样展示。"""
    src = str(src or "").strip()
    if src in _SOURCE_LABELS:
        return _SOURCE_LABELS[src]
    if src.startswith("live:"):
        chan = src.split(":", 1)[1]
        return f"实时采集 · {chan}", _SOURCE_COLORS["live"]
    return f"来源 {src}", "#6c757d"


def _source_badge(vuln: Dict) -> str:
    """单条 finding 的溯源徽标（无 source 字段返回空串）。"""
    import html as _html_escape
    src = str(vuln.get("source") or "").strip()
    if not src:
        return ""
    label, color = _source_label(src)
    return (f'<br><span style="display:inline-block;margin:4px 0;padding:2px 8px;'
            f'border-radius:10px;background:{color};color:#fff;font-size:12px;">'
            f'溯源: {_html_escape.escape(label)}</span>')


def _render_source_attribution_section(vulns: List[Dict]) -> str:
    """R2-A S2: 来源汇总段（各来源检出数与占比）。全部无 source 时返回空串。"""
    import html as _html_escape
    from collections import Counter
    counter: Counter = Counter()
    for v in vulns or []:
        src = str((v or {}).get("source") or "").strip()
        if src:
            counter[src] += 1
    if not counter:
        return ""
    total = sum(counter.values())
    rows = []
    for src, n in sorted(counter.items(), key=lambda kv: (-kv[1], kv[0])):
        label, color = _source_label(src)
        pct = round(n / total * 100, 1) if total else 0.0
        rows.append(
            f'<li><span style="display:inline-block;min-width:150px;">'
            f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;'
            f'background:{color};color:#fff;font-size:12px;">'
            f'{_html_escape.escape(label)}</span></span> '
            f'{n} 条（{pct}%）</li>')
    return ('<div style="background:#f8f9fa;border:1px solid #e2e6ea;border-radius:8px;'
            'padding:12px;margin:16px 0;">'
            '<h3 style="margin:0 0 8px;">溯源来源分布（S2）</h3>'
            '<p style="margin:0 0 8px;color:#666;font-size:13px;">'
            f'共 {total} 条发现带来源标记（参数挖掘 / 实时采集补测链路）</p>'
            '<ul style="margin:0;padding-left:18px;line-height:1.9;">'
            f'{"".join(rows)}</ul></div>')


# ============================================================
# B5/H2: SARIF 2.1.0 输出（持续集成/DevSecOps 消费）
# ============================================================
def generate_sarif(report_data: Dict, out_path: str = "") -> Dict:
    """把报告漏洞列表转换为 SARIF 2.1.0 JSON 结构，可写入 out_path（若提供）。"""
    import json as _json
    enrich_report(report_data)  # SP17.4：注入 distribution 与 remediation_tier
    rule_ids = {}
    sarif_rules = []
    results = []
    vulns = normalize_vulns(report_data.get("vulnerabilities", [])) or []
    for idx, v in enumerate(vulns[:200]):
        vtype = str(v.get("type", "Vulnerability") or "Vulnerability")
        if vtype not in rule_ids:
            rule_ids[vtype] = len(rule_ids) + 1
            sarif_rules.append({
                "id": "VULNCLAW-{:04d}".format(rule_ids[vtype]),
                "name": vtype,
                "shortDescription": {"text": vtype[:200]},
                "fullDescription": {"text": (v.get("description") or v.get("evidence") or "")[:500]},
                "help": {"text": (v.get("remediation") or "Please review and remediate.")[:500]},
                "properties": {"severity": str(v.get("severity", "Medium"))},
            })
        results.append({
            "ruleId": "VULNCLAW-{:04d}".format(rule_ids[vtype]),
            "level": _sarif_level(str(v.get("severity", "Medium"))),
            "message": {"text": str(v.get("evidence") or vtype)[:500]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(v.get("url", ""))},
                    "region": {"startLine": 1, "snippet": {"text": str(v.get("parameter") or v.get("payload") or "")[:200]}},
                }
            }],
            "properties": {"confidence": str(v.get("confidence", "") or ""),
                           "cvss": v.get("cvss", 0) or 0, "type": vtype,
                           # SP14.3: OOB 回调证据（平行字段，未触发 OOB 时为 None）
                           "oob_evidence": v.get("oob_evidence")},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "VULNCLAW", "version": "1.0",
                                "informationUri": "https://github.com/vulnclaw",
                                "rules": sarif_rules}},
            "results": results,
        }],
    }
    # SP4: E1 攻击图 -> SARIF 2.1.0 run.graphs + run.graphTraversals
    _ag_sarif = _sarif_graphs(report_data)
    if _ag_sarif and _ag_sarif.get("graphs"):
        sarif["runs"][0]["graphs"] = _ag_sarif["graphs"]
        if _ag_sarif.get("traversals"):
            sarif["runs"][0]["graphTraversals"] = _ag_sarif["traversals"]
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f:
            _json.dump(sarif, f, ensure_ascii=False, indent=2)
        logger.info("[SARIF] 已输出至 %s", out_path)
    return sarif


def _sarif_level(severity: str) -> str:
    sev = str(severity).lower()
    if sev in ("critical", "high"):
        return "error"
    if sev == "medium":
        return "warning"
    return "note"


def _sarif_graphs(report_data: dict) -> dict:
    """SP4: E1 攻击图 -> SARIF 2.1.0 run.graphs + graphTraversals。

    - run.graphs[]：攻击图（nodes:id/label；edges:id/sourceNodeId/targetNodeId/label）
    - run.graphTraversals[]：TOP 攻击路径的 edgeTraversals（graphIndex 引用 graphs[0]）
    离线可用（JSON 数据，不依赖 D3 CDN）；无攻击图数据时返回空结构。
    """
    ag = report_data.get("attack_graph") or {}
    nodes = ag.get("nodes") or []
    edges = ag.get("edges") or []
    if not nodes or not edges:
        return {"graphs": [], "traversals": []}
    sarif_nodes = [
        {"id": str(n.get("id")),
         "label": str(n.get("label") or n.get("type") or n.get("id"))}
        for n in nodes
    ]
    edge_id_by_pair = {}
    sarif_edges = []
    for e in edges or []:
        src, tgt = str(e.get("source")), str(e.get("target"))
        if not src or not tgt:
            continue
        eid = "e{}".format(len(sarif_edges))
        edge_id_by_pair[(src, tgt)] = eid
        sarif_edges.append({
            "id": eid, "sourceNodeId": src, "targetNodeId": tgt,
            "label": str(e.get("label") or ""),
        })
    graphs = [{"description": {"text": "E1 资产-漏洞-利用链攻击图"},
               "nodes": sarif_nodes, "edges": sarif_edges}]

    traversals = []
    for p in (report_data.get("attack_paths") or [])[:10]:
        ids = [str(x.get("id")) for x in (p.get("nodes") or [])]
        seq = []
        for i in range(len(ids) - 1):
            eid = edge_id_by_pair.get((ids[i], ids[i + 1]))
            if eid is None:
                seq = []
                break
            seq.append({"edgeId": eid})
        if not seq:
            continue
        traversals.append({
            "id": "t{}".format(len(traversals)),
            "graphIndex": 0,
            "description": {"text": "TOP path prob={} end={}".format(
                p.get("probability", 0), p.get("end_type", ""))},
            "edgeTraversals": seq,
        })
    return {"graphs": graphs, "traversals": traversals}


# ============================================================
# B5/H3: 代码级修复片段（按漏洞类型给最小加固示例）
# ============================================================
def build_fix_snippet(vuln: Dict) -> str:
    """B5/H3: 按漏洞类型返回可落地的代码级修复示例（文本片段，供报告展示）。"""
    vtype = str(vuln.get("type", "") or "").lower()
    code = _FIX_SNIPPETS.get("default")
    for key in _FIX_SNIPPETS:
        if key != "default" and key in vtype:
            code = _FIX_SNIPPETS[key]
            break
    if not code:
        code = _FIX_SNIPPETS["default"]
    return code


_FIX_SNIPPETS = {
    "sql": "# 参数化查询（禁止字符串拼接）\ncur = db.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
    "xss": "# 上下文输出编码 + CSP\n输出前 {{{{ value | escape }}}}；并设 CSP header: default-src 'self'",
    "ssrf": "def fetch(url):\n    if not is_allowlisted(hostname(url)): raise Blocked()\n    # 再发起请求",
    "cmdi": "import subprocess\nsubprocess.run([cmd, arg], shell=False)  # 不要 join + shell=True",
    "command_injection": "import subprocess\nsubprocess.run([cmd, arg], shell=False)",
    "lfi": "path = ALLOW_MAP.get(user_input, None)\nif not path: raise Blocked()\nopen(EXPAND(path), 'rb')",
    "文件": "ALLOW_MAP 白名单映射 + os.path.realpath 规范化，禁止直接拼接用户输入",
    "idor": "if obj.owner_id != current_user.id: raise PermissionDenied()\nreturn obj",
    "越权": "服务端逐资源校验 owner/ACL，勿信任前端传入的角色字段",
    "jwt": "验签算法白名单校验，禁止 alg:none；kid 仅允许白名单公钥；密钥高熵定期轮换",
    "oauth": "redirect_uri 必须与注册值精确匹配；校验 state；scope 最小化",
    "session": "登录成功后 session.regenerate_id(); Cookie.HttpsOnly + Secure + SameSite=Strict",
    "csrf": "<input type=hidden name=csrf value={{{{ csrf_token }}}}> + SameSite=Cookie",
    "xxe": "parser = lxml.etree.XMLParser(resolve_entities=False, no_network=True)",
    "deserialization": "对不可信输入禁用 native 反序列化，改用安全格式(如 JSON schema 校验)或加签名",
    "default": "# 依据具体漏洞类型，参考 OWASP ASVS / WSTG 给出针对性加固代码",
}



def _render_lifecycle_block(report: Dict) -> str:
    """SP10.3: 治理台账视角——按生命周期（新增/持续/已修复）分组渲染。无数据返回空串。"""
    import html as html_escape

    summary = (report or {}).get("lifecycle_summary") or {}
    if not summary:
        return ""
    groups = (report or {}).get("lifecycle_groups") or {}
    chips = ""
    for key, label, color in (("reconfirmed", "持续", "#fd7e14"),
                              ("new", "新增", "#dc3545"),
                              ("fixed", "已修复", "#2E7D32")):
        n = int(summary.get(key, 0) or 0)
        if n:
            chips += ('<span style="display:inline-block;margin:4px 8px 4px 0;padding:6px 14px;'
                      'background:%s;color:#fff;border-radius:20px;font-size:13px;">%s %d</span>') % (color, label, n)
    fixed_items = groups.get("fixed") or []
    fixed_html = ""
    if fixed_items:
        rows = []
        for v in fixed_items[:20]:
            rows.append("<li><code>%s</code> %s <span style='color:#666;'>%s</span></li>" % (
                html_escape.escape(str(v.get("type", ""))),
                html_escape.escape(str(v.get("url", ""))),
                html_escape.escape(str(v.get("severity", "")))))
        fixed_html = ('<div style="background:#f0f9f0;border:1px solid #c6e6c6;border-radius:8px;padding:12px;'
                      'margin-top:8px;"><h4 style="margin:0 0 8px;">已修复项（基线证据留存）</h4>'
                      '<ul style="margin:0;padding-left:18px;line-height:1.9;">%s</ul></div>') % "".join(rows)
    return ('<div style="background:#fff8f0;border:1px solid #f0d9c0;border-radius:8px;padding:12px;margin:16px 0;">'
            '<h3 style="margin:0 0 8px;">漏洞治理台账（SP10）</h3>%s%s</div>') % (chips, fixed_html)


# ============================================================
# B5/H4: 两次扫描结果 diff（新增/已修复/持续存在）
# ============================================================
def diff_reports(baseline: Dict, current: Dict) -> Dict:
    """对比两次扫描报告，输出新增 / 已修复 / 持续存在三类差异（含基线回归提示）。"""
    def keylist(data):
        out = {}
        for v in normalize_vulns((data or {}).get("vulnerabilities", []) or []):
            k = (str(v.get("url", "")), str(v.get("type", "")), str(v.get("parameter", "") or ""))
            out[k] = v
        return out
    old = keylist(baseline)
    new = keylist(current)
    old_keys = set(old)
    new_keys = set(new)
    added_keys = sorted(new_keys - old_keys)
    fixed_keys = sorted(old_keys - new_keys)
    common_keys = sorted(new_keys & old_keys)
    return {
        "added": [new[k] for k in added_keys],
        "fixed": [old[k] for k in fixed_keys],
        "unchanged": [old[k] for k in common_keys],
        "summary": {
            "baseline_total": len(old),
            "current_total": len(new),
            "added_count": len(added_keys),
            "fixed_count": len(fixed_keys),
            "still_count": len(common_keys),
        },
    }


__all__ = [
    "suggest_remediation",
    "build_distribution",
    "enrich_report",

    "generate_markdown_report",
    "generate_html_report",
    "render_html",
    "generate_sarif",
    "diff_reports",
    "_render_lifecycle_block",
    "build_fix_snippet",
    "_build_poc_python",
    "_build_curl_command",
    "generate_poc_artifacts",
]
