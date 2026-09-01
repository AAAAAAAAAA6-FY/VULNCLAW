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
    """P2-5: 由 finding 字段生成可执行的 curl 复现命令。"""
    url = str(vuln.get("url", ""))
    param = str(vuln.get("parameter", "") or "")
    payload = str(vuln.get("payload", "") or vuln.get("attack_payload", "") or "")
    if param and payload:
        from urllib.parse import quote
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={quote(payload, safe='')}"
    else:
        target = url
    return f'curl -s -i "{target}"'


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


def generate_html_report(report_data, html_file="report.html"):
    """生成 HTML 报告 - 同步版本"""
    try:
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


def render_html(enhanced_report):
    """渲染 HTML 报告内容 - 修复：证据截断"""
    import html as html_escape

    target = enhanced_report.get('target', '')
    vulns = enhanced_report.get('vulnerabilities', [])
    vuln_count = len(vulns)
    critical = len([v for v in vulns if v.get('severity') == 'Critical'])
    high = len([v for v in vulns if v.get('severity') == 'High'])
    medium = len([v for v in vulns if v.get('severity') == 'Medium'])
    low = len([v for v in vulns if v.get('severity') == 'Low'])
    info = len([v for v in vulns if v.get('severity') == 'Info'])

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

        vuln_items_html.append(f'''
        <div class="vuln-item vuln-{sev_class}" data-severity="{sev_class}" data-type="{html_escape.escape(vuln_type_raw.lower())}">
            <strong>🔹 {vuln_type}</strong>
            <br>
            <span style="color:#666;">URL: </span><a href="{vuln_url}" target="_blank">{vuln_url}</a>
            <br>
            <span style="color:#666;">严重性: </span><strong>{vuln_severity}</strong>
            {f'<br><span style="color:#666;">参数: </span>{vuln_param}' if vuln_param else ''}
            {f'<br><span style="color:#666;">置信度: </span><strong>{vuln_confidence}</strong>' if vuln_confidence else ''}
            <br>
            <span style="color:#666;">证据: </span>
            <pre style="background:#f8f9fa; padding:8px; border-radius:4px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; max-height:300px; font-size:12px; margin:4px 0;">{evidence}</pre>
            <details style="margin-top:6px;">
                <summary style="cursor:pointer; color:#007bff;">🧪 复现步骤 / PoC</summary>
                <p style="margin:6px 0;"><strong>curl 命令:</strong></p>
                <pre style="background:#263238; color:#cddc39; padding:8px; border-radius:4px; overflow-x:auto; white-space:pre-wrap; word-wrap:break-word; font-size:12px; margin:4px 0;">{curl_cmd}</pre>
                <ol style="margin:6px 0;">{repro_html}</ol>
            </details>
            <details style="margin-top:6px;">
                <summary style="cursor:pointer; color:#007bff;">🛡️ 修复建议（{remediation["cwe"]} / {remediation["owasp"]}）</summary>
                <p style="margin:6px 0;">{html_escape.escape(remediation["fix"])}</p>
            </details>
        </div>
        ''')

    vuln_section = ''.join(vuln_items_html)
    if len(vulns) > 50:
        vuln_section += f'<p style="color:#666; font-style:italic;">... 共 {len(vulns)} 个漏洞，仅显示前 50 个。请查看 JSON 报告获取完整列表。</p>'

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
        </div>

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
    lines.append(f"# 渗透测试报告 - {report_data.get('target', 'Unknown')}")
    lines.append("")
    lines.append(f"**生成时间**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**目标**: {report_data.get('target', '')}")
    lines.append("")
    lines.append("## 概览统计")
    lines.append("")
    lines.append(f"- **子域名总数**: {len(report_data.get('subdomains', []))}")
    lines.append(f"- **存活资产**: {report_data.get('alive', 0)}")
    lines.append(f"- **漏洞总数**: {len(report_data.get('vulnerabilities', []))}")
    lines.append("")

    vulns = report_data.get("vulnerabilities", [])
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
            lines.append("---")
        if len(vulns) > 30:
            lines.append(f"\n... 共 {len(vulns)} 个漏洞，仅显示前 30 个。请查看 JSON 报告获取完整列表。")
    else:
        lines.append("✅ 未发现安全漏洞。")

    # A8.3：漏报率回归基线段（仅当 REGRESSION_BASELINE 设置）
    reg = _regression_block(report_data)
    if reg:
        lines.append(reg)
        logger.info(f"📊 [回归基线] {reg.strip().splitlines()[-1]}")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    logger.info(f"📄 Markdown 报告已保存至 {output_path}")


__all__ = [
    "generate_markdown_report",
    "generate_html_report",
    "render_html",
]
