# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core/review_exporter.py
"""
人工审核清单导出模块
将 ScanContext 中收集的可疑线索导出为 JSON 和 HTML 片段
"""
import json
import time
from pathlib import Path
from vulnclaw.core.logger import logger
from vulnclaw.core.context import ScanContext
from typing import Dict

PRIORITY_LABELS = {
    'high': '🔴 高',
    'medium': '🟠 中',
    'low': '🟢 低'
}

PRIORITY_ORDER = {'high': 0, 'medium': 1, 'low': 2}


def export_review_manifest(scan_context: ScanContext, output_dir: str, target: str, report_data: Dict = None) -> Dict:
    """
    导出人工审核清单
    """
    clues = scan_context.get_review_clues_sorted()
    if not clues:
        logger.info("没有收集到任何可疑线索，跳过人工审核清单导出")
        return {"total_clues": 0, "clues": []}

    manifest = {
        'target': target,
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_clues': len(clues),
        'high_priority_count': sum(1 for c in clues if c['priority'] == 'high'),
        'medium_priority_count': sum(1 for c in clues if c['priority'] == 'medium'),
        'low_priority_count': sum(1 for c in clues if c['priority'] == 'low'),
        'clues': clues
    }

    output_path = Path(output_dir)
    try:
            output_path.mkdir(parents=True, exist_ok=True)
    except PermissionError:
            logger.warning(f"⚠️ 无权限创建目录: {output_path}，使用临时目录")
            import tempfile
            output_path = Path(tempfile.gettempdir()) / "review_exports"
            output_path.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace('https://', '').replace('http://', '').replace('/', '_')
    json_file = output_path / f"manual_review_{safe_target}_{int(time.time())}.json"
    with open(json_file, 'w', encoding='utf-8') as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    logger.info(f"📋 人工审核清单已保存至 {json_file}")

    html_snippet = _build_review_html(manifest)
    html_file = output_path / f"review_snippet_{safe_target}.html"
    with open(html_file, 'w', encoding='utf-8') as f:
        f.write(html_snippet)
    logger.info(f"📄 审核清单 HTML 片段已保存至 {html_file}")

    return manifest


def _build_review_html(manifest: Dict) -> str:
    """生成 HTML 片段（内部使用）"""
    lines = []
    lines.append('<div class="review-section">')
    lines.append(f'<h2>🧑‍💻 人工审核清单（共 {manifest["total_clues"]} 条）</h2>')
    lines.append('<p style="color:#666;">以下线索扫描器未能自动确认为漏洞，但具有较高可疑度，建议手动验证。</p>')

    for priority in ['high', 'medium', 'low']:
        clues = [c for c in manifest['clues'] if c['priority'] == priority]
        if not clues:
            continue
        label = PRIORITY_LABELS.get(priority, priority)
        lines.append(f'<h3>{label} 优先级（{len(clues)} 条）</h3>')
        lines.append('<ul style="list-style-type: none; padding-left: 0;">')
        for clue in clues:
            lines.append(f'''
            <li style="background:#f8f9fa; margin:8px 0; padding:12px; border-radius:6px; border-left:4px solid {_priority_color(priority)};">
                <div><strong>🔗 URL:</strong> <a href="{clue['url']}" target="_blank">{clue['url']}</a></div>
                <div><strong>📌 类型:</strong> {clue['type']}</div>
                <div><strong>📝 证据:</strong> {clue['evidence']}</div>
                <div><strong>💡 建议:</strong> {clue['suggestion']}</div>
                {_render_params(clue.get('params', {}))}
                {_render_raw(clue.get('raw', {}))}
                {_render_ai_guide(clue)}
            </li>
            ''')
        lines.append('</ul>')

    lines.append('</div>')
    return '\n'.join(lines)


def _priority_color(priority: str) -> str:
    return {'high': '#dc3545', 'medium': '#fd7e14', 'low': '#28a745'}.get(priority, '#6c757d')


def _render_params(params: dict) -> str:
    if not params:
        return ''
    items = ' '.join([f"<code>{k}={v}</code>" for k, v in params.items()])
    return f'<div><strong>📋 参数:</strong> {items}</div>'


def _render_raw(raw: dict) -> str:
    if not raw:
        return ''
    return f'<div style="font-size:12px;color:#888;">🔎 附加信息: {json.dumps(raw, ensure_ascii=False)[:100]}...</div>'


def _render_ai_guide(clue: dict) -> str:
    """渲染 AI 测试指南"""
    ai = clue.get('ai_analysis')
    if not ai:
        return ''
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


# ============================================================
# 对外接口
# ============================================================
def build_review_html(manifest: Dict) -> str:
    """
    生成人工审核清单的 HTML 片段（外部调用接口）
    """
    if not manifest or not manifest.get('clues'):
        return '<div class="review-section"><p>✅ 无可疑线索，无需人工审核。</p></div>'

    return _build_review_html(manifest)


__all__ = ['export_review_manifest', 'build_review_html']