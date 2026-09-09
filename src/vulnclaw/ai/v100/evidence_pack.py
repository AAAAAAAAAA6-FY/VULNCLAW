# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""A 方案: EvidencePack 证据打包器——把 finding 的可消费证据组装成结构化文本喂 AI。

职责（候选生成器 + 带证验证大脑的分层核心）：
  1. 从 finding 聚合所有可用字段（类型/URL/参数/载荷/引擎标志/响应证据/回显/OOB）；
  2. 智能截断：剥长 base64 块与 <script> 块，保留响应头 + 特征关键词附近窗口；
  3. 渲染 probe 观测结果（基线 vs 载荷的客观信号），供 AI 基于证据裁决而非猜测。
所有输出为纯字符串，无副作用；任何异常都不上抛（fail-closed：宁可少喂不可喂错）。
"""
import re
import time

EVIDENCE_PACK_MAX_CHARS = 3000   # 单候选 token 预算（字符）
RESP_HEAD_KEEP = 2000            # 响应体头部保留字符数
KEYWORD_WINDOW = 300             # 特征关键词两侧窗口

# 特征关键词：命中后保留关键词附近窗口（帮助 AI 快速看到报错/回显点）
_HIT_MARKERS = (
    "syntax", "root:", "uid=", "<script", "onerror", "{{", "127.0.0.1",
    "169.254.169.254", "etc/passwd", "sqlstate", "ora-", "near \"", "no such",
)

# 长 base64 块（>=64 字符连续 base64），整体替换避免烧 token
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{64,}(?:={0,2})")
# 完整 <script>…</script> 块
_SCRIPT_RE = re.compile(r"<script\b[^>]*>.*?</script>", re.S | re.I)


def _strip_bloat(text: str) -> str:
    """剥掉大体积噪音：长 base64 块与 <script> 块整体替换为短标记。

    base64 判断要求块内 unique 字符 >=4（真实 base64 通常混合大小写/数字，
    纯单字符长串如 'AAAAA...' 不属于 base64，保留原样避免误伤）。
    """

    def _b64_sub(m):
        block = m.group(0)
        if len(set(block)) < 4:  # 字数过度集中 → 非 base64，保原文
            return block
        return f"[base64 块, {len(block)} 字节]"

    out = _BASE64_RE.sub(_b64_sub, str(text or ""))
    out = _SCRIPT_RE.sub("[JS 块, 已裁剪]", out)
    return out.strip()


def _smart_truncate(text: str, budget: int = RESP_HEAD_KEEP, markers: tuple = ()) -> str:
    """智能截断：剥噪音 → 保留头部 → 若命中特征关键词保留其附近窗口，中间省略。"""
    t = _strip_bloat(str(text or ""))
    if len(t) <= budget:
        return t
    marks = tuple(markers) or _HIT_MARKERS
    low = t.lower()
    best = None
    for m in marks:
        idx = low.find(m.lower())
        if idx >= 0:
            best = (idx, m)
            break
    if best is None:
        return t[:budget]
    idx, _m = best
    half = KEYWORD_WINDOW // 2
    start = max(0, min(idx - half, len(t) - budget))
    window = t[start:start + budget]
    prefix = "…[省略 %d 字符]…" % start
    if len(prefix) + len(window) > budget:
        window = window[:budget - len(prefix)]
    return prefix + window


def _probe_summary(probe: dict | None) -> str:
    """渲染 probe 观测为一行客观信号摘要。probe 缺失/失败一律输出弱信号标记。"""
    if not isinstance(probe, dict) or probe.get("ok") is not True:
        return "probe 观测缺失/失败（fail-closed：无客观信号，禁止 confirm）"
    lines = []
    lines.append(f"base_status={probe.get('base_status')} attack_status={probe.get('attack_status')}")
    lines.append(f"payload_reflect={probe.get('reflect')} status_shift={probe.get('status_shift')}")
    if probe.get("len_diff") is not None:
        lines.append(f"len_diff={probe.get('len_diff'):.2%}")
    if probe.get("duration_diff") is not None:
        lines.append(f"duration_diff={probe.get('duration_diff'):.2f}s")
    return " | ".join(lines)


def _oracle_summary(diff: dict | None) -> str:
    """渲染双会话差分观测为一行客观信号摘要（B 方案）。缺失/失败 → 弱信号标记（fail-closed）。"""
    if not isinstance(diff, dict) or diff.get("ok") is not True:
        return "无 oracle 差分观测（fail-closed：无差分证据，禁止 confirm 越权）"
    ident = "匿名" if diff.get("anon") else "第二账号"
    parts = [f"身份B（{ident}）请求: 状态={diff.get('b_status')}"]
    if diff.get("b_blocked"):
        parts.append("身份B被拦(auth_enforced)")
    elif diff.get("b_private"):
        parts.append("私有标记=" + ",".join(sorted(diff.get("b_private", {}).keys())))
        parts.append(f"body_sim={diff.get('body_sim')}")
    else:
        parts.append(f"body_sim={diff.get('body_sim')}")
    return " | ".join(parts)


def build_evidence_pack(vuln: dict, probe: dict | None = None) -> str:
    """组装结构化证据包文本。任何字段缺失渲染（无），保证 prompt 结构稳定。"""
    sec = []
    sec.append("【漏洞候选】")
    sec.append(
        f"  type={vuln.get('type', '?')} | severity={vuln.get('severity', '?')} | "
        f"method={vuln.get('method', '?')}"
    )
    sec.append(f"  url={vuln.get('url', '')} | param={vuln.get('parameter') or vuln.get('param', '')}")
    if vuln.get("payload"):
        sec.append(f"  payload={str(vuln.get('payload', ''))[:200]}")

    sec.append("【引擎判定】")
    sec.append(
        f"  ai_verdict={vuln.get('ai_verdict', '（无）')} | "
        f"confidence={vuln.get('confidence', '（无）')} | "
        f"verification_method={vuln.get('verification_method', '（无）')}"
    )

    flags = {}
    for k in ("dir_listing", "file_read", "base64_encoded", "cmd_exec", "time_verified",
              "deser_confirmed", "has_response_diff", "technical_confirmed", "oob_confirmed",
              "exploited", "browser_verified"):
        flags[k] = vuln.get(k)
    _fas = [k for k, v in flags.items() if v]
    sec.append("【引擎结构化标志】")
    sec.append("  " + (", ".join(_fas) if _fas else "（无）"))

    if vuln.get("response_preview"):
        sec.append("【响应证据】")
        sec.append("  " + str(vuln["response_preview"])[:2000])

    if vuln.get("chain_info"):
        ci = vuln.get("chain_info") if isinstance(vuln.get("chain_info"), dict) else {}
        if ci.get("http_status") not in (None, "", 0):
            sec.append("【链路信息】")
            sec.append(f"  http_status={ci.get('http_status')} | echo_feature={ci.get('echo_feature')}")

    sec.append("【证据原文】")
    ev = str(vuln.get("evidence", "") or "")
    sec.append("  " + _smart_truncate(ev, budget=1400) if ev else "  （无）")

    sec.append("【probe 观测结果】")
    sec.append("  " + _probe_summary(probe))

    sec.append("【oracle 差分观测】")
    sec.append("  " + _oracle_summary(vuln.get("oracle_diff")))

    out = "\n".join(sec)
    if len(out) > EVIDENCE_PACK_MAX_CHARS:
        out = out[:EVIDENCE_PACK_MAX_CHARS] + "\n…[证据包超出预算已截断]…"
    return out


__all__ = ["build_evidence_pack", "_smart_truncate", "_strip_bloat", "_probe_summary",
           "EVIDENCE_PACK_MAX_CHARS"]
