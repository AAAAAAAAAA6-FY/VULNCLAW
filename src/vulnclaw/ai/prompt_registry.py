# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""AI Prompt 统一注册表（T12）。

背景：此前 verify / taskgen 的 prompt 是**散落在各 phase 里的字符串字面量**，
改一个字没有任何回归信号——误报率/召回率的漂移只能等全量扫描跑完才可能被察觉，
而且无法回答"这次改动到底影响了什么"。

收口后每个 prompt 带：
  - ``version``：内容变更必须 +1（可 diff、可回滚、可灰度）
  - ``system`` / ``params``：与模板同源，避免调用侧各写一套
  - ``samples``：样例回归集（输入 + 期望包含片段），改 prompt 后一键验证

设计取舍：
  - 只存模板与元数据，**不做 LLM 调用**（IO 留在 phases_*，注册表保持纯函数）
  - 占位符用 ``str.replace`` 而非 ``str.format``：prompt 里天然含 JSON 示例
    ``{"index": 0, ...}``，``format`` 会把 ``{`` 当占位符直接抛 KeyError
  - 迁移期模板文本**逐字保留**，只换引用不换内容 → 行为零变化
"""
import difflib
from typing import Any, Dict, List

# prompt id -> spec
_PROMPTS: Dict[str, Dict[str, Any]] = {
    "verify.cross_batch": {
        "version": "1.0",
        "description": "同 URL+参数下多引擎候选的批量证据型裁决"
                       "（phases_verify._verify_cross_batch）",
        "system": "只输出 JSON 数组，不要 Markdown 代码块。",
        "params": {"temperature": 0.1, "max_tokens": 1500},
        "template": (
            "你是 Web 漏洞证据型验证官。以下是同一 URL 与参数上多个检测引擎给出的漏洞候选，"
            "每候选附【证据包】与【probe 观测结果】。请逐条独立裁决，不受同组其他条目影响。\n"
            "\n"
            "【裁决规则】\n"
            "1. 反射/回显类漏洞：只有载荷回显（reflect=true）或明确响应差分才可 confirm；\n"
            "2. 无客观证据或 probe 缺失/失败（ok=false）：必须判 confirmed=false 且 confidence=low"
            "（证据不足）；\n"
            "3. 绝不猜测，宁可证据不足。\n\n"
            "{items}"
            "\n\n只输出 JSON 数组，不要任何解释性文字，格式：\n"
            '[{"index": 0, "confirmed": true, "confidence": "high", "reason": "证据式理由"}]\n'
            "confidence 只能是 high / medium / low。"
        ),
        "samples": [
            {
                "name": "结构完整性：规则段与 JSON 输出约束都必须保留",
                "vars": {"items": "    候选 0: sqli @ /a?x=1"},
                "expect_contains": [
                    "【裁决规则】",
                    "只输出 JSON 数组",
                    '"index": 0',
                    "confidence 只能是 high / medium / low。",
                    "    候选 0: sqli @ /a?x=1",
                ],
            },
            {
                "name": "证据不足规则不得被改写成「可猜测」",
                "vars": {"items": ""},
                "expect_contains": [
                    "ok=false",
                    "绝不猜测，宁可证据不足。",
                ],
            },
        ],
    },
    "verify.single_evidence": {
        "version": "1.0",
        "description": "单条候选的证据型裁决（phases_verify：证据包 + probe 观测）",
        "system": "",
        "params": {},
        "template": (
            "你是 Web 漏洞证据型验证官。你的唯一职责：基于下方【证据包】与【probe 观测结果】做客观裁决。\n"
            "\n"
            "【裁决规则】\n"
            "1. 反射/XSS 回显类漏洞：只有观测到载荷回显（reflect=true）或明确的"
            "状态/长度/内容差分才允许 confirm；\n"
            "2. 无任何客观证据，或 probe 观测缺失/失败（ok=false）：一律判\"证据不足\"，不得 confirm；\n"
            "3. 绝不猜测、绝不脑补；宁可\"证据不足\"也不误判。\n"
            "\n"
            "【证据包】\n{evidence_pack}\n"
            "\n"
            "【probe 观测结果】\n{probe_summary}\n"
            "\n"
            "请只回答问题并**仅输出一个 JSON 对象**（不要 markdown 代码块、不要额外文字）：\n"
            '{"confirmed": "是|否|证据不足", "confidence": "high|medium|low", '
            '"reason": "一条最有力的证据行", "evidence_ref": ["证据1", "证据2"], '
            '"curl_poc": "复现该判定的 curl 命令（单行可直接执行）"}\n'
            "规则：证据不足/无法构造 curl 时对应字段给空字符串或空数组，绝不编造。"
        ),
        "samples": [
            {
                "name": "证据包与 probe 两段都要注入，且保留 fail-closed 措辞",
                "vars": {"evidence_pack": "PACK_X", "probe_summary": "PROBE_X"},
                "expect_contains": [
                    "【证据包】\nPACK_X",
                    "【probe 观测结果】\nPROBE_X",
                    "ok=false",
                    "绝不猜测、绝不脑补",
                ],
            },
        ],
    },
    "verify.dedupe": {
        "version": "1.0",
        "description": "同类型+同 URL、仅参数不同的重复报告判定（phases_verify 去重）",
        "system": "",
        "params": {},
        "template": (
            "以下多条漏洞类型与 URL 相同、仅参数不同，请判断是否为同一个底层漏洞的重复报告。"
            "若是，返回需保留的唯一条目下标 JSON 数组（如 [0]）；若不是同一漏洞返回 []。\n"
            "{summary}"
        ),
        "samples": [
            {
                "name": "条目摘要必须注入，且保留下标数组的输出格式约束",
                "vars": {"summary": "[0] param=id sev=High"},
                "expect_contains": [
                    "重复报告",
                    "[0] param=id sev=High",
                    "返回 []",
                ],
            },
        ],
    },
    "strategic.plan_llm": {
        "version": "1.0",
        "description": "战略层 LLM 增强：按侦察情报产出高价值路径 Top-N"
                       "（decision_layers.strategic_plan_llm）",
        "system": "只输出 JSON。",
        "params": {"temperature": 0.1, "max_tokens": 500},
        "template": (
            "你是渗透测试战略规划器。根据侦察信息，给出下一步最值得优先测试的"
            "路径列表（最多 10 条，按价值排序）。\n"
            "技术栈: {tech}\n端口: {ports}\n已发现漏洞: {vulns}\n"
            "只输出 JSON：{\"targets\": [{\"path\": \"/xxx\", \"reason\": \"...\"}]}"
        ),
        "samples": [
            {
                "name": "技术栈/端口/已发现漏洞三段都要注入，且保留 JSON 输出约束",
                "vars": {"tech": "PHP/7.4", "ports": "80,443", "vulns": "sqli@http://x/a"},
                "expect_contains": [
                    "技术栈: PHP/7.4",
                    "端口: 80,443",
                    "已发现漏洞: sqli@http://x/a",
                    "只输出 JSON",
                    "最多 10 条",
                ],
            },
        ],
    },
}


# 审计：本次进程内实际渲染过的 prompt (key -> version)。注册表保持纯函数，
# 仅此处维护"哪些版本被用过"的可追溯记录，供扫描报告挂载 prompt_versions。
_USED: Dict[str, str] = {}


def get_prompt(pid: str) -> Dict[str, Any]:
    """取 prompt spec（不存在返回空 dict —— 调用方据此回退，不抛异常）。"""
    return _PROMPTS.get(pid) or {}


def get_version(pid: str) -> str:
    """取 prompt 注册的语义化版本（major.minor）。未注册返回 ""（fail-open）。"""
    spec = _PROMPTS.get(pid)
    return str(spec.get("version") or "") if spec else ""


def used_versions() -> List[Dict[str, str]]:
    """本次进程内实际渲染过的 prompt 清单 ``[{key, version}, ...]``，供审计/报告。

    读取失败一律返回空列表（写/读失败静默降级，绝不打断报告链路）。
    """
    try:
        return [{"key": pid, "version": ver}
                for pid, ver in _USED.items() if pid]
    except Exception:  # noqa: BLE001 - 审计字段降级
        return []


def reset_used() -> None:
    """清空已用记录（测试隔离；生产单进程单扫描天然自洽）。"""
    _USED.clear()


def list_prompts() -> List[Dict[str, Any]]:
    """列出全部已注册 prompt（id / version / 样例数），供审计与报表。"""
    return [
        {"id": pid,
         "version": s.get("version"),
         "description": s.get("description", ""),
         "samples": len(s.get("samples") or [])}
        for pid, s in _PROMPTS.items()
    ]


def render(pid: str, **kwargs: Any) -> str:
    """渲染 prompt 模板（占位符用 replace，不解析 JSON 花括号）。

    未注册的 id 返回空串 —— 调用方应保留原字面量兜底，避免注册表缺失
    直接打断扫描链路。
    """
    spec = _PROMPTS.get(pid)
    if not spec:
        return ""
    try:
        _USED[pid] = str(spec.get("version") or "")
    except Exception:  # noqa: BLE001 - 审计记录失败静默降级，不影响渲染
        pass
    text = str(spec.get("template") or "")
    for key, val in kwargs.items():
        text = text.replace("{" + str(key) + "}", str(val))
    return text


def _render_with(text: str, sample: Dict[str, Any]) -> str:
    """按样例变量渲染一段文本（与 render 同口径：replace 而非 format）。"""
    out = text
    for key, val in (sample.get("vars") or {}).items():
        out = out.replace("{" + str(key) + "}", str(val))
    return out


def run_regression(pid: str, text: str = None) -> Dict[str, Any]:
    """跑某 prompt 的样例回归集。

    Args:
        pid: prompt id。
        text: 待评估文本；留空则用注册表当前版本。

    Returns:
        ``{prompt_id, version, total, passed, failed, cases}``
    """
    spec = _PROMPTS.get(pid)
    if not spec:
        return {"prompt_id": pid, "ok": False, "error": "unknown_prompt",
                "total": 0, "passed": 0, "failed": 0, "cases": []}
    base = text if text is not None else str(spec.get("template") or "")
    cases = []
    for s in (spec.get("samples") or []):
        rendered = _render_with(base, s)
        missing = [e for e in (s.get("expect_contains") or []) if e not in rendered]
        cases.append({"name": s.get("name", ""), "ok": not missing,
                      "missing": missing})
    passed = sum(1 for c in cases if c["ok"])
    return {
        "prompt_id": pid,
        "version": spec.get("version"),
        "total": len(cases),
        "passed": passed,
        "failed": len(cases) - passed,
        "cases": cases,
    }


def prompt_diff(pid: str, new_text: str) -> Dict[str, Any]:
    """T12 验收物：改 prompt 后一键出效果 diff。

    一次给出三件事：
      ① 文本级 unified diff（改了哪几行）
      ② 改动前 / 后各自的样例回归通过数
      ③ 回归增量 ``regression_delta`` —— **小于 0 即"这次改动打挂了样例"，
         应阻断合入**（把"改 prompt 靠感觉"变成有门禁的变更）
    """
    spec = _PROMPTS.get(pid) or {}
    old_text = str(spec.get("template") or "")
    before = run_regression(pid, old_text)
    after = run_regression(pid, new_text)
    diff = list(difflib.unified_diff(
        old_text.splitlines(), str(new_text or "").splitlines(),
        fromfile=f"{pid}@v{spec.get('version')}",
        tofile=f"{pid}@candidate",
        lineterm="", n=1,
    ))
    return {
        "prompt_id": pid,
        "registered_version": spec.get("version"),
        "text_changed": old_text != str(new_text or ""),
        "unified_diff": diff,
        "before": before,
        "after": after,
        "regression_delta": after["passed"] - before["passed"],
    }
