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
        "version": 1,
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
}


def get_prompt(pid: str) -> Dict[str, Any]:
    """取 prompt spec（不存在返回空 dict —— 调用方据此回退，不抛异常）。"""
    return _PROMPTS.get(pid) or {}


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
