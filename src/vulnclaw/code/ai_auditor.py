# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 2 模块 4：AI 审计器。

使用 LLM 对 Semgrep/CodeQL 的原始发现进行二次审计：
1. 过滤误报（false positive suppression）
2. 生成 diff（修复建议）
3. 评估漏洞可利用性

集成 ai/core.py 的 LLMClient.ask()。
"""
import asyncio
import json
from typing import List, Dict, Tuple, Optional

from vulnclaw.core.logger import logger
from vulnclaw.ai.core import get_llm_client


class AIAuditor:
    """AI 漏洞审计器：LLM 二次过滤 + 修复建议。"""

    def __init__(self, batch_size: int = 5):
        """初始化 AI 审计器。

        Args:
            batch_size: 每批发送给 LLM 审计的发现数量。
        """
        self.batch_size = batch_size
        self._llm = get_llm_client()
        self._audited_count = 0
        self._filtered_count = 0
        self._diff_count = 0

    async def audit_findings(
        self, findings: List[Dict], source_code_map: Optional[Dict[str, str]] = None
    ) -> Tuple[List[Dict], List[Dict]]:
        """对扫描发现进行 AI 二次审计。

        Args:
            findings: 原始发现列表（来自 Semgrep/CodeQL）。
            source_code_map: 文件路径 → 源码内容映射（用于 LLM 获取上下文）。

        Returns:
            (filtered_findings, diffs) 元组：
            - filtered_findings: 过滤误报后的有效发现列表
            - diffs: 修复建议列表，每个包含 file / original / suggested_fix / explanation
        """
        if not findings:
            return [], []

        logger.info(f"🤖 [AIAuditor] 开始审计 {len(findings)} 个发现 (batch={self.batch_size})")

        filtered: List[Dict] = []
        diffs: List[Dict] = []

        # 分批审计
        for i in range(0, len(findings), self.batch_size):
            batch = findings[i : i + self.batch_size]
            batch_filtered, batch_diffs = await self._audit_batch(batch, source_code_map)
            filtered.extend(batch_filtered)
            diffs.extend(batch_diffs)

        self._audited_count = len(findings)
        self._filtered_count = len(findings) - len(filtered)
        self._diff_count = len(diffs)

        logger.info(
            f"✅ [AIAuditor] 审计完成: 原始={len(findings)} "
            f"有效={len(filtered)} 误报={self._filtered_count} 修复建议={len(diffs)}"
        )
        return filtered, diffs

    async def _audit_batch(
        self, batch: List[Dict], source_code_map: Optional[Dict[str, str]]
    ) -> Tuple[List[Dict], List[Dict]]:
        """审计一批发现。"""
        # 构建 LLM prompt
        prompt = self._build_audit_prompt(batch, source_code_map)

        try:
            response = await asyncio.wait_for(
                self._llm.ask(
                    prompt=prompt,
                    system="你是高级安全审计专家。分析以下代码扫描发现，判断是否为真实漏洞，"
                           "过滤误报，并为每个真实漏洞提供修复建议。必须返回 JSON 格式。",
                    temperature=0.1,
                    max_tokens=4096,
                    force_json=True,
                ),
                timeout=90.0,
            )

            return self._parse_audit_response(response, batch)

        except asyncio.TimeoutError:
            logger.warning("⚠️ [AIAuditor] LLM 审计超时，保留全部发现")
            return batch, []
        except Exception as exc:
            logger.warning(f"⚠️ [AIAuditor] LLM 审计异常: {exc}，保留全部发现")
            return batch, []

    def _build_audit_prompt(
        self, batch: List[Dict], source_code_map: Optional[Dict[str, str]]
    ) -> str:
        """构建审计 prompt。"""
        items = []
        for i, f in enumerate(batch):
            item = (
                f"--- 发现 #{i} ---\n"
                f"引擎: {f.get('engine', '?')}\n"
                f"规则: {f.get('rule_id', '?')}\n"
                f"文件: {f.get('file', '?')}:{f.get('line', 0)}\n"
                f"严重度: {f.get('severity', '?')}\n"
                f"消息: {f.get('message', '?')}\n"
                f"代码片段: {f.get('code_snippet', 'N/A')[:200]}\n"
                f"CWE: {f.get('cwe', 'N/A')}\n"
            )
            # 附加上下文代码
            if source_code_map and f.get("file") in source_code_map:
                lines = source_code_map[f["file"]].splitlines()
                start = max(0, f.get("line", 0) - 5)
                end = min(len(lines), f.get("end_line", f.get("line", 0)) + 5)
                context = "\n".join(f"  {start+j+1}: {lines[start+j]}" for j in range(end - start))
                item += f"上下文:\n{context}\n"
            items.append(item)

        return (
            f"以下是 {len(batch)} 个代码扫描发现。请逐个分析并返回 JSON：\n\n"
            f"{{\"results\": [{{\n"
            f"  \"index\": 0,\n"
            f"  \"is_true_positive\": true/false,\n"
            f"  \"confidence\": \"HIGH/MEDIUM/LOW\",\n"
            f"  \"reason\": \"判断理由\",\n"
            f"  \"suggested_fix\": \"修复代码（如有）\",\n"
            f"  \"fix_explanation\": \"修复说明\"\n"
            f"}}]}}\n\n"
            + "\n\n".join(items)
        )

    def _parse_audit_response(
        self, response: str, batch: List[Dict]
    ) -> Tuple[List[Dict], List[Dict]]:
        """解析 LLM 审计响应。"""
        filtered: List[Dict] = []
        diffs: List[Dict] = []

        try:
            if isinstance(response, dict):
                data = response
            else:
                data = json.loads(response)

            results = data.get("results", [])

            for result in results:
                idx = result.get("index", 0)
                if idx >= len(batch):
                    continue

                finding = batch[idx]
                is_tp = result.get("is_true_positive", True)

                if is_tp:
                    # 增强 finding
                    finding["ai_confidence"] = result.get("confidence", "MEDIUM")
                    finding["ai_reason"] = result.get("reason", "")
                    finding["ai_audited"] = True
                    filtered.append(finding)

                    # 生成 diff
                    if result.get("suggested_fix"):
                        diffs.append({
                            "file": finding.get("file", ""),
                            "line": finding.get("line", 0),
                            "original": finding.get("code_snippet", ""),
                            "suggested_fix": result.get("suggested_fix", ""),
                            "explanation": result.get("fix_explanation", ""),
                            "rule_id": finding.get("rule_id", ""),
                            "cwe": finding.get("cwe", ""),
                        })
                else:
                    logger.debug(
                        f"   [AIAuditor] 过滤误报: {finding.get('rule_id')} "
                        f"@ {finding.get('file')}:{finding.get('line')} - {result.get('reason', '')[:100]}"
                    )

        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            logger.warning(f"⚠️ [AIAuditor] LLM 响应解析失败: {exc}，保留全部发现")
            return batch, []

        return filtered, diffs

    def get_stats(self) -> Dict:
        """返回审计统计信息。"""
        return {
            "audited": self._audited_count,
            "filtered": self._filtered_count,
            "valid": self._audited_count - self._filtered_count,
            "diffs": self._diff_count,
        }
