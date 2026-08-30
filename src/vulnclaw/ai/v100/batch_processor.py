# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# ai/v100/batch_processor.py
"""
智能批处理器 - 将多个任务合并为单次AI调用
减少API调用次数，提高每次调用的价值
修复：
1. 批处理丢失基线上下文：在 Prompt 中包含 normal_response_snippet
2. 解析批量响应时保留原始任务上下文
3. 增加任务去重和相似度合并
"""

import json

from vulnclaw.core.logger import logger
from typing import Dict, List


class BatchProcessor:
    """
    批处理器
    - 合并同类任务
    - 减少API调用次数
    - 支持批量结果解析
    - 修复：保留基线上下文
    """

    def __init__(self, max_batch_size: int = 5):
        self.max_batch_size = max_batch_size
        self._batch_stats = {
            "total_tasks": 0,
            "batched_tasks": 0,
            "batches_created": 0,
            "api_calls_saved": 0
        }

    def merge_tasks(self, tasks: List[Dict]) -> List[Dict]:
        """
        合并同类任务为批量请求
        返回: 合并后的任务列表（普通任务 + 批量任务）
        """
        if not tasks:
            return []

        # 按任务类型和参数分组
        groups = {}
        for task in tasks:
            task_type = task.get("type", "unknown")
            param = task.get("param", "unknown")
            # 也按目标分组，避免不同目标的响应混淆
            target = task.get("target", "")
            key = f"{task_type}_{param}_{target}"

            if key not in groups:
                groups[key] = []
            groups[key].append(task)

        merged = []
        for key, group in groups.items():
            if len(group) <= 1:
                merged.extend(group)
            else:
                for i in range(0, len(group), self.max_batch_size):
                    batch = group[i:i + self.max_batch_size]
                    if len(batch) == 1:
                        merged.extend(batch)
                    else:
                        # 创建批量任务，保留所有任务的原始上下文
                        merged.append({
                            "type": "batch",
                            "sub_type": group[0].get("type", "unknown"),
                            "is_batch": True,
                            "tasks": batch,
                            "count": len(batch),
                            "priority": max(t.get("priority", 5) for t in batch),
                            "key": key,
                            # ===== 修复：保留目标信息 =====
                            "target": group[0].get("target", ""),
                            "param": group[0].get("param", ""),
                            # ===== 修复：保留原始任务ID用于结果回写 =====
                            "task_ids": [t.get("task_id", f"task_{i}") for i, t in enumerate(batch)]
                        })

                        self._batch_stats["batched_tasks"] += len(batch)
                        self._batch_stats["batches_created"] += 1
                        self._batch_stats["api_calls_saved"] += len(batch) - 1

        self._batch_stats["total_tasks"] = len(tasks)

        logger.debug(f"📦 批处理: {len(tasks)} 个任务 → {len(merged)} 个批次 (节省 {self._batch_stats['api_calls_saved']} 次API调用)")
        return merged

    def generate_batch_prompt(self, batch: Dict) -> str:
        """
        生成批量分析Prompt
        修复：包含正常响应片段，用于对比判断
        """
        tasks = batch.get("tasks", [])
        sub_type = batch.get("sub_type", "unknown")

        tasks_str = []
        for i, task in enumerate(tasks, 1):
            target = task.get("target", "")
            param = task.get("param", "")
            payload = task.get("payload", "")
            response_snippet = task.get("response_snippet", "")

            # ===== 修复：获取正常响应片段 =====
            normal_response = task.get("normal_response_snippet", "")

            tasks_str.append(f"【目标 {i}】")
            tasks_str.append(f"  - URL: {target}")
            tasks_str.append(f"  - 参数: {param}")
            if payload:
                tasks_str.append(f"  - Payload: {payload[:100]}...")
            if response_snippet:
                tasks_str.append(f"  - 攻击响应片段: {response_snippet[:300]}...")
            if normal_response:
                tasks_str.append(f"  - 正常响应片段: {normal_response[:300]}...")
                tasks_str.append("  - 请对比攻击响应和正常响应的差异")
            tasks_str.append("")

        prompt = f"""
你是一位渗透测试专家。请分析以下 {len(tasks)} 个{self._get_task_type_name(sub_type)}检测结果，判断每个是否存在漏洞。

{''.join(tasks_str)}

重要判断标准：
1. 如果提供了正常响应片段，请对比攻击响应与正常响应的差异
2. 如果攻击响应与正常响应几乎相同，很可能没有漏洞
3. 如果攻击响应包含错误信息、异常输出或敏感数据，可能存在漏洞
4. 对于时间盲注，如果没有响应时间数据，不要轻易判定为漏洞

输出JSON数组，每个元素对应一个目标，包含：
- index: 对应目标的编号（从1开始）
- has_vuln: true/false
- vuln_type: 漏洞类型名称（如果 has_vuln 为 true）
- confidence: "高"/"中"/"低"
- evidence: 证据描述
- severity: "Critical"/"High"/"Medium"/"Low"

只输出JSON数组，不要其他内容。
"""
        return prompt

    def parse_batch_response(self, response: str, batch: Dict) -> List[Dict]:
        """
        解析批量响应，返回各任务的结果
        修复：保留原始任务上下文
        """
        tasks = batch.get("tasks", [])
        results = []

        try:
            # 提取JSON数组
            import re
            match = re.search(r'\[.*\]', response, re.DOTALL)
            if not match:
                logger.warning("批量响应中未找到JSON数组，全部标记为未发现")
                return [{"task": task, "has_vuln": False, "index": i, "vuln_type": "未检测", "confidence": "低", "evidence": "批量响应解析失败"} for i, task in enumerate(tasks)]

            data = json.loads(match.group())

            if not isinstance(data, list):
                logger.warning("批量响应不是数组，全部标记为未发现")
                return [{"task": task, "has_vuln": False, "index": i, "vuln_type": "未检测", "confidence": "低", "evidence": "批量响应格式错误"} for i, task in enumerate(tasks)]

            # 映射结果
            result_map = {}
            for item in data:
                idx = item.get("index", 0)
                if idx is None or idx == 0:
                    # 尝试从原始顺序匹配
                    continue
                # 存储结果
                result_map[idx] = {
                    "task_idx": idx - 1,
                    "has_vuln": item.get("has_vuln", False),
                    "vuln_type": item.get("vuln_type", "未知"),
                    "confidence": item.get("confidence", "低"),
                    "evidence": item.get("evidence", ""),
                    "severity": item.get("severity", "Low")
                }

            # 按顺序生成结果
            for i, task in enumerate(tasks):
                idx = i + 1
                if idx in result_map:
                    result = result_map[idx]
                    results.append({
                        "task": task,
                        "has_vuln": result["has_vuln"],
                        "vuln_type": result["vuln_type"],
                        "confidence": result["confidence"],
                        "evidence": result["evidence"],
                        "severity": result["severity"],
                        "index": i
                    })
                else:
                    # 尝试从数据中按顺序匹配
                    found = False
                    for item in data:
                        if item.get("index") is None or item.get("index") == 0:
                            # 按顺序分配
                            if len(results) < len(data):
                                results.append({
                                    "task": task,
                                    "has_vuln": item.get("has_vuln", False),
                                    "vuln_type": item.get("vuln_type", "未知"),
                                    "confidence": item.get("confidence", "低"),
                                    "evidence": item.get("evidence", ""),
                                    "severity": item.get("severity", "Low"),
                                    "index": i
                                })
                                found = True
                                break
                    if not found:
                        # ===== 修复：保留原始任务，标记为未检测 =====
                        results.append({
                            "task": task,
                            "has_vuln": False,
                            "vuln_type": "未检测",
                            "confidence": "低",
                            "evidence": "批量响应中未包含此目标",
                            "severity": "Info",
                            "index": i
                        })

            return results

        except json.JSONDecodeError as e:
            logger.warning(f"批量响应解析失败: {e}")
            return [{"task": task, "has_vuln": False, "vuln_type": "解析失败", "confidence": "低", "evidence": str(e), "severity": "Info", "index": i} for i, task in enumerate(tasks)]
        except Exception as e:
            logger.warning(f"批量响应处理失败: {e}")
            return [{"task": task, "has_vuln": False, "vuln_type": "处理失败", "confidence": "低", "evidence": str(e), "severity": "Info", "index": i} for i, task in enumerate(tasks)]

    def _get_task_type_name(self, task_type: str) -> str:
        """获取任务类型中文名"""
        names = {
            "sqli": "SQL注入",
            "xss": "XSS跨站脚本",
            "lfi": "文件包含",
            "cmdi": "命令注入",
            "nosql": "NoSQL注入",
            "ssti": "模板注入",
            "ssrf": "SSRF",
            "xxe": "XXE",
            "idor": "IDOR越权",
            "jwt": "JWT",
            "oauth": "OAuth",
            "graphql": "GraphQL",
            "file_upload": "文件上传",
            "el_injection": "EL注入",
            "cors": "CORS",
            "security_headers": "安全头",
            "race_condition": "竞争条件",
            "open_redirect": "开放重定向",
            "crlf": "CRLF注入",
            "ldap": "LDAP注入",
            "host_header": "Host头注入",
            "info_leak": "信息泄露",
            "business_logic": "业务逻辑",
            "cache_poison": "缓存投毒",
            "session": "会话安全"
        }
        return names.get(task_type, task_type)

    def get_stats(self) -> Dict:
        """获取批处理统计"""
        return {
            **self._batch_stats,
            "save_ratio": f"{self._batch_stats['api_calls_saved'] / max(1, self._batch_stats['total_tasks']) * 100:.1f}%"
        }


__all__ = ['BatchProcessor']
