# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 2 模块 2：Semgrep 适配器。

调用 semgrep CLI 对指定路径进行代码扫描，返回标准化 JSON。
标准化格式与 codeql_adapter 保持一致。
"""
import asyncio
import json
import os
from typing import List, Dict

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_tool_path


# --- 标准化漏洞数据模型 ---
# {
#     "id": "semgrep:python:sql-injection",
#     "engine": "semgrep",
#     "rule_id": "python.django.security.injection.sql.sql-injection",
#     "severity": "ERROR",          # ERROR / WARNING / INFO
#     "confidence": "HIGH",          # HIGH / MEDIUM / LOW
#     "file": "app/views.py",
#     "line": 42,
#     "column": 10,
#     "end_line": 45,
#     "message": "Possible SQL injection via string concatenation",
#     "code_snippet": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
#     "cwe": "CWE-89",
#     "owasp": "A03:2021-Injection"
# }


class SemgrepAdapter:
    """Semgrep 代码扫描适配器。"""

    def __init__(self, config: str = "auto", timeout: int = 300):
        """初始化 Semgrep 适配器。

        Args:
            config: Semgrep 规则集，auto 表示自动选择。可指定 "p/python" / "p/java" 等。
            timeout: 扫描超时时间（秒）。
        """
        self.config = config
        self.timeout = timeout
        self._semgrep_path = None

    def _get_semgrep_path(self) -> str:
        """获取 semgrep 可执行文件路径。"""
        if self._semgrep_path:
            return self._semgrep_path
        path = get_tool_path("semgrep") or "semgrep"
        self._semgrep_path = path
        return path

    async def scan(self, path: str, rules: str = None) -> List[Dict]:
        """执行 Semgrep 扫描。

        Args:
            path: 要扫描的代码目录路径。
            rules: 自定义规则集（覆盖 config），如 "p/python" / "p/owasp-top-ten"。

        Returns:
            标准化漏洞列表。

        Raises:
            RuntimeError: semgrep 未安装或扫描失败。
            asyncio.TimeoutError: 扫描超时。
        """
        semgrep = self._get_semgrep_path()
        rule_set = rules or self.config
        output_file = os.path.join(path, ".semgrep_results.json")

        cmd = [semgrep, "scan", "--json", "--output", output_file]
        if rule_set and rule_set != "auto":
            cmd.extend(["--config", rule_set])
        cmd.append(path)

        logger.info(f"🔍 [Semgrep] 开始扫描: {path} (rules={rule_set})")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )

            if process.returncode != 0:
                err = stderr.decode().strip()
                logger.warning(f"⚠️ [Semgrep] 扫描退出码={process.returncode}: {err[:200]}")
                # semgrep 非零退出码也可能有结果

            # 读取 JSON 结果
            if os.path.exists(output_file):
                raw = json.loads(open(output_file, "r", encoding="utf-8").read())
                findings = self._normalize(raw)
                logger.info(f"✅ [Semgrep] 扫描完成: {len(findings)} 个发现")
                return findings
            else:
                logger.warning("⚠️ [Semgrep] 结果文件不存在")
                return []

        except asyncio.TimeoutError:
            logger.error(f"❌ [Semgrep] 扫描超时 ({self.timeout}s)")
            raise
        except FileNotFoundError:
            raise RuntimeError("semgrep 未安装，请运行 pip install semgrep")
        finally:
            # 清理临时文件
            if os.path.exists(output_file):
                os.unlink(output_file)

    def _normalize(self, raw: Dict) -> List[Dict]:
        """将 Semgrep 原始 JSON 转为标准化漏洞格式。"""
        findings: List[Dict] = []
        for result in raw.get("results", []):
            check_id = result.get("check_id", "unknown")
            severity = result.get("extra", {}).get("severity", "INFO").upper()
            message = result.get("extra", {}).get("message", "")
            lines = result.get("extra", {}).get("lines", "")
            metadata = result.get("extra", {}).get("metadata", {})

            findings.append({
                "id": f"semgrep:{check_id}",
                "engine": "semgrep",
                "rule_id": check_id,
                "severity": severity,
                "confidence": self._map_confidence(severity),
                "file": result.get("path", ""),
                "line": result.get("start", {}).get("line", 0),
                "column": result.get("start", {}).get("col", 0),
                "end_line": result.get("end", {}).get("line", 0),
                "message": message,
                "code_snippet": lines.strip()[:500] if lines else "",
                "cwe": self._extract_cwe(metadata),
                "owasp": metadata.get("owasp", ""),
            })
        return findings

    def _map_confidence(self, severity: str) -> str:
        """Semgrep severity → 标准化 confidence。"""
        return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(severity, "LOW")

    def _extract_cwe(self, metadata: Dict) -> str:
        """从 metadata 中提取 CWE。"""
        cwe = metadata.get("cwe", metadata.get("CWE", ""))
        if isinstance(cwe, list) and cwe:
            return cwe[0]
        return str(cwe) if cwe else ""
