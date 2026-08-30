# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 2 模块 3：CodeQL 适配器。

调用 CodeQL CLI 对指定路径进行代码扫描，返回标准化 JSON。
标准化格式与 semgrep_adapter 保持一致。
"""
import asyncio
import json
import os
import tempfile
from typing import List, Dict

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_tool_path


class CodeQLAdapter:
    """CodeQL 代码扫描适配器。"""

    def __init__(self, language: str = "python", timeout: int = 600):
        """初始化 CodeQL 适配器。

        Args:
            language: 扫描语言（python / javascript / java / go 等）。
            timeout: 扫描超时时间（秒）。
        """
        self.language = language
        self.timeout = timeout
        self._codeql_path = None

    def _get_codeql_path(self) -> str:
        """获取 codeql 可执行文件路径。"""
        if self._codeql_path:
            return self._codeql_path
        path = get_tool_path("codeql") or "codeql"
        self._codeql_path = path
        return path

    async def scan(self, path: str, database: str = None) -> List[Dict]:
        """执行 CodeQL 扫描。

        流程：database create → database analyze → 解析 SARIF → 标准化。

        Args:
            path: 要扫描的代码目录路径。
            database: 已有的 CodeQL 数据库路径（跳过 create 步骤）。

        Returns:
            标准化漏洞列表。

        Raises:
            RuntimeError: codeql 未安装或扫描失败。
            asyncio.TimeoutError: 扫描超时。
        """
        codeql = self._get_codeql_path()
        tmp_dir = tempfile.mkdtemp(prefix="codeql_")

        try:
            # 1. 创建数据库（如果未提供）
            if database is None:
                db_path = os.path.join(tmp_dir, "db")
                await self._create_database(codeql, path, db_path)
            else:
                db_path = database

            # 2. 执行分析
            sarif_path = os.path.join(tmp_dir, "results.sarif")
            await self._analyze(codeql, db_path, sarif_path)

            # 3. 解析 SARIF 结果
            if os.path.exists(sarif_path):
                raw = json.loads(open(sarif_path, "r", encoding="utf-8").read())
                findings = self._normalize(raw)
                logger.info(f"✅ [CodeQL] 扫描完成: {len(findings)} 个发现")
                return findings
            else:
                logger.warning("⚠️ [CodeQL] SARIF 结果文件不存在")
                return []

        except asyncio.TimeoutError:
            logger.error(f"❌ [CodeQL] 扫描超时 ({self.timeout}s)")
            raise
        except FileNotFoundError:
            raise RuntimeError("codeql 未安装，请从 https://codeql.github.com/ 下载")
        finally:
            # 清理临时目录
            import shutil
            shutil.rmtree(tmp_dir, ignore_errors=True)

    async def _create_database(self, codeql: str, source: str, db_path: str) -> None:
        """创建 CodeQL 数据库。"""
        cmd = [
            codeql, "database", "create", db_path,
            "--language=" + self.language,
            "--source-root=" + source,
            "--overwrite",
        ]
        logger.info(f"🔍 [CodeQL] 创建数据库: {source} ({self.language})")

        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=self.timeout // 2
        )
        if process.returncode != 0:
            raise RuntimeError(
                f"CodeQL database create 失败: {stderr.decode().strip()[:300]}"
            )

    async def _analyze(self, codeql: str, db_path: str, sarif_path: str) -> None:
        """执行 CodeQL 分析。"""
        # 使用内置的安全查询套件
        query_suite = f"{self.language}-security-and-quality"
        cmd = [
            codeql, "database", "analyze", db_path,
            "--format=sarif-latest",
            f"--output={sarif_path}",
            query_suite,
        ]
        logger.info(f"🔍 [CodeQL] 执行分析: {query_suite}")

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
            logger.warning(f"⚠️ [CodeQL] 分析退出码={process.returncode}: {err[:200]}")

    def _normalize(self, sarif: Dict) -> List[Dict]:
        """将 SARIF 格式转为标准化漏洞列表。"""
        findings: List[Dict] = []
        for run in sarif.get("runs", []):
            rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules.get(rule_id, {})
                level = result.get("level", "note").upper()
                message = result.get("message", {}).get("text", "")
                loc = result.get("locations", [{}])[0].get("physicalLocation", {})
                region = loc.get("region", {})

                findings.append({
                    "id": f"codeql:{rule_id}",
                    "engine": "codeql",
                    "rule_id": rule_id,
                    "severity": self._map_severity(level),
                    "confidence": self._map_confidence(level),
                    "file": loc.get("artifactLocation", {}).get("uri", ""),
                    "line": region.get("startLine", 0),
                    "column": region.get("startColumn", 0),
                    "end_line": region.get("endLine", 0),
                    "message": message,
                    "code_snippet": result.get("partialFingerprints", {}).get("primaryLocationLineText", "")[:500],
                    "cwe": self._extract_cwe(rule),
                    "owasp": rule.get("properties", {}).get("owasp", ""),
                })
        return findings

    def _map_severity(self, level: str) -> str:
        """SARIF level → 标准化 severity。"""
        return {"ERROR": "ERROR", "WARNING": "WARNING", "NOTE": "INFO"}.get(level, "INFO")

    def _map_confidence(self, level: str) -> str:
        """SARIF level → 标准化 confidence。"""
        return {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}.get(level, "LOW")

    def _extract_cwe(self, rule: Dict) -> str:
        """从 CodeQL rule 中提取 CWE。"""
        tags = rule.get("properties", {}).get("tags", [])
        for tag in tags:
            if tag.startswith("cwe-") or tag.startswith("CWE-"):
                return tag.upper()
        return ""
