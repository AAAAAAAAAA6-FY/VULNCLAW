# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 2 模块 5：依赖扫描器。

扫描项目的依赖文件（requirements.txt / package.json / pom.xml 等），
检查已知漏洞（CVE）。
"""
import asyncio
import json
import os
from typing import List, Dict

from vulnclaw.core.logger import logger
from vulnclaw.core.utils import get_tool_path


# --- 支持的依赖文件模式 ---
DEPENDENCY_FILES = {
    "python": ["requirements.txt", "Pipfile", "Pipfile.lock", "poetry.lock", "setup.py"],
    "nodejs": ["package.json", "package-lock.json", "yarn.lock"],
    "java": ["pom.xml", "build.gradle", "build.gradle.kts"],
    "go": ["go.mod", "go.sum"],
    "ruby": ["Gemfile", "Gemfile.lock"],
}


class DependencyScanner:
    """依赖漏洞扫描器。"""

    def __init__(self, timeout: int = 120):
        """初始化依赖扫描器。

        Args:
            timeout: 扫描超时时间（秒）。
        """
        self.timeout = timeout

    async def audit_dependencies(self, path: str) -> List[Dict]:
        """扫描项目依赖中的已知漏洞。

        流程：
        1. 检测项目语言和依赖文件
        2. 调用对应工具（pip-audit / npm audit / dependency-check）
        3. 标准化结果

        Args:
            path: 项目根目录路径。

        Returns:
            标准化漏洞列表：
            [{
                "id": "CVE-2024-12345",
                "engine": "dependency",
                "package": "requests",
                "installed_version": "2.20.0",
                "fixed_version": "2.31.0",
                "severity": "HIGH",
                "confidence": "HIGH",
                "cwe": "CWE-89",
                "description": "SQL injection in requests...",
                "ecosystem": "pip"
            }]
        """
        logger.info(f"📦 [DependencyScanner] 扫描依赖: {path}")

        # 1. 检测依赖文件
        dep_files = self._detect_dependency_files(path)
        if not dep_files:
            logger.info("ℹ️ [DependencyScanner] 未找到依赖文件，跳过")
            return []

        # 2. 根据语言选择扫描工具
        all_findings: List[Dict] = []
        for language, files in dep_files.items():
            if language == "python":
                findings = await self._scan_python(path, files)
            elif language == "nodejs":
                findings = await self._scan_nodejs(path, files)
            elif language == "java":
                findings = await self._scan_java(path, files)
            elif language == "go":
                findings = await self._scan_go(path, files)
            else:
                logger.debug(f"   [DependencyScanner] {language} 暂不支持自动扫描")
                continue
            all_findings.extend(findings)

        logger.info(f"✅ [DependencyScanner] 扫描完成: {len(all_findings)} 个漏洞")
        return all_findings

    def _detect_dependency_files(self, path: str) -> Dict[str, List[str]]:
        """检测项目中的依赖文件。"""
        detected: Dict[str, List[str]] = {}
        for language, patterns in DEPENDENCY_FILES.items():
            found = []
            for pattern in patterns:
                full = os.path.join(path, pattern)
                if os.path.exists(full):
                    found.append(full)
            if found:
                detected[language] = found
                logger.debug(f"   [DependencyScanner] 检测到 {language}: {found}")
        return detected

    async def _scan_python(self, path: str, files: List[str]) -> List[Dict]:
        """使用 pip-audit 扫描 Python 依赖。"""
        pip_audit = get_tool_path("pip-audit") or "pip-audit"
        req_file = next((f for f in files if f.endswith("requirements.txt")), None)

        if not req_file:
            logger.debug("   [DependencyScanner] Python: 无 requirements.txt，跳过")
            return []

        cmd = [pip_audit, "-r", req_file, "-f", "json"]
        return await self._run_tool(cmd, "pip-audit", self._normalize_pip_audit)

    async def _scan_nodejs(self, path: str, files: List[str]) -> List[Dict]:
        """使用 npm audit 扫描 Node.js 依赖。"""
        npm = get_tool_path("npm") or "npm"
        cmd = [npm, "audit", "--json"]
        return await self._run_tool(cmd, "npm-audit", self._normalize_npm_audit, cwd=path)

    async def _scan_java(self, path: str, files: List[str]) -> List[Dict]:
        """使用 dependency-check 扫描 Java 依赖。"""
        dep_check = get_tool_path("dependency-check") or "dependency-check"
        cmd = [dep_check, "--project", "scan", "--scan", path, "--format", "JSON", "--out", "-"]
        return await self._run_tool(cmd, "dependency-check", self._normalize_dep_check)

    async def _scan_go(self, path: str, files: List[str]) -> List[Dict]:
        """使用 govulncheck 扫描 Go 依赖。"""
        govuln = get_tool_path("govulncheck") or "govulncheck"
        cmd = [govuln, "-json", "./..."]
        return await self._run_tool(cmd, "govulncheck", self._normalize_govulncheck, cwd=path)

    async def _run_tool(
        self,
        cmd: List[str],
        tool_name: str,
        normalizer: callable,
        cwd: str = None,
    ) -> List[Dict]:
        """执行扫描工具并标准化结果。"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=self.timeout
            )

            if process.returncode != 0 and not stdout:
                logger.warning(
                    f"⚠️ [DependencyScanner] {tool_name} 失败 (exit={process.returncode}): "
                    f"{stderr.decode().strip()[:200]}"
                )
                return []

            raw_output = stdout.decode().strip()
            if not raw_output:
                return []

            try:
                raw_json = json.loads(raw_output)
            except json.JSONDecodeError:
                logger.warning(f"⚠️ [DependencyScanner] {tool_name} 输出非 JSON")
                return []

            return normalizer(raw_json)

        except asyncio.TimeoutError:
            logger.warning(f"⚠️ [DependencyScanner] {tool_name} 超时 ({self.timeout}s)")
            return []
        except FileNotFoundError:
            logger.warning(f"⚠️ [DependencyScanner] {tool_name} 未安装，跳过")
            return []

    def _normalize_pip_audit(self, raw: Dict) -> List[Dict]:
        """标准化 pip-audit 输出。"""
        findings: List[Dict] = []
        for dep in raw.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                findings.append({
                    "id": vuln.get("id", "unknown"),
                    "engine": "dependency",
                    "package": dep.get("name", ""),
                    "installed_version": dep.get("version", ""),
                    "fixed_version": ", ".join(vuln.get("fix_versions", [])),
                    "severity": self._map_severity(vuln.get("severity", "")),
                    "confidence": "HIGH",
                    "cwe": ", ".join(vuln.get("cwe_ids", [])),
                    "description": vuln.get("description", "")[:300],
                    "ecosystem": "pip",
                })
        return findings

    def _normalize_npm_audit(self, raw: Dict) -> List[Dict]:
        """标准化 npm audit 输出。"""
        findings: List[Dict] = []
        for vuln_id, vuln in raw.get("vulnerabilities", {}).items():
            findings.append({
                "id": vuln_id,
                "engine": "dependency",
                "package": vuln.get("name", ""),
                "installed_version": vuln.get("range", ""),
                "fixed_version": vuln.get("fixAvailable", {}).get("version", "") if isinstance(vuln.get("fixAvailable"), dict) else "",
                "severity": vuln.get("severity", "info").upper(),
                "confidence": "HIGH",
                "cwe": "",
                "description": f"npm vulnerability: {vuln_id}",
                "ecosystem": "npm",
            })
        return findings

    def _normalize_dep_check(self, raw: Dict) -> List[Dict]:
        """标准化 dependency-check 输出。"""
        findings: List[Dict] = []
        for dep in raw.get("dependencies", []):
            for vuln in dep.get("vulnerabilities", []):
                findings.append({
                    "id": vuln.get("cve", "unknown"),
                    "engine": "dependency",
                    "package": dep.get("fileName", ""),
                    "installed_version": dep.get("version", ""),
                    "fixed_version": vuln.get("fixedVersion", ""),
                    "severity": vuln.get("severity", "INFO").upper(),
                    "confidence": "HIGH",
                    "cwe": vuln.get("cwe", ""),
                    "description": vuln.get("description", "")[:300],
                    "ecosystem": "maven",
                })
        return findings

    def _normalize_govulncheck(self, raw: Dict) -> List[Dict]:
        """标准化 govulncheck 输出。"""
        findings: List[Dict] = []
        for vuln in raw.get("vulns", []):
            findings.append({
                "id": vuln.get("id", "unknown"),
                "engine": "dependency",
                "package": vuln.get("module", ""),
                "installed_version": vuln.get("version", ""),
                "fixed_version": vuln.get("fixed", ""),
                "severity": "HIGH" if vuln.get("fixed") else "MEDIUM",
                "confidence": "HIGH",
                "cwe": "",
                "description": vuln.get("details", "")[:300],
                "ecosystem": "go",
            })
        return findings

    def _map_severity(self, severity: str) -> str:
        """映射严重度。"""
        s = severity.lower()
        if s in ("critical", "high"):
            return "HIGH"
        elif s in ("moderate", "medium"):
            return "MEDIUM"
        return "LOW"
