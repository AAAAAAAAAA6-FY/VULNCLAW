# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 3 模块 4：POC 生成器。

使用 Jinja2 模板为不同漏洞类型生成可执行的 POC 脚本。
模板位于 deepsec/templates/ 目录。

支持的模板：
- sqli.py.j2    → Python SQL 注入 POC
- lfi.py.j2     → Python LFI POC
- rce.py.j2     → Python RCE POC
- xss.html.j2   → HTML XSS POC
"""
from pathlib import Path

from vulnclaw.core.logger import logger
from typing import Dict, Optional


# --- 模板目录 ---
TEMPLATES_DIR = Path(__file__).parent / "templates"

# --- 漏洞类型 → 模板映射 ---
TEMPLATE_MAP = {
    "sqli": "sqli.py.j2",
    "sql_injection": "sqli.py.j2",
    "lfi": "lfi.py.j2",
    "file_inclusion": "lfi.py.j2",
    "path_traversal": "lfi.py.j2",
    "rce": "rce.py.j2",
    "command_injection": "rce.py.j2",
    "code_execution": "rce.py.j2",
    "xss": "xss.html.j2",
    "cross_site_scripting": "xss.html.j2",
}


class POCGenerator:
    """POC 脚本生成器。

    使用 Jinja2 模板引擎渲染 POC 脚本。
    """

    def __init__(self, templates_dir: Optional[str] = None):
        """初始化 POC 生成器。

        Args:
            templates_dir: 自定义模板目录（默认使用 deepsec/templates/）。
        """
        self.templates_dir = Path(templates_dir) if templates_dir else TEMPLATES_DIR
        self._jinja_env = None
        self._init_jinja()

    def _init_jinja(self) -> None:
        """初始化 Jinja2 环境。"""
        try:
            from jinja2 import Environment, FileSystemLoader
            self._jinja_env = Environment(
                loader=FileSystemLoader(str(self.templates_dir)),
                autoescape=False,
                trim_blocks=True,
                lstrip_blocks=True,
            )
            logger.debug(f"📝 [POCGenerator] Jinja2 初始化: {self.templates_dir}")
        except ImportError:
            logger.warning("⚠️ [POCGenerator] jinja2 未安装，使用简单替换模式")
            self._jinja_env = None

    async def generate(self, finding: Dict) -> str:
        """为漏洞生成 POC 脚本。

        Args:
            finding: 漏洞字典，包含 type / url / parameter / payload / evidence 等。

        Returns:
            POC 脚本内容字符串。
        """
        vuln_type = finding.get("type", "").lower()
        template_name = self._select_template(vuln_type)

        if template_name is None:
            # 无匹配模板，生成通用 POC
            return self._generate_generic(finding)

        # 构建模板上下文
        context = self._build_context(finding)

        # 渲染模板
        poc = await self._render(template_name, context)

        logger.info(f"📝 [POCGenerator] 生成 POC: {vuln_type} → {template_name}")
        return poc

    def _select_template(self, vuln_type: str) -> Optional[str]:
        """根据漏洞类型选择模板。

        Args:
            vuln_type: 漏洞类型字符串。

        Returns:
            模板文件名，或 None（无匹配）。
        """
        for key, template in TEMPLATE_MAP.items():
            if key in vuln_type:
                return template
        return None

    def _build_context(self, finding: Dict) -> Dict:
        """构建模板渲染上下文。

        Args:
            finding: 漏洞字典。

        Returns:
            模板上下文字典。
        """
        return {
            "target_url": finding.get("url", ""),
            "parameter": finding.get("parameter", ""),
            "payload": finding.get("payload", ""),
            "vuln_type": finding.get("type", ""),
            "severity": finding.get("severity", ""),
            "evidence": finding.get("evidence", ""),
            "method": finding.get("method", "GET"),
            "headers": finding.get("headers", {}),
            "cookie": finding.get("cookie", ""),
        }

    async def _render(self, template_name: str, context: Dict) -> str:
        """渲染 Jinja2 模板。

        Args:
            template_name: 模板文件名。
            context: 渲染上下文。

        Returns:
            渲染后的 POC 脚本字符串。
        """
        if self._jinja_env:
            template = self._jinja_env.get_template(template_name)
            return template.render(**context)
        else:
            # 无 Jinja2 时使用简单文件读取 + 字符串替换
            template_path = self.templates_dir / template_name
            if not template_path.exists():
                return self._generate_generic(context)
            content = template_path.read_text(encoding="utf-8")
            for key, value in context.items():
                content = content.replace(f"{{{{ {key} }}}}", str(value))
            return content

    def _generate_generic(self, finding: Dict) -> str:
        """生成通用 POC（无模板时）。

        Args:
            finding: 漏洞字典或上下文。

        Returns:
            Python POC 脚本字符串。
        """
        url = finding.get("target_url") or finding.get("url", "")
        param = finding.get("parameter", "")
        payload = finding.get("payload", "")
        vuln_type = finding.get("vuln_type") or finding.get("type", "unknown")

        return f'''#!/usr/bin/env python3
"""
通用 POC - {vuln_type}
自动生成 by DeepSec POCGenerator
"""
import requests

TARGET = "{url}"
PARAMETER = "{param}"
PAYLOAD = "{payload}"

def verify():
    """验证漏洞是否存在。"""
    # TODO: 根据漏洞类型实现验证逻辑
    params = {{PARAMETER: PAYLOAD}}
    resp = requests.get(TARGET, params=params, timeout=10)
    print(f"Status: {{resp.status_code}}")
    print(f"Response: {{resp.text[:500]}}")
    # TODO: 添加漏洞验证判断逻辑
    return True

if __name__ == "__main__":
    if verify():
        print(f"[+] 漏洞确认: {vuln_type} @ {{TARGET}}")
    else:
        print("[-] 漏洞未确认")
'''

    def list_templates(self) -> list[str]:
        """列出所有可用模板。"""
        if not self.templates_dir.exists():
            return []
        return [f.name for f in self.templates_dir.glob("*.j2")]

    async def generate_batch(self, findings: list[Dict]) -> list[Dict]:
        """批量生成 POC。

        Args:
            findings: 漏洞列表。

        Returns:
            [{"finding_id": str, "poc": str, "template": str}]
        """
        results = []
        for finding in findings:
            vuln_type = finding.get("type", "").lower()
            template = self._select_template(vuln_type) or "generic"
            poc = await self.generate(finding)
            results.append({
                "finding_id": finding.get("id", vuln_type),
                "poc": poc,
                "template": template,
            })
        return results
