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
import json
from pathlib import Path

from vulnclaw.core.logger import logger
from vulnclaw.core.settings import settings
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


# ============================================================
# A8.2：CVE ↔ PoC 双向索引
# 命中 CVE 后，按组件/名称映射漏洞类型生成脚本化 PoC，并附 nuclei -id 复现命令；
# 索引 cve_id -> {vuln_type, nuclei_cmd, poc_script} 同时支持「CVE 查 PoC」与「PoC 溯源 CVE」。
# ============================================================
CVE_POC_INDEX: Dict[str, Dict] = {}

# 组件（小写）-> 漏洞类型（对齐 POCGenerator 模板：rce/sqli/lfi/xss/deserialization）
_COMPONENT_VULN_TYPE: Dict[str, str] = {
    "struts": "rce", "spring": "rce", "log4j": "rce", "log4shell": "rce",
    "fastjson": "rce", "shiro": "rce", "weblogic": "rce", "jboss": "rce",
    "tomcat": "rce", "jenkins": "rce", "viewstate": "deserialization",
    "drupal": "rce", "joomla": "rce", "wordpress": "sqli", "grafana": "rce",
    "gitlab": "rce", "confluence": "rce", "solr": "rce", "elasticsearch": "rce",
    "nacos": "rce", "flink": "rce", "exim": "rce", "oracle": "rce",
}


def _cve_to_vuln_type(cve_id: str, components=None, name: str = "") -> str:
    """CVE 组件/名称 -> POCGenerator 模板类型。"""
    text = " ".join([str(c) for c in (components or [])] + [str(name or "")])
    low = text.lower()
    for comp, vt in _COMPONENT_VULN_TYPE.items():
        if comp in low:
            return vt
    if "sqli" in low or "sql injection" in low:
        return "sqli"
    if "xss" in low or "cross-site" in low:
        return "xss"
    if "traversal" in low or "directory" in low or "lfi" in low:
        return "lfi"
    if "deserial" in low:
        return "deserialization"
    # 高危 CVE 多数可 RCE，默认 rce 模板
    return "rce"


async def build_cve_poc(
    cve_id: str,
    finding: Optional[Dict] = None,
    components=None,
    name: str = "",
) -> Dict:
    """A8.2：为 CVE 生成 PoC（双向索引：CVE -> PoC，PoC 含 CVE 溯源）。

    返回 {cve_id, vuln_type, nuclei_cmd, poc_script}；命中即生成复现命令。
    """
    vuln_type = _cve_to_vuln_type(cve_id, components, name)
    target = ""
    if finding:
        target = (
            finding.get("url") or finding.get("target")
            or finding.get("matched_at") or ""
        )
    # nuclei -id 即该 CVE 的权威 PoC 模板
    nuclei_cmd = (
        f"nuclei -id {cve_id} -u {target}" if target
        else f"nuclei -id {cve_id} -u <target>"
    )
    poc_script = ""
    try:
        gen = POCGenerator()
        syn = {
            "type": vuln_type,
            "url": target,
            "parameter": (finding or {}).get("parameter", ""),
            "payload": (finding or {}).get("matched", ""),
            "severity": (finding or {}).get("severity", "High"),
            "evidence": (finding or {}).get("matched", ""),
        }
        poc_script = await gen.generate(syn)
    except Exception as e:  # noqa: BLE001
        logger.debug(f"[PoC] CVE={cve_id} 脚本生成失败: {e}")
    rec = {
        "cve_id": cve_id,
        "vuln_type": vuln_type,
        "nuclei_cmd": nuclei_cmd,
        "poc_script": poc_script,
    }
    CVE_POC_INDEX[cve_id] = rec
    return rec


def get_cve_poc(cve_id: str) -> Optional[Dict]:
    """按 CVE 查询已生成 PoC（双向索引反向查询）。"""
    return CVE_POC_INDEX.get(cve_id)


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
        # Z3.1: 本次生成来源（template/llm/generic），批量路径据此打 template 字段
        self._last_origin = "template"
        self._last_description = ""
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

        if template_name is not None:
            # 构建模板上下文
            context = self._build_context(finding)

            # 渲染模板
            poc = await self._render(template_name, context)
            self._last_origin = "template"
            self._last_description = template_name
            logger.info(f"📝 [POCGenerator] 生成 POC: {vuln_type} → {template_name}")
            return poc

        # Z3.1: 无匹配模板 → 先走 LLM 动态生成（失败/开关关 → 硬回退静态通用骨架，绝不阻断）
        self._last_origin = "generic"
        self._last_description = "static generic skeleton"
        llm_poc = await self._generate_llm(finding)
        if llm_poc:
            self._last_origin = "llm"
            logger.info(f"📝 [POCGenerator] LLM 动态生成 POC: {vuln_type}")
            return llm_poc
        logger.info(f"📝 [POCGenerator] 无模板回退通用骨架: {vuln_type}")
        return self._generate_generic(finding)

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

    async def _generate_llm(self, finding: Dict) -> Optional[str]:
        """Z3.1: LLM 按漏洞类型动态生成可运行 PoC。

        仅在未命中静态模板时触发（降低 Token 消耗）；LLM 不可用 / 输出非法 /
        开关关闭 → 返回 None，调用方硬回退静态通用骨架，绝不阻断报告生成。

        system 固化约束：非破坏性、最小影响、单次验证 <=10s、不外传目标数据。
        """
        if not getattr(settings, "enable_llm_poc", True):
            return None
        try:
            from vulnclaw.ai.core import get_llm_client

            client = get_llm_client()
            if client is None:
                return None
            prompt = (
                "请为以下漏洞生成一个可直接运行的 Python3 PoC 脚本（requests 标准库，"
                "以 if __name__ == '__main__' 组织）。\n"
                f"漏洞类型: {finding.get('type', 'unknown')}\n"
                f"目标 URL: {finding.get('url', '')}\n"
                f"参数: {finding.get('parameter', '')}\n"
                f"已观察载荷: {finding.get('payload', '') or finding.get('matched', '')}\n"
                f"严重度: {finding.get('severity', 'High')}\n"
                "输出为 JSON 对象，字段：code（脚本全文）、description（一句话说明）、"
                "validation_steps（验证步骤数组）。硬性约束：1) 非破坏性，不删改数据；"
                "2) 最小影响，单次验证调用耗时 <=10s，超时终止；3) 不把目标响应外传给任何第三方；"
                "4) 发送的请求不携带破坏性载荷。"
            )
            result = await client.ask(
                prompt,
                system=(
                    "你是安全研究 PoC 编写专家。只输出合法 JSON（code/description/"
                    "validation_steps 三字段），禁止 markdown 与额外文字。code 必须是"
                    "可直接运行的 Python3 脚本，且严格遵守非破坏、最小影响、单次 <=10s、"
                    "不外传目标数据。"
                ),
                temperature=0.2,
                max_tokens=1200,
                retries=2,
                force_json=True,
                usage_site="pocgen",
            )
            payload = result
            if isinstance(payload, str):
                payload = json.loads(payload)
            code = str((payload or {}).get("code", "") or "").strip()
            if len(code) < 30:
                return None
            desc = str((payload or {}).get("description", "") or "").strip()
            self._last_description = desc or "llm generated poc"
            return code
        except Exception as exc:  # noqa: BLE001
            logger.warning(f"⚙️ [POCGenerator] LLM 动态生成失败，回退静态骨架: {exc}")
            return None

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
        method = str(finding.get("method", "GET") or "GET").upper()

        # SP19: 按漏洞类型生成 verify() 验证判断逻辑（生成代码字符串，不实际执行）
        vt = str(vuln_type).lower()
        if "sql" in vt or "sqli" in vt:
            verify_block = (
                '    # SQL 注入验证：响应文本匹配数据库错误特征\n'
                '    sql_markers = ("sql syntax", "you have an error", "mysql", "ora-",\n'
                '                   "sqlite", "microsoft ole db", "unclosed quotation mark")\n'
                '    low = resp.text.lower()\n'
                '    if any(m in low for m in sql_markers):\n'
                '        print("[+] SQL 错误特征命中")\n'
                '        return True\n'
                '    return False\n'
            )
        elif "xss" in vt:
            verify_block = (
                '    # XSS 验证：payload 去空格后反射回显检查\n'
                '    if PAYLOAD.replace(" ", "") in resp.text.replace(" ", ""):\n'
                '        print("[+] Payload 反射回显，XSS 确认")\n'
                '        return True\n'
                '    return False\n'
            )
        elif "rce" in vt or "command" in vt or "cmd" in vt:
            verify_block = (
                '    # 命令执行验证：响应含命令回显特征或 payload 随机 token 反射\n'
                '    rce_markers = ("uid=", "id=")\n'
                '    low = resp.text.lower()\n'
                '    if any(m in low for m in rce_markers) or PAYLOAD in resp.text:\n'
                '        print("[+] 命令执行回显确认")\n'
                '        return True\n'
                '    return False\n'
            )
        elif "ssrf" in vt:
            verify_block = (
                '    # SSRF 验证：命中内网/云元数据特征\n'
                '    ssrf_markers = ("instance-id", "ami-", "169.254")\n'
                '    low = resp.text.lower()\n'
                '    if any(m in low for m in ssrf_markers):\n'
                '        print("[+] SSRF 元数据回显确认")\n'
                '        return True\n'
                '    return False\n'
            )
        else:
            # 默认兜底：未知类型保持探测型（仅打印 Status/Response）
            verify_block = (
                '    # 探测型：仅打印响应，交由人工研判\n'
                '    return True\n'
            )

        return f'''#!/usr/bin/env python3
"""
通用 POC - {vuln_type}
自动生成 by DeepSec POCGenerator
"""
import requests

TARGET = "{url}"
PARAMETER = "{param}"
PAYLOAD = "{payload}"
METHOD = "{method}"

def verify():
    """验证漏洞是否存在。"""
    params = {{PARAMETER: PAYLOAD}}
    if METHOD == "POST":
        resp = requests.post(TARGET, data=params, timeout=10)
    else:
        resp = requests.get(TARGET, params=params, timeout=10)
    print(f"Status: {{resp.status_code}}")
    print(f"Response: {{resp.text[:500]}}")
{verify_block}
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
            poc = await self.generate(finding)
            if self._last_origin == "template":
                template = self._select_template(vuln_type) or "generic"
            else:
                # llm / generic：批量路径直接沿用本次生成来源标记
                template = self._last_origin
            results.append({
                "finding_id": finding.get("id", vuln_type),
                "poc": poc,
                "template": template,
            })
        return results
