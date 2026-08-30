#!/usr/bin/env python3
"""Sprint 4 模块 7：教程生成器。

从扫描日志自动生成 Markdown 教程文档。
使用 Jinja2 模板渲染。

输出格式：教程包含以下章节：
1. 扫描概览（目标/时间/漏洞数）
2. 侦察阶段（子域名/端口/服务）
3. 漏洞发现（按类型分类）
4. 漏洞验证（AI 交叉验证过程）
5. 利用链（POC 展示）
6. 修复建议
"""
import os
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
import sys
sys.dont_write_bytecode = True
import asyncio
import json
import re
from datetime import datetime
from pathlib import Path

from vulnclaw.core.logger import logger


class TutorialGenerator:
    """从扫描日志生成 Markdown 教程。"""

    def __init__(self, templates_dir: Optional[str] = None):
        """初始化教程生成器。

        Args:
            templates_dir: Jinja2 模板目录（默认使用内置模板）。
        """
        self.templates_dir = Path(templates_dir) if templates_dir else Path(__file__).parent / "templates"
        self._jinja_env = None
        self._init_jinja()

    def _init_jinja(self):
        """初始化 Jinja2。"""
        try:
            from jinja2 import Environment, FileSystemLoader
            self._jinja_env = Environment(
                loader=FileSystemLoader(str(self.templates_dir)),
                autoescape=False,
                trim_blocks=True,
                lstrip_blocks=True,
            )
        except ImportError:
            logger.warning("⚠️ [TutorialGenerator] jinja2 未安装，使用内置模板")

    async def generate(
        self,
        scan_log: str,
        scan_report: Optional[Dict] = None,
        output_path: Optional[str] = None,
    ) -> str:
        """从扫描日志生成教程。

        Args:
            scan_log: 扫描日志文本。
            scan_report: 扫描报告 JSON（可选，增强教程内容）。
            output_path: 输出文件路径（不指定则返回字符串）。

        Returns:
            Markdown 教程字符串。
        """
        logger.info("📝 [TutorialGenerator] 开始生成教程")

        # 1. 解析日志
        parsed = self._parse_log(scan_log)

        # 2. 合并报告数据
        if scan_report:
            parsed = self._merge_report(parsed, scan_report)

        # 3. 渲染模板
        markdown = self._render(parsed)

        # 4. 输出到文件
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(markdown, encoding="utf-8")
            logger.info(f"✅ [TutorialGenerator] 教程已保存: {output_path}")

        return markdown

    def _parse_log(self, log: str) -> Dict:
        """解析扫描日志，提取结构化信息。

        Args:
            log: 日志文本。

        Returns:
            {
                "target": str,
                "start_time": str,
                "end_time": str,
                "elapsed": str,
                "recon": {...},
                "findings": [...],
                "verify": {...},
                "exploit": {...},
                "stats": {...},
            }
        """
        parsed: Dict = {
            "target": "",
            "start_time": "",
            "end_time": "",
            "elapsed": "",
            "recon": {"subdomains": [], "ports": [], "services": []},
            "findings": [],
            "verify": {"total": 0, "verified": 0, "false_positives": 0},
            "exploit": {"chains": [], "pocs": []},
            "stats": {},
            "raw_log_lines": log.count("\n"),
        }

        # 提取目标 URL
        target_match = re.search(r"目标[:\s]+(https?://\S+)", log)
        if target_match:
            parsed["target"] = target_match.group(1)

        # 提取时间
        start_match = re.search(r"开始[:\s]+([\d\-:\s]+)", log)
        if start_match:
            parsed["start_time"] = start_match.group(1).strip()

        elapsed_match = re.search(r"耗时[:\s]+([\d.]+)\s*s", log)
        if elapsed_match:
            parsed["elapsed"] = elapsed_match.group(1) + "s"

        # 提取子域名
        for m in re.finditer(r"子域名[：:\s]+([a-zA-Z0-9.\-]+)", log):
            parsed["recon"]["subdomains"].append(m.group(1))

        # 提取开放端口
        for m in re.finditer(r"端口[：:\s]+(\d+)", log):
            parsed["recon"]["ports"].append(int(m.group(1)))

        # 提取漏洞发现
        for m in re.finditer(r"漏洞[：:\s]+([^\n]+)", log):
            parsed["findings"].append({
                "description": m.group(1).strip(),
                "type": "unknown",
            })

        # 提取验证统计
        verify_match = re.search(r"验证[:\s]+(\d+)/(\d+)", log)
        if verify_match:
            parsed["verify"]["verified"] = int(verify_match.group(1))
            parsed["verify"]["total"] = int(verify_match.group(2))

        # 提取利用链
        for m in re.finditer(r"利用链[：:\s]+([^\n]+)", log):
            parsed["exploit"]["chains"].append(m.group(1).strip())

        return parsed

    def _merge_report(self, parsed: Dict, report: Dict) -> Dict:
        """合并扫描报告数据到解析结果。"""
        parsed["target"] = report.get("target", parsed["target"])
        parsed["start_time"] = report.get("start_time", parsed["start_time"])
        parsed["elapsed"] = str(report.get("elapsed_seconds", "")) + "s"

        # 合并漏洞
        if "findings" in report:
            parsed["findings"] = report["findings"]

        # 合并统计
        parsed["stats"] = report.get("stats", {})

        # 合并 DAG profile
        if "dag_profile" in report:
            parsed["dag_profile"] = report["dag_profile"]

        return parsed

    def _render(self, data: Dict) -> str:
        """渲染 Markdown 教程。"""
        if self._jinja_env:
            try:
                template = self._jinja_env.get_template("tutorial.md.j2")
                return template.render(**data, now=datetime.now().strftime("%Y-%m-%d %H:%M"))
            except Exception:
                pass

        # 无 Jinja2 时使用内置模板
        return self._render_builtin(data)

    def _render_builtin(self, data: Dict) -> str:
        """内置 Markdown 模板（无 Jinja2 时使用）。"""
        target = data.get("target", "unknown")
        elapsed = data.get("elapsed", "N/A")
        findings = data.get("findings", [])
        recon = data.get("recon", {})
        verify = data.get("verify", {})
        exploit = data.get("exploit", {})

        md = f"""# 渗透测试教程 - {target}

> 自动生成 by VULNCLAW TutorialGenerator
> 时间：{datetime.now().strftime("%Y-%m-%d %H:%M")}
> 耗时：{elapsed}

## 1. 扫描概览

| 项目 | 值 |
|------|------|
| 目标 | {target} |
| 耗时 | {elapsed} |
| 漏洞数 | {len(findings)} |
| 已验证 | {verify.get('verified', 0)}/{verify.get('total', len(findings))} |

## 2. 侦察阶段

### 子域名 ({len(recon.get('subdomains', []))})
"""
        for sub in recon.get("subdomains", [])[:20]:
            md += f"- {sub}\n"

        md += f"\n### 开放端口 ({len(recon.get('ports', []))})\n"
        for port in recon.get("ports", [])[:20]:
            md += f"- {port}\n"

        md += f"\n## 3. 漏洞发现 ({len(findings)})\n\n"
        for i, f in enumerate(findings, 1):
            f_type = f.get("type", "unknown")
            f_url = f.get("url", "")
            f_severity = f.get("severity", "")
            md += f"### #{i} {f_type} ({f_severity})\n"
            md += f"- URL: {f_url}\n"
            if f.get("parameter"):
                md += f"- 参数: {f['parameter']}\n"
            if f.get("payload"):
                md += f"- Payload: `{f['payload'][:100]}`\n"
            md += "\n"

        md += f"## 4. 漏洞验证\n\n"
        md += f"- 总计: {verify.get('total', 0)}\n"
        md += f"- 已验证: {verify.get('verified', 0)}\n"
        md += f"- 误报过滤: {verify.get('false_positives', 0)}\n\n"

        md += f"## 5. 利用链 ({len(exploit.get('chains', []))})\n\n"
        for chain in exploit.get("chains", []):
            md += f"- {chain}\n"

        md += f"\n## 6. 修复建议\n\n"
        for i, f in enumerate(findings, 1):
            if f.get("remediation"):
                md += f"### #{i} 修复建议\n{f['remediation']}\n\n"

        md += "\n---\n*本教程由 VULNCLAW 自动生成*\n"
        return md

    async def generate_from_file(
        self,
        log_path: str,
        report_path: Optional[str] = None,
        output_path: Optional[str] = None,
    ) -> str:
        """从日志文件生成教程。

        Args:
            log_path: 日志文件路径。
            report_path: 报告 JSON 路径（可选）。
            output_path: 输出路径（可选）。

        Returns:
            Markdown 教程字符串。
        """
        log_text = Path(log_path).read_text(encoding="utf-8", errors="replace")

        report = None
        if report_path and Path(report_path).exists():
            try:
                report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass

        return await self.generate(log_text, report, output_path)
