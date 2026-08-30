#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""批量 POC 脚本生成器 - VULNCLAW v100

功能：读取扫描报告 / 指定漏洞类型，批量生成独立 POC 脚本。
输出格式支持 .py / .html / .sh。
"""
import argparse
import datetime
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
os.environ.setdefault("PYTHONPYCACHEPREFIX", "")
sys.dont_write_bytecode = True

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)
try:
    sys.path.insert(0, _PROJECT_ROOT)
except (OSError, ValueError) as exc:
    print(f"[warn] sys.path insert 失败: {exc}", file=sys.stderr)

try:
    from vulnclaw.core.logger import logger
except ImportError:
    import logging
    logger = logging.getLogger("generate_pocs")
    logger.addHandler(logging.StreamHandler(sys.stderr))
    logger.setLevel(logging.INFO)

_DEFAULT_PAYLOADS: Dict[str, List[str]] = {
    "sqli": ["1' OR '1'='1", "1' UNION SELECT NULL--", "1' AND SLEEP(3)--"],
    "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
    "rce": ["; id", "&& cat /etc/passwd", "| whoami"],
    "lfi": ["/etc/passwd", "../../etc/passwd"],
    "ssrf": ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/"],
}

_DEFAULT_OUTPUT_DIR = "./pocs"
_DEFAULT_FORMAT = "py"
_DEFAULT_COUNT = 3
_SUPPORTED_FORMATS = ("py", "html", "sh")
_FORMAT_EXT: Dict[str, str] = {"py": ".py", "html": ".html", "sh": ".sh"}


class POCGenerator:
    """批量 POC 脚本生成器。

    使用方式::

        gen = POCGenerator(output_dir="./pocs", fmt="py")
        gen.generate(vuln_dict)
        gen.generate_all(report_list)
    """

    def __init__(
        self,
        output_dir: str = _DEFAULT_OUTPUT_DIR,
        fmt: str = _DEFAULT_FORMAT,
    ):
        if fmt not in _SUPPORTED_FORMATS:
            logger.warning("不支持的 fmt=%s，回退到 py", fmt)
            fmt = "py"
        self.output_dir = Path(output_dir)
        self.fmt = fmt
        try:
            self.output_dir.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError) as exc:
            logger.error("输出目录创建失败 %s: %s", output_dir, exc)
            raise

    @staticmethod
    def extract_vulns(report: Dict[str, Any]) -> List[Dict[str, Any]]:
        """从扫描报告中提取漏洞列表，兼容多种报告结构。"""
        if not isinstance(report, dict):
            return []
        for key in ("findings", "vulns", "vulnerabilities", "results"):
            if key in report:
                data = report[key]
                if isinstance(data, list):
                    return data
        if "type" in report or "url" in report:
            return [report]
        return []

    def generate(self, vuln: Dict[str, Any]) -> Optional[Path]:
        """为单个漏洞生成 POC 文件。"""
        vuln_type = str(vuln.get("type", vuln.get("vuln_type", "other"))).lower()
        target = str(vuln.get("url", vuln.get("target", "")))
        param = str(vuln.get("param", ""))
        severity = str(vuln.get("severity", "medium"))
        payloads = vuln.get("payloads") or _DEFAULT_PAYLOADS.get(vuln_type, [""])
        if isinstance(payloads, str):
            payloads = [payloads]

        ext = _FORMAT_EXT.get(self.fmt, ".txt")
        safe_type = re.sub(r"[^a-zA-Z0-9_]", "_", vuln_type)
        url_hash = hashlib.md5((target + param).encode()).hexdigest()[:8]
        filename = "poc_{type}_{hash}{ext}".format(
            type=safe_type, hash=url_hash, ext=ext
        )
        filepath = self.output_dir / filename

        payloads_json = json.dumps(payloads, ensure_ascii=False)
        try:
            content = self._build_content(vuln_type, target, param, severity, payloads_json)
            filepath.write_text(content, encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            logger.error("POC 写入失败 %s: %s", filepath, exc)
            return None

        logger.info("POC 已生成: %s", filepath)
        return filepath

    def _build_content(
        self,
        vuln_type: str,
        target: str,
        param: str,
        severity: str,
        payloads_json: str,
    ) -> str:
        """根据输出格式构建 POC 内容。"""
        if self.fmt == "py":
            return (
                "#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n"
                '"""\nPOC: {vtype}\n目标: {target}\n参数: {param}\n严重性: {severity}\n"""\n'
                "import requests\n"
                'TARGET = "{target}"\nPARAM = "{param}"\n'
                "PAYLOADS = {payloads}\n"
                "r = requests.get(TARGET, timeout=10)\nprint(r.status_code, len(r.text))\n"
            ).format(
                vtype=vuln_type, target=target, param=param,
                severity=severity, payloads=payloads_json,
            )
        elif self.fmt == "html":
            return '<!-- POC: {vtype} -->\n<a href="{target}">Test</a>\n'.format(
                vtype=vuln_type, target=target,
            )
        else:
            return '#!/bin/bash\n# POC: {vtype}\ncurl -g "{target}"\n'.format(
                vtype=vuln_type, target=target,
            )

    def generate_all(self, vulns: List[Dict[str, Any]]) -> List[Path]:
        """批量生成 POC 文件。"""
        created: List[Path] = []
        for v in vulns:
            try:
                path = self.generate(v)
                if path is not None:
                    created.append(path)
            except (OSError, ValueError) as exc:
                logger.warning("POC 生成失败: %s", exc)
            except Exception as exc:
                logger.error("POC 生成未知异常: %s", exc)
        return created


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="批量 POC 脚本生成器 - VULNCLAW v100")
    parser.add_argument("--input", "-i", help="扫描报告 JSON 文件")
    parser.add_argument("--output", "-o", default=_DEFAULT_OUTPUT_DIR, help="输出目录")
    parser.add_argument("--format", "-f", default=_DEFAULT_FORMAT,
                        choices=list(_SUPPORTED_FORMATS), help="输出格式")
    parser.add_argument("--vuln-type", "-t", help="指定漏洞类型")
    parser.add_argument("--target", help="指定目标 URL")
    parser.add_argument("--all", "-a", action="store_true",
                        help="对所有默认类型生成示例 POC")
    parser.add_argument("--count", type=int, default=_DEFAULT_COUNT,
                        help="--all 模式下每个类型生成数量")
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    try:
        gen = POCGenerator(output_dir=args.output, fmt=args.format)
    except (OSError, PermissionError):
        sys.exit(1)

    if args.all:
        vulns: List[Dict[str, Any]] = []
        target = args.target or "https://example.com"
        for vtype, plist in _DEFAULT_PAYLOADS.items():
            for i in range(min(args.count, len(plist))):
                vulns.append({
                    "type": vtype,
                    "url": target,
                    "param": f"param_{i}",
                    "payloads": [plist[i]],
                    "severity": "high",
                })
        created = gen.generate_all(vulns)
        print(f"[+] --all 模式: 生成 {len(created)} 个 POC -> {args.output}")
        return

    if args.vuln_type and args.target:
        vuln = {
            "type": args.vuln_type,
            "url": args.target,
            "param": "param",
            "payloads": _DEFAULT_PAYLOADS.get(args.vuln_type, [""]),
            "severity": "high",
        }
        path = gen.generate(vuln)
        if path:
            print(f"[+] 生成 1 个 POC: {path}")
        return

    if args.input:
        try:
            with open(args.input, "r", encoding="utf-8") as f:
                report = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("读取报告失败: %s", exc)
            sys.exit(1)
        vulns = POCGenerator.extract_vulns(report)
        if not vulns:
            logger.warning("报告中未找到漏洞数据")
            sys.exit(0)
        created = gen.generate_all(vulns)
        print(f"[+] 生成 {len(created)} 个 POC -> {args.output}")
        return

    print(__doc__)


if __name__ == "__main__":
    main()