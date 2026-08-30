#!/usr/bin/env python3
"""
Sprint 3 验收测试骨架。
覆盖 DeepSec 深度利用链全模块。

运行: pytest tests/test_sprint3.py -v --tb=short
"""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# ExploitChain 测试
# ============================================================

class TestExploitChain:
    """漏洞利用链编排器测试。"""

    def test_prioritize_sorting(self):
        """TC-EC-01: 漏洞按严重度排序。"""
        from vulnclaw.deepsec.exploit_chain import ExploitChain

        chain = ExploitChain(target="http://test.com", dangerous=False)
        findings = [
            {"type": "xss", "severity": "Low", "url": "http://t.com/1"},
            {"type": "sqli", "severity": "Critical", "url": "http://t.com/2"},
            {"type": "lfi", "severity": "High", "url": "http://t.com/3"},
        ]
        sorted_f = chain._prioritize(findings)
        assert sorted_f[0]["severity"] == "Critical"
        assert sorted_f[1]["severity"] == "High"
        assert sorted_f[2]["severity"] == "Low"

    def test_prioritize_dedup(self):
        """TC-EC-02: 漏洞去重。"""
        from vulnclaw.deepsec.exploit_chain import ExploitChain

        chain = ExploitChain(target="http://test.com", dangerous=False)
        findings = [
            {"type": "sqli", "url": "http://t.com/1", "parameter": "id"},
            {"type": "sqli", "url": "http://t.com/1", "parameter": "id"},  # 重复
            {"type": "sqli", "url": "http://t.com/1", "parameter": "name"},  # 不同参数
        ]
        sorted_f = chain._prioritize(findings)
        assert len(sorted_f) == 2

    def test_select_strategy_sqli(self):
        """TC-EC-03: SQL 注入策略选择。"""
        from vulnclaw.deepsec.exploit_chain import ExploitChain

        chain = ExploitChain(target="http://test.com", dangerous=False)
        finding = {"type": "sql_injection"}
        assert chain._select_strategy(finding) == "sqlmap"

    def test_select_strategy_rce(self):
        """TC-EC-04: RCE 策略选择。"""
        from vulnclaw.deepsec.exploit_chain import ExploitChain

        chain = ExploitChain(target="http://test.com", dangerous=False)
        finding = {"type": "command_injection"}
        assert chain._select_strategy(finding) == "shell"

    def test_select_strategy_default(self):
        """TC-EC-05: 未知类型默认 POC。"""
        from vulnclaw.deepsec.exploit_chain import ExploitChain

        chain = ExploitChain(target="http://test.com", dangerous=False)
        finding = {"type": "unknown_vuln"}
        assert chain._select_strategy(finding) == "poc"


# ============================================================
# SQLMapWrapper 测试
# ============================================================

class TestSQLMapWrapper:
    """SQLMap 封装器测试。"""

    def test_generate_poc(self):
        """TC-SM-01: POC 命令生成。"""
        from vulnclaw.deepsec.sqlmap_wrapper import SQLMapWrapper

        wrapper = SQLMapWrapper(target="http://test.com")
        finding = {
            "url": "http://test.com/page?id=1",
            "parameter": "id",
        }
        poc = wrapper.generate_poc(finding)
        assert "sqlmap" in poc
        assert "http://test.com/page?id=1" in poc
        assert "-p" in poc and "id" in poc

    def test_init_params(self):
        """TC-SM-02: 初始化参数。"""
        from vulnclaw.deepsec.sqlmap_wrapper import SQLMapWrapper

        wrapper = SQLMapWrapper(target="http://t.com", level=5, risk=3)
        assert wrapper.level == 5
        assert wrapper.risk == 3
        assert wrapper.target == "http://t.com"


# ============================================================
# POCGenerator 测试
# ============================================================

class TestPOCGenerator:
    """POC 生成器测试。"""

    def test_select_template_sqli(self):
        """TC-PG-01: SQL 注入模板选择。"""
        from vulnclaw.deepsec.poc_generator import POCGenerator

        gen = POCGenerator()
        template = gen._select_template("sql_injection")
        assert template == "sqli.py.j2"

    def test_select_template_lfi(self):
        """TC-PG-02: LFI 模板选择。"""
        from vulnclaw.deepsec.poc_generator import POCGenerator

        gen = POCGenerator()
        template = gen._select_template("file_inclusion")
        assert template == "lfi.py.j2"

    def test_select_template_rce(self):
        """TC-PG-03: RCE 模板选择。"""
        from vulnclaw.deepsec.poc_generator import POCGenerator

        gen = POCGenerator()
        template = gen._select_template("command_injection")
        assert template == "rce.py.j2"

    def test_select_template_xss(self):
        """TC-PG-04: XSS 模板选择。"""
        from vulnclaw.deepsec.poc_generator import POCGenerator

        gen = POCGenerator()
        template = gen._select_template("cross_site_scripting")
        assert template == "xss.html.j2"

    def test_select_template_none(self):
        """TC-PG-05: 未知类型返回 None。"""
        from vulnclaw.deepsec.poc_generator import POCGenerator

        gen = POCGenerator()
        template = gen._select_template("unknown_type")
        assert template is None

    def test_generate_generic(self):
        """TC-PG-06: 通用 POC 生成。"""
        from vulnclaw.deepsec.poc_generator import POCGenerator

        gen = POCGenerator()
        finding = {
            "url": "http://test.com",
            "parameter": "q",
            "payload": "test",
            "type": "unknown",
        }
        poc = gen._generate_generic(finding)
        assert "requests" in poc
        assert "http://test.com" in poc


# ============================================================
# ShellChannel 测试
# ============================================================

class TestShellChannel:
    """Shell 通道测试。"""

    def test_generate_reverse_shell_bash(self):
        """TC-SC-01: Bash reverse shell 生成。"""
        from vulnclaw.deepsec.shell_channel import ShellChannel

        channel = ShellChannel(target="http://test.com")
        shell = channel.generate_reverse_shell("10.0.0.1", 4444, "bash")
        assert "10.0.0.1" in shell
        assert "4444" in shell
        assert "bash" in shell

    def test_generate_reverse_shell_python(self):
        """TC-SC-02: Python reverse shell 生成。"""
        from vulnclaw.deepsec.shell_channel import ShellChannel

        channel = ShellChannel(target="http://test.com")
        shell = channel.generate_reverse_shell("10.0.0.1", 4444, "python")
        assert "10.0.0.1" in shell
        assert "4444" in shell
        assert "socket" in shell

    def test_generate_poc(self):
        """TC-SC-03: POC 脚本生成。"""
        from vulnclaw.deepsec.shell_channel import ShellChannel

        channel = ShellChannel(target="http://test.com")
        finding = {
            "url": "http://test.com/cmd",
            "parameter": "cmd",
            "type": "RCE",
        }
        poc = channel.generate_poc(finding)
        assert "requests" in poc
        assert "reverse" in poc.lower()
        assert "http://test.com/cmd" in poc


# ============================================================
# DAG execute_deep_exploit_node 测试
# ============================================================

class TestDeepExploitNode:
    """DAG 深度利用节点测试。"""

    def test_node_type_registered(self):
        """TC-DAG-01: EXPLOIT_DEEP 节点已注册。"""
        from vulnclaw.dag.executor import NODE_EXECUTORS
        from vulnclaw.dag.graph import NodeType

        assert NodeType.EXPLOIT_DEEP in NODE_EXECUTORS
        assert NODE_EXECUTORS[NodeType.EXPLOIT_DEEP].__name__ == "execute_deep_exploit_node"

    def test_node_executor_callable(self):
        """TC-DAG-02: execute_deep_exploit_node 是协程函数。"""
        from vulnclaw.dag.executor import execute_deep_exploit_node
        import inspect

        assert inspect.iscoroutinefunction(execute_deep_exploit_node)

    def test_node_type_value(self):
        """TC-DAG-03: NodeType.EXPLOIT_DEEP 枚举值。"""
        from vulnclaw.dag.graph import NodeType

        assert NodeType.EXPLOIT_DEEP.value == "exploit_deep"


# ============================================================
# scan.py --deep / --dangerous 参数测试
# ============================================================

class TestScanDeepArg:
    """scan.py 参数测试。"""

    def test_deep_arg_in_help(self):
        """TC-CLI-01: --deep 参数出现在 --help。"""
        import subprocess
        result = subprocess.run(
            [sys.executable, "scan.py", "scan", "--help"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
            timeout=10, encoding="utf-8", errors="replace",
            stdin=subprocess.DEVNULL,  # 避免继承 pytest 捕获的无效句柄 (WinError 6/50)
        )
        assert "--deep" in result.stdout

    def test_dangerous_arg_in_help(self):
        """TC-CLI-02: --dangerous 参数出现在 --help。"""
        import subprocess
        result = subprocess.run(
            [sys.executable, "scan.py", "scan", "--help"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
            timeout=10, encoding="utf-8", errors="replace",
            stdin=subprocess.DEVNULL,  # 避免继承 pytest 捕获的无效句柄 (WinError 6/50)
        )
        assert "--dangerous" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
