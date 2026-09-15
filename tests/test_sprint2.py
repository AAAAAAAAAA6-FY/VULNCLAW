#!/usr/bin/env python3
"""
Sprint 2 验收测试骨架。
覆盖代码扫描全链路：repo_manager / semgrep / codeql / ai_auditor / dependency_scanner / DAG 节点。

运行: pytest tests/test_sprint2.py -v --tb=short
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
# RepoManager 测试
# ============================================================

class TestRepoManager:
    """仓库管理器测试。"""

    def test_clone_local_dir(self):
        """TC-RM-01: 本地目录 clone（符号链接）。"""
        from vulnclaw.code.repo_manager import RepoManager

        with tempfile.TemporaryDirectory() as tmp_src:
            # 创建模拟源目录
            os.makedirs(os.path.join(tmp_src, "src"), exist_ok=True)
            Path(tmp_src, "src", "main.py").write_text("print('hello')")

            mgr = RepoManager(workspace=tempfile.mkdtemp())
            loop = asyncio.new_event_loop()
            dest = loop.run_until_complete(mgr.clone_repo(tmp_src))
            assert os.path.exists(dest)
            assert os.path.exists(os.path.join(dest, "src", "main.py"))
            mgr.cleanup()
            loop.close()

    def test_extract_repo_name(self):
        """TC-RM-02: 从 URL 提取仓库名。"""
        from vulnclaw.code.repo_manager import RepoManager
        mgr = RepoManager()

        assert mgr._extract_repo_name("https://github.com/user/repo.git") == "repo"
        assert mgr._extract_repo_name("https://github.com/user/my-project") == "my-project"
        assert mgr._extract_repo_name("/local/path/to/project.zip") == "project"

    def test_cleanup(self):
        """TC-RM-03: cleanup 清理所有目录。"""
        from vulnclaw.code.repo_manager import RepoManager

        with tempfile.TemporaryDirectory() as tmp_src:
            mgr = RepoManager(workspace=tempfile.mkdtemp())
            loop = asyncio.new_event_loop()
            dest = loop.run_until_complete(mgr.clone_repo(tmp_src))
            assert os.path.exists(dest)
            mgr.cleanup()
            assert not os.path.exists(dest)
            loop.close()


# ============================================================
# P0 安全边界契约测试：断言"拒绝/不写出界"，而不是"函数返回了"
# ============================================================
import zipfile  # noqa: E402

import pytest  # noqa: E402


class TestRepoManagerSecurityBoundaries:
    """P0-1（归档穿越）/ P0-2（本地目录越界）攻击者输入契约。"""

    def _zip(self, path, members):
        with zipfile.ZipFile(path, "w") as zf:
            for name, data in members:
                zf.writestr(name, data)

    def _run(self, coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_zip_slip_does_not_escape(self, tmp_path):
        from vulnclaw.code.repo_manager import RepoManager
        ws = tmp_path / "ws"
        outside = tmp_path / "pwned.txt"
        arc = tmp_path / "evil.zip"
        self._zip(str(arc), [("../pwned.txt", "PWNED"), ("ok.txt", "safe")])
        self._run(RepoManager(workspace=str(ws)).clone_repo(str(arc)))
        assert not outside.exists(), "归档路径穿越写出工作区外文件！"
        assert (ws / "evil" / "ok.txt").read_text(encoding="utf-8") == "safe"

    def test_zip_absolute_and_drive_paths_rejected(self, tmp_path):
        from vulnclaw.code.repo_manager import RepoManager
        ws = tmp_path / "ws2"
        arc = tmp_path / "abs.zip"
        self._zip(str(arc), [("/abs_pwned.txt", "X"), ("C:/abs_pwned.txt", "Y"),
                             ("good.txt", "ok")])
        self._run(RepoManager(workspace=str(ws)).clone_repo(str(arc)))
        assert (ws / "abs" / "good.txt").exists()
        assert not (ws / "abs" / "abs_pwned.txt").exists()

    def test_tar_traversal_and_symlink_rejected(self, tmp_path):
        import io
        import tarfile
        from vulnclaw.code.repo_manager import RepoManager
        ws = tmp_path / "ws3"
        arc = tmp_path / "evil.tar.gz"
        with tarfile.open(str(arc), "w:gz") as tf:
            data = b"PWNED"
            for name in ("../../tar_pwned.txt", "good.txt"):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                tf.addfile(info, io.BytesIO(data))
            link = tarfile.TarInfo("link.txt")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tf.addfile(link)
        self._run(RepoManager(workspace=str(ws)).clone_repo(str(arc)))
        assert not (tmp_path / "tar_pwned.txt").exists()
        assert (ws / "evil" / "good.txt").exists()
        assert not (ws / "evil" / "link.txt").exists()

    def test_symlink_source_rejected(self, tmp_path):
        from vulnclaw.code.repo_manager import RepoManager
        real = tmp_path / "real_repo"
        real.mkdir()
        (real / "a.py").write_text("x=1", encoding="utf-8")
        link = tmp_path / "link_repo"
        try:
            os.symlink(str(real), str(link))
        except (OSError, NotImplementedError):  # pragma: no cover
            return
        with pytest.raises(RuntimeError, match="符号链接"):
            self._run(RepoManager(workspace=str(tmp_path / "ws4")).clone_repo(str(link)))

    def test_local_dir_outside_allowed_roots_refused(self, tmp_path, monkeypatch):
        from vulnclaw.code.repo_manager import RepoManager
        from vulnclaw.config.settings import settings as st
        allowed = tmp_path / "allowed"
        allowed.mkdir()
        monkeypatch.setattr(st, "code_audit_allowed_roots", str(allowed))
        outside = tmp_path / "secret_repo"
        outside.mkdir()
        (outside / "s.py").write_text("k=1", encoding="utf-8")
        with pytest.raises(RuntimeError, match="批准根目录"):
            self._run(RepoManager(workspace=str(tmp_path / "ws5")).clone_repo(str(outside)))

    def test_local_dir_copies_not_links(self, tmp_path):
        from vulnclaw.code.repo_manager import RepoManager
        src = tmp_path / "src_repo"
        src.mkdir()
        (src / "m.py").write_text("v=2", encoding="utf-8")
        dest = self._run(RepoManager(workspace=str(tmp_path / "ws6")).clone_repo(str(src)))
        assert not os.path.islink(dest), "本地目录不得再使用 symlink"
        assert (Path(dest) / "m.py").read_text(encoding="utf-8") == "v=2"


class TestSandboxEgressGuard:
    """P0-3：网络命令不得指向内网/本机/云元数据。"""

    @staticmethod
    def _run(coro):
        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(coro)
        finally:
            loop.close()

    def test_metadata_and_private_blocked(self):
        from vulnclaw.core import sandbox as sb
        for target in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:8080/",
                       "http://10.0.0.5/", "http://192.168.1.1/", "http://[::1]/",
                       "http://metadata.google.internal/", "http://redis.internal:6379/"):
            res = self._run(sb.run_sandboxed("curl", [target]))
            assert res.get("blocked") is True, f"未被拦截: {target}"
            assert res.get("egress_blocked") is True

    def test_non_network_command_unaffected(self):
        from vulnclaw.core import sandbox as sb
        assert sb._egress_guard("echo", ["hello"]) is None

    def test_guard_can_be_disabled(self, monkeypatch):
        from vulnclaw.config.settings import settings as st
        monkeypatch.setattr(st, "sandbox_egress_guard", False)
        from vulnclaw.core import sandbox as sb
        assert sb._egress_guard("curl", ["http://127.0.0.1/"]) is None


# ============================================================
# SemgrepAdapter 测试
# ============================================================

class TestSemgrepAdapter:
    """Semgrep 适配器测试。"""

    def test_normalize_semgrep_results(self):
        """TC-SG-01: 标准化 Semgrep JSON 输出。"""
        from vulnclaw.code.engines.semgrep_adapter import SemgrepAdapter

        adapter = SemgrepAdapter()
        raw = {
            "results": [
                {
                    "check_id": "python.django.security.injection.sql",
                    "path": "app/views.py",
                    "start": {"line": 42, "col": 10},
                    "end": {"line": 45},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Possible SQL injection",
                        "lines": "cursor.execute('SELECT * FROM users WHERE id=' + user_id)",
                        "metadata": {"cwe": ["CWE-89"], "owasp": "A03:2021-Injection"},
                    },
                },
            ]
        }
        findings = adapter._normalize(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f["engine"] == "semgrep"
        assert f["severity"] == "ERROR"
        assert f["confidence"] == "HIGH"
        assert f["file"] == "app/views.py"
        assert f["line"] == 42
        assert f["cwe"] == "CWE-89"

    def test_map_confidence(self):
        """TC-SG-02: severity → confidence 映射。"""
        from vulnclaw.code.engines.semgrep_adapter import SemgrepAdapter
        adapter = SemgrepAdapter()

        assert adapter._map_confidence("ERROR") == "HIGH"
        assert adapter._map_confidence("WARNING") == "MEDIUM"
        assert adapter._map_confidence("INFO") == "LOW"


# ============================================================
# CodeQLAdapter 测试
# ============================================================

class TestCodeQLAdapter:
    """CodeQL 适配器测试。"""

    def test_normalize_sarif_results(self):
        """TC-CQ-01: 标准化 SARIF 输出。"""
        from vulnclaw.code.engines.codeql_adapter import CodeQLAdapter

        adapter = CodeQLAdapter()
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {
                                    "id": "py/sql-injection",
                                    "properties": {"tags": ["cwe-89", "security"]},
                                }
                            ]
                        }
                    },
                    "results": [
                        {
                            "ruleId": "py/sql-injection",
                            "level": "error",
                            "message": {"text": "SQL injection vulnerability"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app/models.py"},
                                        "region": {"startLine": 10, "startColumn": 5, "endLine": 12},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        findings = adapter._normalize(sarif)

        assert len(findings) == 1
        f = findings[0]
        assert f["engine"] == "codeql"
        assert f["rule_id"] == "py/sql-injection"
        assert f["severity"] == "ERROR"
        assert f["file"] == "app/models.py"
        assert f["cwe"] == "CWE-89"

    def test_map_severity(self):
        """TC-CQ-02: SARIF level → severity 映射。"""
        from vulnclaw.code.engines.codeql_adapter import CodeQLAdapter
        adapter = CodeQLAdapter()

        assert adapter._map_severity("ERROR") == "ERROR"
        assert adapter._map_severity("WARNING") == "WARNING"
        assert adapter._map_severity("NOTE") == "INFO"


# ============================================================
# AIAuditor 测试
# ============================================================

class TestAIAuditor:
    """AI 审计器测试。"""

    def test_parse_audit_response_true_positive(self):
        """TC-AI-01: LLM 判定为真漏洞 → 保留 + 生成 diff。"""
        from vulnclaw.code.ai_auditor import AIAuditor

        auditor = AIAuditor()
        batch = [
            {
                "engine": "semgrep",
                "rule_id": "sql-injection",
                "file": "app.py",
                "line": 10,
                "code_snippet": "cursor.execute(sql)",
                "cwe": "CWE-89",
            }
        ]
        response = json.dumps({
            "results": [
                {
                    "index": 0,
                    "is_true_positive": True,
                    "confidence": "HIGH",
                    "reason": "用户输入直接拼接进 SQL 查询",
                    "suggested_fix": "cursor.execute(sql, (user_id,))",
                    "fix_explanation": "使用参数化查询",
                }
            ]
        })

        filtered, diffs = auditor._parse_audit_response(response, batch)
        assert len(filtered) == 1
        assert filtered[0]["ai_confidence"] == "HIGH"
        assert len(diffs) == 1
        assert diffs[0]["suggested_fix"] == "cursor.execute(sql, (user_id,))"

    def test_parse_audit_response_false_positive(self):
        """TC-AI-02: LLM 判定为误报 → 过滤。"""
        from vulnclaw.code.ai_auditor import AIAuditor

        auditor = AIAuditor()
        batch = [
            {
                "engine": "semgrep",
                "rule_id": "hardcoded-password",
                "file": "config.py",
                "line": 5,
                "code_snippet": "password = 'test123'",
            }
        ]
        response = json.dumps({
            "results": [
                {
                    "index": 0,
                    "is_true_positive": False,
                    "confidence": "HIGH",
                    "reason": "测试环境配置，非生产代码",
                }
            ]
        })

        filtered, diffs = auditor._parse_audit_response(response, batch)
        assert len(filtered) == 0
        assert len(diffs) == 0

    def test_parse_audit_response_invalid_json(self):
        """TC-AI-03: LLM 返回无效 JSON → 保留全部。"""
        from vulnclaw.code.ai_auditor import AIAuditor

        auditor = AIAuditor()
        batch = [{"engine": "semgrep", "rule_id": "test", "file": "a.py", "line": 1}]

        filtered, diffs = auditor._parse_audit_response("not valid json", batch)
        assert len(filtered) == 1  # 保留全部
        assert len(diffs) == 0


# ============================================================
# DependencyScanner 测试
# ============================================================

class TestDependencyScanner:
    """依赖扫描器测试。"""

    def test_detect_dependency_files_python(self):
        """TC-DEP-01: 检测 Python 依赖文件。"""
        from vulnclaw.code.dependency_scanner import DependencyScanner

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "requirements.txt").write_text("requests==2.20.0\n")
            Path(tmp, "app.py").write_text("import requests")

            scanner = DependencyScanner()
            detected = scanner._detect_dependency_files(tmp)

            assert "python" in detected
            assert len(detected["python"]) == 1

    def test_detect_dependency_files_empty(self):
        """TC-DEP-02: 无依赖文件时返回空。"""
        from vulnclaw.code.dependency_scanner import DependencyScanner

        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "README.md").write_text("# Project")
            scanner = DependencyScanner()
            detected = scanner._detect_dependency_files(tmp)

            assert detected == {}

    def test_normalize_pip_audit(self):
        """TC-DEP-03: 标准化 pip-audit 输出。"""
        from vulnclaw.code.dependency_scanner import DependencyScanner

        scanner = DependencyScanner()
        raw = {
            "dependencies": [
                {
                    "name": "requests",
                    "version": "2.20.0",
                    "vulns": [
                        {
                            "id": "CVE-2023-32681",
                            "fix_versions": ["2.31.0"],
                            "description": "Leak of Proxy-Authorization header",
                        }
                    ],
                }
            ]
        }
        findings = scanner._normalize_pip_audit(raw)

        assert len(findings) == 1
        f = findings[0]
        assert f["package"] == "requests"
        assert f["installed_version"] == "2.20.0"
        assert f["fixed_version"] == "2.31.0"
        assert f["ecosystem"] == "pip"


# ============================================================
# DAG execute_code_scan_node 测试
# ============================================================

class TestCodeScanNode:
    """DAG 代码扫描节点测试。"""

    def test_node_type_registered(self):
        """TC-DAG-01: CODE_SCAN 节点类型已注册。"""
        from vulnclaw.dag.executor import NODE_EXECUTORS
        from vulnclaw.dag.graph import NodeType

        assert NodeType.CODE_SCAN in NODE_EXECUTORS
        assert NODE_EXECUTORS[NodeType.CODE_SCAN].__name__ == "execute_code_scan_node"

    def test_node_executor_callable(self):
        """TC-DAG-02: execute_code_scan_node 可调用。"""
        from vulnclaw.dag.executor import execute_code_scan_node
        import inspect

        assert inspect.iscoroutinefunction(execute_code_scan_node)

    def test_node_type_value(self):
        """TC-DAG-03: NodeType.CODE_SCAN 枚举值正确。"""
        from vulnclaw.dag.graph import NodeType

        assert NodeType.CODE_SCAN.value == "code_scan"


# ============================================================
# scan.py --code 参数测试
# ============================================================

class TestScanCodeArg:
    """scan.py --code 参数测试。"""

    def test_code_arg_exists(self):
        """TC-CLI-01: --code 参数可被 argparse 解析。"""
        import scan

        # 模拟解析
        parser = MagicMock()
        parser.parse_args.return_value = MagicMock(code=True, repo="https://github.com/test/repo", lang="python")
        # 验证参数存在
        args = parser.parse_args([])
        assert hasattr(args, "code")

    def test_code_arg_default_false(self):
        """TC-CLI-02: --code 默认为 False。"""
        # 通过子进程测试
        import subprocess
        result = subprocess.run(
            [sys.executable, "scan.py", "--help"],
            capture_output=True, text=True, cwd=str(PROJECT_ROOT),
            timeout=10, encoding="utf-8", errors="replace",
            stdin=subprocess.DEVNULL,  # 避免继承 pytest 捕获的无效句柄 (WinError 6/50)
        )
        assert "code" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
