# -*- coding: utf-8 -*-
"""scan_main.run_code_audit 测试：覆盖本地仓库 / semgrep 缺失降级 / 空仓库 / Git URL 四条路径。

运行: pytest tests/test_scan_main.py -v
"""
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnclaw import scan_main  # noqa: E402


def _fake_finding(rule_id="python.test.sqli", severity="WARNING"):
    """构造与 SemgrepAdapter._normalize 一致的标准化漏洞项。"""
    return {
        "id": f"semgrep:{rule_id}",
        "engine": "semgrep",
        "rule_id": rule_id,
        "severity": severity,
        "confidence": "HIGH",
        "file": "app.py",
        "line": 10,
        "column": 5,
        "end_line": 12,
        "message": "Possible injection",
        "code_snippet": "query(id)",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
    }


def _setup_mocks(monkeypatch, tmp_path, repo_path, findings=None,
                 ai_filtered=None, ai_diffs=None, dep_findings=None,
                 semgrep_error=None):
    """替换 run_code_audit 的全部外部依赖，返回 (mgr, adapter, auditor, cache_dir)。"""
    cache_dir = tmp_path / "cache"
    monkeypatch.setattr("vulnclaw.config.PROJECT_CACHE_DIR", str(cache_dir))

    mgr = AsyncMock()
    mgr.clone_repo.return_value = repo_path
    mgr.cleanup = MagicMock()  # 同步方法，避免 coroutine never awaited
    monkeypatch.setattr("vulnclaw.code.repo_manager.get_repo_manager", lambda: mgr)

    adapter = AsyncMock()
    if semgrep_error is not None:
        adapter.scan.side_effect = semgrep_error
    else:
        adapter.scan.return_value = findings or []
    monkeypatch.setattr("vulnclaw.code.engines.semgrep_adapter.SemgrepAdapter", lambda **kw: adapter)

    # CodeQL：二进制缺失 -> 跳过（不 mock 则真实探测 codeql 路径）
    monkeypatch.setattr("vulnclaw.core.utils.get_tool_path", lambda name: None)

    ds = AsyncMock()
    ds.audit_dependencies.return_value = dep_findings or []
    monkeypatch.setattr("vulnclaw.code.dependency_scanner.DependencyScanner", lambda **kw: ds)

    auditor = AsyncMock()
    auditor.audit_findings.return_value = (ai_filtered or [], ai_diffs or [])
    monkeypatch.setattr("vulnclaw.code.ai_auditor.AIAuditor", lambda **kw: auditor)

    monkeypatch.setattr("vulnclaw.core.report_generator.generate_html_report", MagicMock())
    return mgr, adapter, auditor, cache_dir


def _read_report(cache_dir, target_name):
    jsons = sorted((Path(cache_dir) / "reports").glob(f"code_audit_{target_name}_*.json"))
    assert jsons, f"未找到报告: code_audit_{target_name}_*.json in {cache_dir}"
    return json.loads(jsons[-1].read_text(encoding="utf-8"))


class TestRunCodeAudit:
    """run_code_audit 四条路径。"""

    @pytest.mark.asyncio
    async def test_local_repo_path(self, tmp_path, monkeypatch):
        """本地仓库路径：clone_repo 收到本地目录，全链路正常，返回 0 且报告完整。"""
        repo_dir = tmp_path / "local_app"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")

        finding = _fake_finding()
        ai_filtered = [dict(finding, ai_confidence="HIGH")]
        ai_diffs = [{"rule_id": "python.test.sqli", "original": "query(id)",
                     "suggested_fix": "query(id, safe=True)", "file": "app.py"}]

        mgr, adapter, auditor, cache_dir = _setup_mocks(
            monkeypatch, tmp_path, str(repo_dir),
            findings=[finding], ai_filtered=ai_filtered, ai_diffs=ai_diffs,
        )

        args = SimpleNamespace(code=True, repo=str(repo_dir), lang="python")
        result = await scan_main.run_code_audit(args)

        assert result == 0
        mgr.clone_repo.assert_awaited_once_with(str(repo_dir))
        adapter.scan.assert_awaited()  # 4 个规则集各扫一次
        auditor.audit_findings.assert_awaited_once()

        report = _read_report(cache_dir, "local_app")
        assert report["target"] == str(repo_dir)
        # 4 个规则集各扫一次，每次返回 1 条 -> 共 4 条
        assert report["semgrep_findings_count"] == 4
        assert len(report["vulnerabilities"]) == 1  # AI 过滤后
        assert report["summary"]["high"] == 1
        assert not any("Semgrep 扫描失败" in e for e in report["errors"])

    @pytest.mark.asyncio
    async def test_semgrep_missing_degrade(self, tmp_path, monkeypatch):
        """semgrep 缺失：scan 抛异常 -> 记录 errors 降级，流程继续并生成报告。"""
        repo_dir = tmp_path / "repo_a"
        repo_dir.mkdir()
        (repo_dir / "x.py").write_text("x = 1\n", encoding="utf-8")

        mgr, adapter, auditor, cache_dir = _setup_mocks(
            monkeypatch, tmp_path, str(repo_dir),
            semgrep_error=RuntimeError("semgrep 未安装，请运行 pip install semgrep"),
        )

        args = SimpleNamespace(code=True, repo=str(repo_dir), lang="python")
        result = await scan_main.run_code_audit(args)

        assert result == 0
        report = _read_report(cache_dir, "repo_a")
        assert any("Semgrep 扫描失败" in e for e in report["errors"])
        assert report["semgrep_findings_count"] == 0
        # 无发现 -> AI 审计不应执行
        assert not auditor.audit_findings.called

    @pytest.mark.asyncio
    async def test_empty_repo(self, tmp_path, monkeypatch):
        """空仓库：无任何发现 -> 跳过 AI 审计，报告 vulnerabilities 为空。"""
        repo_dir = tmp_path / "empty_repo"
        repo_dir.mkdir()  # 空目录

        mgr, adapter, auditor, cache_dir = _setup_mocks(
            monkeypatch, tmp_path, str(repo_dir), findings=[],
        )

        args = SimpleNamespace(code=True, repo=str(repo_dir), lang="python")
        result = await scan_main.run_code_audit(args)

        assert result == 0
        assert not auditor.audit_findings.called
        report = _read_report(cache_dir, "empty_repo")
        assert report["vulnerabilities"] == []
        assert report["summary"]["high"] == 0

    @pytest.mark.asyncio
    async def test_git_url(self, tmp_path, monkeypatch):
        """Git URL：repo_url 透传给 clone_repo，target_name 从 URL 提取。"""
        repo_dir = tmp_path / "git_repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text("print(1)\n", encoding="utf-8")

        git_url = "https://github.com/Anon-Artist/vulnpy.git"
        mgr, adapter, auditor, cache_dir = _setup_mocks(
            monkeypatch, tmp_path, str(repo_dir), findings=[_fake_finding()],
        )

        args = SimpleNamespace(code=True, repo=git_url, lang="python")
        result = await scan_main.run_code_audit(args)

        assert result == 0
        mgr.clone_repo.assert_awaited_once_with(git_url)
        report = _read_report(cache_dir, "vulnpy")
        assert report["target"] == git_url
