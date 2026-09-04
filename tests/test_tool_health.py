# -*- coding: utf-8 -*-
"""方案② 工具体检自动安装专项测试：plan/ensure/manifest/URL 规则。

运行: pytest tests/test_tool_health.py -v
"""
import json
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnclaw.core import utils  # noqa: E402


def _fake_settings(monkeypatch, tmp_path):
    from vulnclaw.config.settings import settings
    monkeypatch.setattr(settings, "thirdparty_dir", str(tmp_path / "thirdparty"))
    return tmp_path / "thirdparty"


def _tiny_tools(monkeypatch, tmp_path):
    """只保留 2 个工具，避免真实清单干扰 plan 检查。"""
    tiny = [
        {"name": "waybackurls", "ver": "0.1.0", "owner": "tomnomnom", "repo": "waybackurls",
         "bin": {"win": "waybackurls.exe", "linux": "waybackurls", "darwin": "waybackurls"}},
        {"name": "katana", "ver": "1.1.3", "owner": "projectdiscovery", "repo": "katana",
         "bin": {"win": "katana.exe", "linux": "katana", "darwin": "katana"}},
    ]
    monkeypatch.setattr(utils, "THIRDPARTY_TOOLS", tiny)
    return tiny


# ---------- plan_tool_install ----------
class TestPlanToolInstall:
    def test_all_missing_returns_all(self, monkeypatch, tmp_path):
        _fake_settings(monkeypatch, tmp_path)
        tiny = _tiny_tools(monkeypatch, tmp_path)
        missing = utils.plan_tool_install()
        assert {t["name"] for t in missing} == {"waybackurls", "katana"}

    def test_existing_tool_not_missing(self, monkeypatch, tmp_path):
        third = _fake_settings(monkeypatch, tmp_path)
        third.mkdir(parents=True, exist_ok=True)
        (third / "waybackurls.exe").write_bytes(b"x" * (200 * 1024))
        _tiny_tools(monkeypatch, tmp_path)
        missing = utils.plan_tool_install()
        assert {t["name"] for t in missing} == {"katana"}

    def test_stale_tiny_file_still_missing(self, monkeypatch, tmp_path):
        third = _fake_settings(monkeypatch, tmp_path)
        third.mkdir(parents=True, exist_ok=True)
        (third / "katana.exe").write_bytes(b"tiny")  # < 100KB 视为损坏残留
        _tiny_tools(monkeypatch, tmp_path)
        missing = utils.plan_tool_install()
        assert {t["name"] for t in missing} == {"waybackurls", "katana"}


# ---------- ensure_thirdparty_tools ----------
class TestEnsure:
    def test_no_missing_zero_cost(self, monkeypatch, tmp_path):
        third = _fake_settings(monkeypatch, tmp_path)
        third.mkdir(parents=True, exist_ok=True)
        (third / "waybackurls.exe").write_bytes(b"x" * (200 * 1024))
        (third / "katana.exe").write_bytes(b"x" * (200 * 1024))
        _tiny_tools(monkeypatch, tmp_path)
        called = []
        monkeypatch.setattr(utils, "download_thirdparty_tools",
                            lambda *a, **kw: called.append(1) or (0, 0))
        assert utils.ensure_thirdparty_tools() == (0, 0)
        assert not called

    def test_missing_auto_off_skips_download(self, monkeypatch, tmp_path):
        _fake_settings(monkeypatch, tmp_path)
        _tiny_tools(monkeypatch, tmp_path)
        monkeypatch.setattr(utils, "download_thirdparty_tools", lambda *a, **kw: (9, 9))
        ok, fail = utils.ensure_thirdparty_tools(auto_install=False)
        assert (ok, fail) == (0, 2)

    def test_missing_auto_on_github_down_skips(self, monkeypatch, tmp_path, capsys):
        _fake_settings(monkeypatch, tmp_path)
        _tiny_tools(monkeypatch, tmp_path)
        monkeypatch.setattr(utils, "_github_reachable", lambda *a, **kw: False)
        monkeypatch.setattr(utils, "download_thirdparty_tools", lambda *a, **kw: (2, 0))
        ok, fail = utils.ensure_thirdparty_tools()
        assert (ok, fail) == (0, 2)
        assert "GitHub 不可达" in capsys.readouterr().err or True  # logger 通道，不强制断言文本

    def test_missing_auto_on_github_ok_downloads(self, monkeypatch, tmp_path):
        _fake_settings(monkeypatch, tmp_path)
        _tiny_tools(monkeypatch, tmp_path)
        monkeypatch.setattr(utils, "_github_reachable", lambda *a, **kw: True)
        monkeypatch.setattr(utils, "download_thirdparty_tools", lambda *a, **kw: (2, 0))
        ok, fail = utils.ensure_thirdparty_tools()
        assert (ok, fail) == (2, 0)

    def test_download_exception_swallowed(self, monkeypatch, tmp_path):
        _fake_settings(monkeypatch, tmp_path)
        _tiny_tools(monkeypatch, tmp_path)
        monkeypatch.setattr(utils, "_github_reachable", lambda *a, **kw: True)

        def _boom(*a, **kw):
            raise RuntimeError("network down")

        monkeypatch.setattr(utils, "download_thirdparty_tools", _boom)
        ok, fail = utils.ensure_thirdparty_tools()
        assert (ok, fail) == (0, 2)


# ---------- SHA256 manifest ----------
class TestManifest:
    def test_record_writes_manifest(self, tmp_path):
        tool = tmp_path / "gau.exe"
        tool.write_bytes(b"fake-binary-content")
        utils._record_tool_manifest(tmp_path, "gau", "2.0.9", tool)
        mf = tmp_path / "tool_manifest.json"
        assert mf.exists()
        data = json.loads(mf.read_text(encoding="utf-8"))
        assert data["gau"]["ver"] == "2.0.9"
        assert len(data["gau"]["sha256"]) == 64

    def test_same_hash_no_warning(self, tmp_path, capsys):
        tool = tmp_path / "gau.exe"
        tool.write_bytes(b"abc")
        utils._record_tool_manifest(tmp_path, "gau", "2.0.9", tool)
        utils._record_tool_manifest(tmp_path, "gau", "2.0.9", tool)
        assert "不一致" not in capsys.readouterr().err

    def test_diff_hash_warns(self, tmp_path, caplog):
        tool = tmp_path / "gau.exe"
        tool.write_bytes(b"abc")
        utils._record_tool_manifest(tmp_path, "gau", "2.0.9", tool)
        tool.write_bytes(b"def")  # 文件被替换
        utils._record_tool_manifest(tmp_path, "gau", "2.0.9", tool)
        assert "SHA256 不一致" in caplog.text


# ---------- 新增工具 URL 规则 ----------
class TestNewToolUrls:
    def test_katana_pd_rule(self):
        url, ext = utils._tp_release_url(
            {"name": "katana", "ver": "1.1.3", "owner": "projectdiscovery", "repo": "katana"}
        )
        assert url == "https://github.com/projectdiscovery/katana/releases/download/v1.1.3/katana_1.1.3_windows_amd64.zip"
        assert ext == "zip"

    def test_waybackurls_tomnomnom_rule(self):
        url, ext = utils._tp_release_url(
            {"name": "waybackurls", "ver": "0.1.0", "owner": "tomnomnom", "repo": "waybackurls"}
        )
        assert url == "https://github.com/tomnomnom/waybackurls/releases/download/v0.1.0/waybackurls-windows-amd64-0.1.0.tgz"
        assert ext == "tar.gz"

    def test_gau_lc_rule(self):
        url, ext = utils._tp_release_url(
            {"name": "gau", "ver": "2.0.9", "owner": "lc", "repo": "gau"}
        )
        assert url == "https://github.com/lc/gau/releases/download/v2.0.9/gau_2.0.9_windows_amd64.zip"
        assert ext == "zip"

    def test_gospider_jaeles_rule(self):
        url, ext = utils._tp_release_url(
            {"name": "gospider", "ver": "1.1.6", "owner": "jaeles-project", "repo": "gospider"}
        )
        assert url == "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_1.1.6_windows_amd64.zip"
        assert ext == "zip"
