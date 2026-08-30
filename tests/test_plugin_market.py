#!/usr/bin/env python3
"""
插件市场远程拉取工具测试脚本
Sprint 1 验收专用

测试覆盖：
1. list_available_plugins() - 从 GitHub 拉取插件列表
2. install_plugin(name, version) - 下载、校验、解压、安装
3. uninstall_plugin(name) - 删除插件
4. 钩子注册与调用
5. 断网/限流等异常场景降级
"""

import os
import sys
import json
import tempfile
import shutil
import pytest
from unittest.mock import patch, MagicMock, Mock
from pathlib import Path

# 确保项目根目录在 sys.path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vulnclaw.core.plugin_market import (
    list_available_plugins,
    install_plugin,
    uninstall_plugin,
    list_installed_plugins,
    PluginManager,
    PluginManifestError,
    ChecksumMismatchError,
    PluginNotFoundError,
    DownloadError,
)
from vulnclaw.core.settings import settings


# ============================================================
# Fixtures
# ============================================================

@pytest.fixture
def mock_github_response():
    """模拟 GitHub API 返回的插件列表"""
    return [
        {
            "name": "slack_notifier",
            "version": "1.0.0",
            "description": "Send vulnerability alerts to Slack",
            "sha256": "abc123def456",
            "download_url": "https://github.com/vulnclaw/plugins/releases/download/v1.0.0/slack_notifier.zip",
            "dependencies": ["requests"],
            "hooks": ["on_vuln_found"],
        },
        {
            "name": "nuclei_updater",
            "version": "1.2.0",
            "description": "Auto-update nuclei templates before scan",
            "sha256": "def789ghi012",
            "download_url": "https://github.com/vulnclaw/plugins/releases/download/v1.2.0/nuclei_updater.zip",
            "dependencies": ["subprocess"],
            "hooks": ["on_scan_start"],
        },
        {
            "name": "jira_integration",
            "version": "0.9.0",
            "description": "Create Jira issues from findings",
            "sha256": "jkl345mno678",
            "download_url": "https://github.com/vulnclaw/plugins/releases/download/v0.9.0/jira_integration.zip",
            "dependencies": ["requests"],
            "hooks": ["on_vuln_found"],
        },
    ]


@pytest.fixture
def temp_plugin_dir():
    """临时插件目录，测试后自动清理"""
    tmp_dir = tempfile.mkdtemp(prefix="vulnclaw_plugins_")
    original_plugin_dir = settings.PLUGIN_DIR if hasattr(settings, "PLUGIN_DIR") else "thirdparty/plugins"

    # 临时覆盖
    settings.PLUGIN_DIR = tmp_dir
    yield tmp_dir

    # 清理
    settings.PLUGIN_DIR = original_plugin_dir
    shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================
# 测试用例
# ============================================================

class TestPluginMarket:
    """插件市场核心功能测试"""

    # ---------- 列表拉取 ----------

    @patch("vulnclaw.core.plugin_market.requests.get")
    def test_list_available_plugins_success(self, mock_get, mock_github_response):
        """TC-PM-01: 正常拉取插件列表"""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = mock_github_response
        mock_get.return_value = mock_resp

        plugins = list_available_plugins()

        assert len(plugins) == 3
        assert plugins[0]["name"] == "slack_notifier"
        assert plugins[0]["version"] == "1.0.0"
        assert plugins[1]["name"] == "nuclei_updater"
        assert plugins[2]["name"] == "jira_integration"

    @patch("vulnclaw.core.plugin_market.requests.get")
    def test_list_available_plugins_github_403(self, mock_get):
        """TC-PM-02: GitHub API 返回 403（限流/无权限）"""
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.text = "API rate limit exceeded"
        mock_get.return_value = mock_resp

        with pytest.raises(DownloadError) as exc:
            list_available_plugins()
        assert "403" in str(exc.value) or "rate limit" in str(exc.value).lower()

    @patch("vulnclaw.core.plugin_market.requests.get")
    def test_list_available_plugins_network_timeout(self, mock_get):
        """TC-PM-03: 网络超时降级"""
        mock_get.side_effect = TimeoutError("Connection timed out")

        with pytest.raises(DownloadError) as exc:
            list_available_plugins()
        assert "timeout" in str(exc.value).lower() or "Timeout" in str(exc.value)

    # ---------- 插件安装 ----------

    @patch("vulnclaw.core.plugin_market.list_available_plugins")
    @patch("vulnclaw.core.plugin_market._download_plugin_zip")
    @patch("vulnclaw.core.plugin_market._verify_sha256")
    @patch("vulnclaw.core.plugin_market._extract_plugin")
    @patch("vulnclaw.core.plugin_market._load_plugin_manifest")
    @patch("vulnclaw.core.plugin_market._register_plugin_hooks")
    def test_install_plugin_success(
        self,
        mock_register,
        mock_load_manifest,
        mock_extract,
        mock_verify,
        mock_download,
        mock_list,
        temp_plugin_dir,
        mock_github_response,
    ):
        """TC-PM-04: 正常安装插件"""
        mock_list.return_value = mock_github_response
        mock_download.return_value = "/tmp/plugin.zip"
        mock_verify.return_value = True
        mock_extract.return_value = Path(temp_plugin_dir) / "slack_notifier"
        mock_load_manifest.return_value = {
            "name": "slack_notifier",
            "version": "1.0.0",
            "entry": "main.py",
            "hooks": {"on_vuln_found": "send_slack_alert"},
        }
        mock_register.return_value = True

        result = install_plugin("slack_notifier", version="1.0.0")

        assert result["success"] is True
        assert "slack_notifier" in result["path"]
        assert result["error"] is None

    @patch("vulnclaw.core.plugin_market.list_available_plugins")
    def test_install_plugin_not_found(self, mock_list, temp_plugin_dir):
        """TC-PM-05: 插件不存在"""
        mock_list.return_value = []

        with pytest.raises(PluginNotFoundError) as exc:
            install_plugin("nonexistent_plugin")
        assert "not found" in str(exc.value).lower()

    @patch("vulnclaw.core.plugin_market.list_available_plugins")
    @patch("vulnclaw.core.plugin_market._download_plugin_zip")
    @patch("vulnclaw.core.plugin_market._verify_sha256")
    def test_install_plugin_checksum_mismatch(
        self,
        mock_verify,
        mock_download,
        mock_list,
        temp_plugin_dir,
        mock_github_response,
    ):
        """TC-PM-06: SHA256 校验失败"""
        mock_list.return_value = mock_github_response
        mock_download.return_value = "/tmp/plugin.zip"
        mock_verify.return_value = False  # 校验失败

        with pytest.raises(ChecksumMismatchError) as exc:
            install_plugin("slack_notifier")
        assert "sha256" in str(exc.value).lower() or "checksum" in str(exc.value).lower()

    @patch("vulnclaw.core.plugin_market.list_available_plugins")
    @patch("vulnclaw.core.plugin_market._download_plugin_zip")
    def test_install_plugin_download_failure(
        self,
        mock_download,
        mock_list,
        temp_plugin_dir,
        mock_github_response,
    ):
        """TC-PM-07: 下载失败"""
        mock_list.return_value = mock_github_response
        mock_download.side_effect = DownloadError("Connection refused")

        with pytest.raises(DownloadError) as exc:
            install_plugin("slack_notifier")
        assert "connection" in str(exc.value).lower() or "download" in str(exc.value).lower()

    # ---------- 已安装插件列表 ----------

    @patch("vulnclaw.core.plugin_market._load_installed_manifest")
    def test_list_installed_plugins(self, mock_load, temp_plugin_dir):
        """TC-PM-08: 列出已安装插件"""
        mock_load.return_value = {
            "slack_notifier": {
                "version": "1.0.0",
                "path": str(Path(temp_plugin_dir) / "slack_notifier"),
                "hooks": ["on_vuln_found"],
                "installed_at": "2026-08-29T16:00:00Z",
            },
            "nuclei_updater": {
                "version": "1.2.0",
                "path": str(Path(temp_plugin_dir) / "nuclei_updater"),
                "hooks": ["on_scan_start"],
                "installed_at": "2026-08-29T16:05:00Z",
            },
        }

        plugins = list_installed_plugins()

        assert len(plugins) == 2
        assert plugins[0]["name"] == "slack_notifier"
        assert plugins[1]["name"] == "nuclei_updater"

    # ---------- 卸载插件 ----------

    @patch("vulnclaw.core.plugin_market._load_installed_manifest")
    @patch("vulnclaw.core.plugin_market._save_installed_manifest")
    @patch("shutil.rmtree")
    def test_uninstall_plugin_success(self, mock_rmtree, mock_save, mock_load, temp_plugin_dir):
        """TC-PM-09: 正常卸载插件"""
        mock_load.return_value = {
            "slack_notifier": {
                "version": "1.0.0",
                "path": str(Path(temp_plugin_dir) / "slack_notifier"),
                "hooks": ["on_vuln_found"],
                "installed_at": "2026-08-29T16:00:00Z",
            },
        }

        result = uninstall_plugin("slack_notifier")

        assert result is True
        mock_rmtree.assert_called_once()
        mock_save.assert_called_once()

    @patch("vulnclaw.core.plugin_market._load_installed_manifest")
    def test_uninstall_plugin_not_installed(self, mock_load, temp_plugin_dir):
        """TC-PM-10: 卸载未安装的插件"""
        mock_load.return_value = {}

        with pytest.raises(PluginNotFoundError) as exc:
            uninstall_plugin("not_installed")
        assert "not installed" in str(exc.value).lower()


# ============================================================
# 集成测试（需要真实网络，默认跳过）
# ============================================================

@pytest.mark.integration
@pytest.mark.skip(reason="需要真实 GitHub API 网络，手动运行: pytest -m integration")
class TestPluginMarketIntegration:
    """集成测试：真实 GitHub 拉取（手动运行）"""

    @patch("vulnclaw.core.settings.PLUGIN_DIR", "/tmp/vulnclaw_plugins_integration")
    def test_real_install_slack_notifier(self):
        """真实安装 slack_notifier 插件"""
        result = install_plugin("slack_notifier")
        assert result["success"] is True
        assert Path(result["path"]).exists()

        # 清理
        shutil.rmtree(result["path"], ignore_errors=True)

    def test_real_list_plugins(self):
        """真实拉取 GitHub 插件列表"""
        plugins = list_available_plugins()
        assert len(plugins) >= 1
        assert "slack_notifier" in [p["name"] for p in plugins]


# ============================================================
# 运行入口
# ============================================================

if __name__ == "__main__":
    # 快速运行（跳过集成测试）
    pytest.main([__file__, "-v", "-k", "not integration", "--tb=short"])
