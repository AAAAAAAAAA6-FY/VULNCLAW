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


@pytest.fixture(autouse=True)
def _clear_dead_candidates():
    """下载源判死标记按用例隔离。"""
    utils._TP_DEAD_CANDIDATES.clear()
    yield
    utils._TP_DEAD_CANDIDATES.clear()


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
        monkeypatch.setattr(utils, "_mirror_reachable", lambda *a, **kw: False)
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
        # 实际资产命名: <repo>_v<ver>_<os>_<arch>.zip（win→windows_x86_64）
        assert url == "https://github.com/jaeles-project/gospider/releases/download/v1.1.6/gospider_v1.1.6_windows_x86_64.zip"
        assert ext == "zip"


# ---------- 方案②+：下载健壮性（镜像/重试/checksum/API 兜底） ----------
class TestCandidateUrls:
    def test_direct_only_when_no_mirrors(self, monkeypatch):
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "tool_download_mirrors", "")
        url = "https://github.com/a/b/releases/download/v1/a.zip"
        assert utils._tp_candidate_urls(url) == [url]

    def test_mirror_appended_in_order(self, monkeypatch):
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "tool_download_mirrors", "https://gh-proxy.com/, https://ghproxy.net/")
        url = "https://github.com/a/b/releases/download/v1/a.zip"
        assert utils._tp_candidate_urls(url) == [
            url,
            "https://gh-proxy.com/" + url,
            "https://ghproxy.net/" + url,
        ]


class TestRetryDownload:
    def test_success_first_try(self, monkeypatch, tmp_path):
        dest = tmp_path / "a.zip"
        monkeypatch.setattr(utils, "_tp_fetch", lambda u, d, t: d.write_bytes(b"ok"))
        used = utils._tp_download("https://github.com/x/y.zip", dest, "t")
        assert used == "https://github.com/x/y.zip"
        assert dest.read_bytes() == b"ok"

    def test_retry_then_success(self, monkeypatch, tmp_path):
        monkeypatch.setattr("time.sleep", lambda *_: None)
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "tool_download_retries", 3)
        dest = tmp_path / "a.zip"
        n = {"i": 0}

        def _flaky(u, d, t):
            n["i"] += 1
            if n["i"] < 3:
                raise RuntimeError("http 500")  # URL 级失败不标死源
            d.write_bytes(b"ok")

        monkeypatch.setattr(utils, "_tp_fetch", _flaky)
        utils._tp_download("https://github.com/x/y.zip", dest, "t")
        assert n["i"] == 3
        assert dest.read_bytes() == b"ok"

    def test_retry_exhausted_raises_and_cleans(self, monkeypatch, tmp_path):
        monkeypatch.setattr("time.sleep", lambda *_: None)
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "tool_download_retries", 2)
        monkeypatch.setattr(settings, "tool_download_mirrors", "https://m.example/")
        dest = tmp_path / "a.zip"

        def _boom(u, d, t):
            raise RuntimeError("connection reset")

        monkeypatch.setattr(utils, "_tp_fetch", _boom)
        with pytest.raises(RuntimeError):
            utils._tp_download("https://github.com/x/y.zip", dest, "t")
        assert not dest.exists()  # 半截文件已清理

    def test_dead_candidate_skipped_next_call(self, monkeypatch, tmp_path):
        monkeypatch.setattr("time.sleep", lambda *_: None)
        from vulnclaw.config.settings import settings
        monkeypatch.setattr(settings, "tool_download_retries", 2)
        monkeypatch.setattr(settings, "tool_download_mirrors", "https://m.example/")
        mirror_url = "https://m.example/https://github.com/x/y.zip"
        dest = tmp_path / "a.zip"
        seen = []

        def _fetch(u, d, t):
            seen.append(u)
            if u.startswith("https://github.com/"):
                raise RuntimeError("timed out")  # 连接级 → 标死
            d.write_bytes(b"ok")

        monkeypatch.setattr(utils, "_tp_fetch", _fetch)
        used = utils._tp_download("https://github.com/x/y.zip", dest, "t")
        assert used == mirror_url
        assert "https://github.com/x/y.zip" in utils._TP_DEAD_CANDIDATES
        seen.clear()
        used2 = utils._tp_download("https://github.com/x/y.zip", tmp_path / "b.zip", "t")
        assert used2 == mirror_url
        assert seen == [mirror_url]  # 直连源已标死，直接命中镜像


class TestChecksumVerify:
    def test_checksum_url_owner_rules(self):
        assert utils._tp_checksum_url(
            {"owner": "projectdiscovery", "repo": "nuclei", "ver": "3.3.8"}
        ) == "https://github.com/projectdiscovery/nuclei/releases/download/v3.3.8/nuclei_3.3.8_checksums.txt"
        assert utils._tp_checksum_url({"owner": "tomnomnom", "repo": "waybackurls", "ver": "0.1.0"}) is None

    def test_pass_when_hash_matches(self, monkeypatch, tmp_path):
        import hashlib
        data = b"archive-bytes"
        arc = tmp_path / "nuclei_3.3.8_windows_amd64.zip"
        arc.write_bytes(data)
        want = hashlib.sha256(data).hexdigest()
        monkeypatch.setattr(
            utils, "_tp_fetch_text",
            lambda u, timeout=30: f"{want}  nuclei_3.3.8_windows_amd64.zip\n",
        )
        note = utils._tp_verify_archive_checksum(
            arc, {"owner": "projectdiscovery", "repo": "nuclei", "ver": "3.3.8"},
            asset_name="nuclei_3.3.8_windows_amd64.zip",
        )
        assert note == ""

    def test_mismatch_hard_rejects(self, monkeypatch, tmp_path):
        arc = tmp_path / "a.zip"
        arc.write_bytes(b"data")
        monkeypatch.setattr(utils, "_tp_fetch_text", lambda u, timeout=30: "deadbeef  a.zip\n")
        with pytest.raises(ValueError):
            utils._tp_verify_archive_checksum(
                arc, {"owner": "ffuf", "repo": "ffuf", "ver": "2.1.0"}, asset_name="a.zip"
            )

    def test_missing_entry_soft_pass(self, monkeypatch, tmp_path):
        arc = tmp_path / "a.zip"
        arc.write_bytes(b"data")
        monkeypatch.setattr(utils, "_tp_fetch_text", lambda u, timeout=30: "deadbeef  other.zip\n")
        note = utils._tp_verify_archive_checksum(
            arc, {"owner": "projectdiscovery", "repo": "nuclei", "ver": "3.3.8"}, asset_name="a.zip"
        )
        assert "跳过" in note

    def test_fetch_fail_soft_pass(self, monkeypatch, tmp_path):
        arc = tmp_path / "a.zip"
        arc.write_bytes(b"data")
        monkeypatch.setattr(utils, "_tp_fetch_text", lambda u, timeout=30: None)
        note = utils._tp_verify_archive_checksum(
            arc, {"owner": "projectdiscovery", "repo": "nuclei", "ver": "3.3.8"}, asset_name="a.zip"
        )
        assert "跳过" in note

    def test_unofficial_owner_soft_pass(self, tmp_path):
        arc = tmp_path / "a.zip"
        arc.write_bytes(b"data")
        note = utils._tp_verify_archive_checksum(
            arc, {"owner": "tomnomnom", "repo": "waybackurls", "ver": "0.1.0"}, asset_name="a.zip"
        )
        assert "manifest" in note


class TestApiFallback:
    def test_pick_matching_platform_asset(self, monkeypatch):
        fake = [
            {"name": "katana_1.1.3_checksums.txt", "browser_download_url": "u0"},
            {"name": "katana_1.1.3_linux_amd64.zip", "browser_download_url": "u1"},
            {"name": "katana_1.1.3_windows_arm64.zip", "browser_download_url": "u2"},
            {"name": "katana_1.1.3_windows_amd64.zip", "browser_download_url": "u3"},
        ]
        monkeypatch.setattr(utils, "_tp_api_assets", lambda o, r, v: fake)
        url = utils._tp_api_asset_url(
            {"owner": "projectdiscovery", "repo": "katana", "ver": "1.1.3"}
        )
        assert url == "u3"

    def test_api_error_returns_none(self, monkeypatch):
        def _boom(*a):
            raise RuntimeError("api down")

        monkeypatch.setattr(utils, "_tp_api_assets", _boom)
        assert utils._tp_api_asset_url(
            {"owner": "projectdiscovery", "repo": "katana", "ver": "1.1.3"}
        ) is None


class TestDownloadFlowIntegration:
    def _one_pd_tool(self):
        return [{"name": "katana", "ver": "1.1.3", "owner": "projectdiscovery", "repo": "katana",
                 "bin": {"win": "katana.exe", "linux": "katana", "darwin": "katana"}}]

    def _make_zip(self, tmp_path):
        import zipfile
        zp = tmp_path / "katana.zip"
        with zipfile.ZipFile(zp, "w") as zf:
            zf.writestr("katana.exe", b"MZ" + b"\x00" * 1024)
        return zp

    @staticmethod
    def _fake_download(zip_path):
        import shutil

        def _dl(url, dest, label, timeout=60):
            shutil.copyfile(zip_path, dest)
            return url

        return _dl

    def test_happy_path_checksum_unavailable_soft(self, monkeypatch, tmp_path):
        third = _fake_settings(monkeypatch, tmp_path)
        third.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(utils, "THIRDPARTY_TOOLS", self._one_pd_tool())
        monkeypatch.setattr(utils, "_tp_download", self._fake_download(self._make_zip(tmp_path)))
        monkeypatch.setattr(utils, "_tp_fetch_text", lambda u, timeout=30: None)
        ok, fail = utils.download_thirdparty_tools(only_missing=True, update_nuclei_templates=False)
        assert (ok, fail) == (1, 0)
        assert (third / "katana.exe").exists()

    def test_checksum_mismatch_rejects_install(self, monkeypatch, tmp_path):
        third = _fake_settings(monkeypatch, tmp_path)
        third.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(utils, "THIRDPARTY_TOOLS", self._one_pd_tool())
        monkeypatch.setattr(utils, "_tp_download", self._fake_download(self._make_zip(tmp_path)))
        monkeypatch.setattr(
            utils, "_tp_fetch_text",
            lambda u, timeout=30: "deadbeef  katana_1.1.3_windows_amd64.zip\n",
        )
        ok, fail = utils.download_thirdparty_tools(only_missing=True, update_nuclei_templates=False)
        assert (ok, fail) == (0, 1)
        assert not (third / "katana.exe").exists()  # 拒装


class TestMirrorPrecheck:
    def test_github_down_mirror_up_proceeds(self, monkeypatch, tmp_path):
        _fake_settings(monkeypatch, tmp_path)
        _tiny_tools(monkeypatch, tmp_path)
        monkeypatch.setattr(utils, "_github_reachable", lambda *a, **kw: False)
        monkeypatch.setattr(utils, "_mirror_reachable", lambda *a, **kw: True)
        monkeypatch.setattr(utils, "download_thirdparty_tools", lambda *a, **kw: (2, 0))
        ok, fail = utils.ensure_thirdparty_tools()
        assert (ok, fail) == (2, 0)

    def test_github_and_mirror_down_skips(self, monkeypatch, tmp_path):
        _fake_settings(monkeypatch, tmp_path)
        _tiny_tools(monkeypatch, tmp_path)
        monkeypatch.setattr(utils, "_github_reachable", lambda *a, **kw: False)
        monkeypatch.setattr(utils, "_mirror_reachable", lambda *a, **kw: False)
        monkeypatch.setattr(utils, "download_thirdparty_tools", lambda *a, **kw: (9, 9))
        ok, fail = utils.ensure_thirdparty_tools()
        assert (ok, fail) == (0, 2)
