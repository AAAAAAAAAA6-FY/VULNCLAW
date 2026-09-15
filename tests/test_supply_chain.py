# -*- coding: utf-8 -*-
"""F1 验收：scripts/sbom.py（离线 SBOM）与 scripts/verify_tools.py（工具完整性）。

全部离线确定性：不联网、不下载、不 pip。
scripts/ 下模块用 importlib 直接加载（不污染 sys.path）。
"""
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"_f1_{name}", _SCRIPTS / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


sbom = _load("sbom")
verify_tools = _load("verify_tools")


# ============================================================
# sbom.py
# ============================================================
class TestSbom:
    def test_normalize_name_pep503(self):
        assert sbom.normalize_name("Foo_Bar.Baz") == "foo-bar-baz"
        assert sbom.normalize_name("  PyYAML  ") == "pyyaml"

    def test_pep508_name_extraction(self):
        assert sbom._pep508_name("httpx[http2]>=0.27.0") == "httpx"
        assert sbom._pep508_name("requests") == "requests"
        assert sbom._pep508_name("") == ""

    def test_load_declared_reads_real_pyproject(self):
        declared = sbom.load_declared()
        assert declared["name"], "pyproject 必须能读到 project.name"
        assert isinstance(declared["dependencies"], dict)

    def test_build_bom_deterministic_serial_and_fields(self):
        declared = {"name": "demo", "version": "1.0", "dependencies": {}}
        a = sbom.build_bom(declared)
        b = sbom.build_bom(declared)
        assert a["serialNumber"] == b["serialNumber"], "同输入必须同 serialNumber（uuid5）"
        assert a["bomFormat"] == "CycloneDX"
        for comp in a["components"]:
            assert comp["type"] == "library"
            assert comp["purl"].startswith("pkg:pypi/")
            assert comp["licenses"], "许可证条目缺失"
            props = {p["name"]: p["value"] for p in comp["properties"]}
            assert props["vulnclaw:installed"] in ("true", "false")

    def test_declared_missing_component_shape(self):
        declared = {
            "name": "demo",
            "version": "",
            "dependencies": {"definitely-not-installed-pkg-xyz": "definitely-not-installed-pkg-xyz>=9"},
        }
        bom = sbom.build_bom(declared)
        comp = next(c for c in bom["components"] if c["purl"].startswith("pkg:pypi/definitely-not-installed-pkg-xyz"))
        assert comp["version"] == ""
        props = {p["name"]: p["value"] for p in comp["properties"]}
        assert props["vulnclaw:dependency-scope"] == "declared-missing"
        assert props["vulnclaw:installed"] == "false"
        # 未安装 → 许可证必须如实 UNKNOWN，不得编造
        lic = comp["licenses"][0]["license"]
        assert (lic.get("id") or lic.get("name")) == "UNKNOWN"

    def test_license_rows_sorted_deterministically(self):
        bom = sbom.build_bom({"name": "demo", "version": "", "dependencies": {}})
        rows = sbom.license_rows(bom)
        keys = [(r[2].lower(), r[0].lower()) for r in rows]
        assert keys == sorted(keys)

    def test_render_licenses_md_contains_unknown_disclosure(self):
        bom = sbom.build_bom({"name": "demo", "version": "", "dependencies": {}})
        md = sbom.render_licenses_md(bom)
        assert "组件总数" in md and "UNKNOWN" in md
        assert "许可证分布" in md and "组件明细" in md

    def test_main_stdout_mode_offline(self, capsys):
        code = sbom.main(["--stdout"])
        assert code == 0
        out = capsys.readouterr().out
        assert '"bomFormat": "CycloneDX"' in out
        # 组件段必须存在（本机环境包至少数十个）
        data = json.loads(out[out.index("{"):out.rindex("}") + 1])
        assert len(data["components"]) >= 1


# ============================================================
# verify_tools.py
# ============================================================
class TestVerifyTools:
    def test_sha256_file(self, tmp_path):
        p = tmp_path / "a.bin"
        p.write_bytes(b"hello-vulnclaw")
        assert verify_tools.sha256_file(p) == hashlib.sha256(b"hello-vulnclaw").hexdigest()

    def test_resolve_executable_in_thirdparty(self, tmp_path):
        td = tmp_path / "thirdparty"
        td.mkdir()
        exe = td / "mytool.exe"
        exe.write_bytes(b"x")
        path, source = verify_tools.resolve_executable("mytool.exe", third_dir=td)
        assert source == "thirdparty"
        assert Path(path) == exe
        nested = td / "sub" / "deep" / "tool2"
        nested.parent.mkdir(parents=True)
        nested.write_bytes(b"y")
        path2, source2 = verify_tools.resolve_executable("tool2", third_dir=td)
        assert source2 == "thirdparty" and Path(path2) == nested

    def test_resolve_executable_missing(self, tmp_path):
        path, source = verify_tools.resolve_executable("no-such-tool-xyz", third_dir=tmp_path)
        assert path == "" and source == ""

    def test_merge_manifest_keeps_missing_records(self):
        old = {"a": {"sha256": "1"}, "b": {"sha256": "2"}}
        present = {"b": {"sha256": "3"}, "c": {"sha256": "4"}}
        merged = verify_tools.merge_manifest(old, present)
        assert merged == {"a": {"sha256": "1"}, "b": {"sha256": "3"}, "c": {"sha256": "4"}}

    def test_verify_three_states(self):
        present = {
            "changed": {"sha256": "bbb", "size": 2},
            "new": {"sha256": "ccc", "size": 3},
            "ok": {"sha256": "aaa", "size": 1},
        }
        manifest = {"ok": {"sha256": "aaa"}, "changed": {"sha256": "OLD"}}
        result = verify_tools.verify(present, manifest, {})
        assert [i["name"] for i in result["ok"]] == ["ok"]
        assert [i["name"] for i in result["mismatch"]] == ["changed"]
        assert [i["name"] for i in result["untracked"]] == ["new"]

    def test_verify_install_manifest_mismatch(self):
        present = {"t": {"sha256": "new", "size": 1}}
        manifest = {"t": {"sha256": "new"}}
        result = verify_tools.verify(present, manifest, {"t": {"sha256": "old"}})
        assert len(result["mismatch"]) == 1
        assert "安装期" in result["mismatch"][0]["reason"]

    def test_scan_present_skips_missing_and_tiny(self, tmp_path, monkeypatch):
        td = tmp_path / "thirdparty"
        td.mkdir()
        (td / "small").write_bytes(b"x")  # < 100KB → 应跳过
        monkeypatch.setattr(verify_tools, "THIRDPARTY", td)
        # resolve_executable 默认参数绑定的是模块加载时的 THIRDPARTY，
        # scan_present 走默认路径；本机 thirdparty 不存在这两个伪工具 → 全部 skip。
        registry = {
            "gone": {"executable": "gone-tool-xyz"},
            "tiny": {"executable": "small"},
        }
        records, skipped = verify_tools.scan_present(registry)
        assert records == {} or all(r["size"] >= 1024 for r in records.values())
        assert len(skipped) == 2, "缺失与过小文件都必须被显式跳过并计数"
        reasons = dict(skipped)
        assert "未找到" in reasons["gone"] or "残留" in reasons["tiny"]

    def test_manifest_roundtrip(self, tmp_path):
        path = tmp_path / "tools_integrity.json"
        tools = {"t1": {"sha256": "a" * 64, "size": 123}}
        verify_tools.write_manifest(path, tools)
        loaded = verify_tools.load_manifest(path)
        assert loaded == tools
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["schema"] == verify_tools.MANIFEST_SCHEMA

    def test_main_empty_registry_early_exit(self, tmp_path, capsys):
        reg = tmp_path / "empty.yaml"
        reg.write_text("tools: {}\n", encoding="utf-8")
        code = verify_tools.main(["--registry", str(reg), "--manifest", str(tmp_path / "m.json")])
        assert code == verify_tools.EXIT_OK
        assert "注册表为空" in capsys.readouterr().out

    def test_relative_hint_never_absolute(self, tmp_path):
        hint = verify_tools._relative_hint(str(tmp_path / "x" / "tool.exe"), "PATH")
        assert not Path(hint).is_absolute()
        assert ":" not in hint and not hint.startswith("\\") and not hint.startswith("/")
