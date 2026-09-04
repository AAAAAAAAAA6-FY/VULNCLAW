# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""工具治理层（Tool Governance）回归测试。

覆盖：目录加载 / 能力降级链解析（不健康跳过+内置兜底）/ 供应链完整性
（ok→unpinned→篡改隔离+审计链）/ 健康降级与恢复 / 调用审计 JSONL /
run_tool 治理包装器接线。

全部离线（假二进制 + monkeypatch resolve_tool_path；base_dir 隔离运行数据）。
"""
import hashlib
import json
import time
from pathlib import Path

import pytest

from vulnclaw.core.tool_governance import get_governance


@pytest.fixture
def gov(tmp_path, monkeypatch):
    """隔离实例：运行数据进 tmp_path；路径解析指向 tmp 假二进制。"""
    g = get_governance(base_dir=str(tmp_path))

    def fake_resolve(name):
        p = tmp_path / "bin" / f"{name}.exe"
        return str(p) if p.is_file() else None  # 未安装 → None（与真函数语义一致）

    monkeypatch.setattr("vulnclaw.core.tool_registry.resolve_tool_path", fake_resolve)
    (tmp_path / "bin").mkdir(exist_ok=True)
    return g


def _make_bin(tmp_path, name, content=b"MZ-fake-binary") -> Path:
    p = tmp_path / "bin" / f"{name}.exe"
    p.write_bytes(content)
    return p


def _pin_manifest(gov, tmp_path, name, content: bytes, ver="1.0.0") -> str:
    third = tmp_path / "thirdparty"
    third.mkdir(exist_ok=True)
    h = hashlib.sha256(content).hexdigest()
    (third / "tool_manifest.json").write_text(
        json.dumps({name: {"ver": ver, "sha256": h}}), encoding="utf-8")
    gov._thirdparty_dir = third
    return h


# ============================================================
# 目录
# ============================================================
def test_directory_loads_and_has_capabilities(gov):
    d = gov.directory()
    assert d["version"] == 1
    assert "nuclei" in d["tools"]
    cap = d["capabilities"]["endpoint_discovery"]
    assert "waybackurls" in cap["candidates"]
    assert cap["builtin_fallback"] == "crawler_bfs"


def test_get_tool_spec(gov):
    spec = gov.get_tool("nuclei")
    assert spec["capability"] == "template_scan"
    assert spec["ver"] == "3.3.8"
    assert gov.get_tool("no-such-tool") is None


# ============================================================
# 能力降级链
# ============================================================
def test_resolve_capability_skips_unhealthy(gov, tmp_path):
    _make_bin(tmp_path, "waybackurls")
    _make_bin(tmp_path, "gau")
    for _ in range(3):
        gov.record_result("waybackurls", success=False, error="segfault")
    resolved = gov.resolve_capability("endpoint_discovery")
    by_tool = {e["tool"]: e for e in resolved}
    assert by_tool["waybackurls"]["usable"] is False
    assert by_tool["gau"]["usable"] is True


def test_resolve_capability_builtin_fallback_when_all_down(gov):
    resolved = gov.resolve_capability("endpoint_discovery")
    assert all(not e.get("usable") for e in resolved if not e.get("builtin"))
    assert any(e.get("tool") == "crawler_bfs" and e.get("builtin") for e in resolved)


def test_resolve_capability_unknown(gov):
    assert gov.resolve_capability("no-such-capability") == []


# ============================================================
# 供应链完整性
# ============================================================
def test_integrity_unpinned_without_manifest(gov, tmp_path):
    _make_bin(tmp_path, "gau")
    assert gov.integrity_check("gau")["status"] == "unpinned"


def test_integrity_ok_with_manifest_hash(gov, tmp_path):
    content = b"nuclei-binary-v3.3.8"
    p = _make_bin(tmp_path, "nuclei", content=content)
    _pin_manifest(gov, tmp_path, "nuclei", content, ver="3.3.8")
    res = gov.integrity_check("nuclei", force=True)
    assert res["status"] == "ok"
    assert res["sha256"] == hashlib.sha256(content).hexdigest()
    assert p.exists()


def test_integrity_quarantines_on_tamper_and_audits(gov, tmp_path):
    """二进制被替换 → 隔离（改名）+ 原路径腾空 + 治理事件入哈希链。"""
    p = _make_bin(tmp_path, "nuclei", content=b"original-content")
    _pin_manifest(gov, tmp_path, "nuclei", b"original-content", ver="3.3.8")

    assert gov.integrity_check("nuclei", force=True)["status"] == "ok"

    p.write_bytes(b"REPLACED-MALICIOUS-CONTENT")
    res = gov.integrity_check("nuclei", force=True)
    assert res["status"] == "quarantined"
    assert not p.exists()                       # 原路径腾空（防执行被替换二进制）
    assert Path(res["quarantined_to"]).is_file()  # 隔离文件保留作证据
    chain = json.loads(gov.chain_file.read_text(encoding="utf-8"))
    assert chain["entries"] and chain["chain_root"] != "0" * 64
    events = json.loads(gov.events_file.read_text(encoding="utf-8"))
    assert events[-1]["kind"] == "integrity_mismatch"


# ============================================================
# 健康降级
# ============================================================
def test_health_degrades_after_consecutive_failures(gov):
    for _ in range(3):
        gov.record_result("nuclei", success=False, error="timeout")
    assert gov.is_healthy("nuclei") is False
    snap = gov.health_snapshot("nuclei")
    assert snap["consecutive_failures"] == 3
    assert snap["degraded_until"] > time.time()


def test_health_recovers_on_success_and_ttl_expiry(gov):
    for _ in range(3):
        gov.record_result("katana", success=False, error="x")
    assert gov.is_healthy("katana") is False
    gov._health_state["katana"]["degraded_until"] = time.time() - 1
    assert gov.is_healthy("katana") is True     # TTL 过期 → 恢复观察
    gov.record_result("katana", success=True, duration_ms=10)
    assert gov.health_snapshot("katana")["consecutive_failures"] == 0


# ============================================================
# 调用审计
# ============================================================
def test_usage_audit_jsonl(gov):
    gov.record_result("nuclei", success=True, duration_ms=42)
    gov.record_result("gau", success=False, duration_ms=15, error="boom")
    rows = [json.loads(x) for x in
            gov.usage_file.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert len(rows) == 2
    assert rows[0]["tool"] == "nuclei" and rows[0]["success"] is True
    assert rows[1]["tool"] == "gau" and rows[1]["error"] == "boom"


# ============================================================
# run_tool 治理包装器接线
# ============================================================
@pytest.mark.asyncio
async def test_run_tool_wrapper_records_audit(monkeypatch, tmp_path):
    """包装器：成功路径写调用审计与健康记录（不真执行子进程）。"""
    g = get_governance(base_dir=str(tmp_path))
    # run_tool 内部惰性 import get_governance → 把单例指到隔离实例
    import vulnclaw.core.tool_governance as tg_mod

    monkeypatch.setattr(tg_mod, "get_governance", lambda base_dir=None: g)
    import vulnclaw.core.tool_registry as tr

    async def fake_impl(name, **kwargs):
        return {"success": True, "stdout": "ok", "stderr": "", "returncode": 0}

    monkeypatch.setattr(tr, "_run_tool_impl", fake_impl)
    res = await tr.run_tool("nuclei", args=["-v"])
    assert res["success"] is True
    rows = [json.loads(x) for x in
            g.usage_file.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert rows and rows[-1]["tool"] == "nuclei" and rows[-1]["success"] is True


@pytest.mark.asyncio
async def test_run_tool_wrapper_survives_impl_crash(monkeypatch, tmp_path):
    """impl 抛异常 → 治理钩子照常记账（finally 保证），业务异常正常上抛。"""
    g = get_governance(base_dir=str(tmp_path))
    import vulnclaw.core.tool_governance as tg_mod

    monkeypatch.setattr(tg_mod, "get_governance", lambda base_dir=None: g)
    import vulnclaw.core.tool_registry as tr

    async def boom(name, **kwargs):
        raise RuntimeError("impl crashed")

    monkeypatch.setattr(tr, "_run_tool_impl", boom)
    with pytest.raises(RuntimeError):
        await tr.run_tool("gau", args=["x"])
    rows = [json.loads(x) for x in
            g.usage_file.read_text(encoding="utf-8").splitlines() if x.strip()]
    assert rows and rows[-1]["tool"] == "gau" and rows[-1]["success"] is False


@pytest.mark.asyncio
async def test_run_tool_wrapper_tolerates_governance_crash(monkeypatch, tmp_path):
    """治理层本身崩溃 → 工具执行不受任何影响（设计红线）。"""
    import vulnclaw.core.tool_registry as tr

    def broken_gov(base_dir=None):
        raise RuntimeError("governance down")

    monkeypatch.setattr(tg_mod_getter(), "get_governance", broken_gov, raising=False)

    async def fake_impl(name, **kwargs):
        return {"success": True}

    monkeypatch.setattr(tr, "_run_tool_impl", fake_impl)
    res = await tr.run_tool("nuclei")
    assert res["success"] is True  # 治理挂了照样执行


def tg_mod_getter():
    import vulnclaw.core.tool_governance as tg

    return tg
