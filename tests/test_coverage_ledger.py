# -*- coding: utf-8 -*-
"""SP3 机器事实覆盖账本：record / track / rollup / gaps / write。"""
import json
import os

import pytest

from vulnclaw.core.coverage import CoverageLedger, run_engine_tracked


class TestRecordAndRollup:
    def test_rollup_engine_asset(self):
        l = CoverageLedger(target="http://t.example.com")
        l.record_run("http://t.example.com", "sqli", findings=2)
        l.record_run("http://t.example.com", "xss", findings=1)
        l.record_skipped("http://t.example.com", "ssrf", "无参数入口")
        snap = l.snapshot()
        assert snap["stats"]["engine_runs"] == 3
        assert snap["rollup"]["by_engine"]["sqli"]["findings"] == 2
        assert snap["rollup"]["by_asset"]["http://t.example.com"]["skipped"] == 1

    def test_exception_track_marks_failed(self):
        l = CoverageLedger()
        with pytest.raises(ValueError):
            with l.track("http://t.example.com", "cmdi"):
                raise ValueError("boom")
        snap = l.snapshot()
        assert snap["rollup"]["by_engine"]["cmdi"]["failed"] == 1

    def test_track_success_records_ran(self):
        l = CoverageLedger()
        with l.track("http://t.example.com", "lfi"):
            pass
        snap = l.snapshot()
        assert snap["rollup"]["by_engine"]["lfi"]["ran"] == 1


class TestGaps:
    def test_never_ran_engine_reported(self):
        l = CoverageLedger()
        l.record_run("http://t.example.com", "sqli")
        gaps = l.gaps(engine_fullset=["sqli", "xss", "ssrf"])
        issues = {g["engine"]: g["issue"] for g in gaps}
        assert issues["xss"] == "never_ran"
        assert "sqli" not in issues


class TestWrite:
    def test_write_json(self, tmp_path):
        l = CoverageLedger(target="http://t.example.com")
        l.record_run("http://t.example.com", "sqli", findings=1)
        out = l.write(out_path=str(tmp_path / "cov.json"), complete=False)
        assert os.path.exists(out)
        with open(out, encoding="utf-8") as f:
            obj = json.load(f)
        assert obj["source"] == "machine_observed"
        assert obj["complete"] is False
        assert obj["schema_version"] == 1
        assert obj["rollup"]["by_engine"]["sqli"]["ran"] == 1

    def test_complete_flag(self):
        l = CoverageLedger()
        l.record_run("a", "e")
        assert l.snapshot(complete=True)["complete"] is True


class TestTrackedWrapper:
    @pytest.mark.asyncio
    async def test_run_engine_tracked_without_ledger(self, monkeypatch):
        # 无 ledger 时等价直接调用（不抛错；mock run_engine 避免真实网络）
        async def _fake(name, **kw):
            return [{"type": "X", "url": kw.get("target") or kw.get("url") or ""}]
        monkeypatch.setattr("vulnclaw.core.scanner.run_engine", _fake)
        findings = await run_engine_tracked("sqli", None, target="http://t.example.com")
        assert isinstance(findings, list)
        assert len(findings) == 1

    @pytest.mark.asyncio
    async def test_run_engine_tracked_records(self, monkeypatch):
        async def _fake(name, **kw):
            return [{"type": "X", "url": kw.get("target") or ""}]
        monkeypatch.setattr("vulnclaw.core.scanner.run_engine", _fake)
        l = CoverageLedger()
        await run_engine_tracked("xss", l, target="http://t.example.com")
        snap = l.snapshot()
        assert snap["rollup"]["by_engine"]["xss"]["ran"] >= 1

    @pytest.mark.asyncio
    async def test_run_engine_tracked_failure_recorded(self, monkeypatch):
        async def _boom(name, **kw):
            raise RuntimeError("engine blew up")
        monkeypatch.setattr("vulnclaw.core.scanner.run_engine", _boom)
        l = CoverageLedger()
        with pytest.raises(RuntimeError):
            await run_engine_tracked("lfi", l, target="http://t.example.com")
        snap = l.snapshot()
        assert snap["rollup"]["by_engine"]["lfi"]["failed"] == 1