# -*- coding: utf-8 -*-
"""方向3 自举靶机验证：靶机生命周期 + 覆盖度量报告结构。"""
import asyncio

import pytest

from vulnclaw.growth import target_lab as tl


class TestTargetLabLifecycle:
    @pytest.mark.asyncio
    async def test_start_stop_sqli(self):
        lab = tl.TargetLab("reflect_sqli")
        url = await lab.start()
        assert url.startswith("http://127.0.0.1:")
        # 靶机行为：正常 id 回显 1 row；恒假条件回显 0 rows
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(url + "/vuln", params={"id": "1"}) as r:
                assert "1 row" in await r.text()
            async with session.get(url + "/vuln", params={"id": "1' AND '1'='2"}) as r:
                assert "0 rows" in await r.text()
        await lab.stop()
        assert lab.base_url == ""

    @pytest.mark.asyncio
    async def test_unknown_lab_raises(self):
        with pytest.raises(ValueError):
            tl.TargetLab("no_such_lab")

    @pytest.mark.asyncio
    async def test_xss_reflects_payload(self):
        async with tl.TargetLab("reflect_xss") as lab:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(lab.base_url + "/vuln", params={"name": "<script>"}) as r:
                    body = await r.text()
                    assert "<script>" in body

    @pytest.mark.asyncio
    async def test_open_redirect_location(self):
        async with tl.TargetLab("open_redirect") as lab:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(lab.base_url + "/vuln", params={"next": "//evil.example"}, allow_redirects=False) as r:
                    assert r.status == 302
                    assert r.headers.get("Location") == "//evil.example"


class TestEngineLabMap:
    def test_map_contains_core_engines(self):
        for name in ("SQLiEngine", "XSSEngine", "OpenRedirectEngine", "SSRFEngine"):
            assert name in tl.ENGINE_LAB_MAP

    def test_all_mapped_labs_exist_in_factories(self):
        for lab in tl.ENGINE_LAB_MAP.values():
            assert lab in tl._LAB_FACTORIES


class TestRunCoverage:
    @pytest.mark.asyncio
    async def test_report_shape_with_mocked_scan(self, monkeypatch):
        async def _fake_scan(engine_cls, base_url):
            return [{"type": "X", "title": "hit", "url": base_url}]
        monkeypatch.setattr(tl, "_run_engine_scan", _fake_scan)
        report = await tl.run_coverage(engine_names=["SQLiEngine", "XSSEngine"])
        assert report["total"] == 2
        assert report["hit"] == 2
        assert report["miss"] == 0
        assert report["priority_gap"] == []

    @pytest.mark.asyncio
    async def test_expected_hit_respected(self, monkeypatch):
        async def _fake_scan_empty(engine_cls, base_url):
            return []
        monkeypatch.setattr(tl, "_run_engine_scan", _fake_scan_empty)
        report = await tl.run_coverage(engine_names=["SQLiEngine"])
        assert report["total"] == 1
        assert report["hit"] == 0
        assert report["miss"] == 1
        assert report["priority_gap"] and report["priority_gap"][0]["engine"] == "SQLiEngine"

    @pytest.mark.asyncio
    async def test_unmapped_reported(self):
        report = await tl.run_coverage(engine_names=["SQLiEngine", "NoSuchEngineX"])
        assert report["no_lab"] == 1
        assert "NoSuchEngineX" in report["unmapped_engines"]


class TestSummarize:
    def test_summarize_gap(self):
        report = {
            "priority_gap": [{"engine": "E1", "lab": "reflect_sqli", "hint": "h"}],
            "unmapped_engines": ["E2"],
        }
        lines = tl.summarize_gap_priorities(report)
        assert len(lines) == 2
        assert any("E1" in ln for ln in lines)

    def test_summarize_all_hit(self):
        assert tl.summarize_gap_priorities({"priority_gap": [], "unmapped_engines": []}) == \
            ["当前映射靶机全部命中，无覆盖缺口"]