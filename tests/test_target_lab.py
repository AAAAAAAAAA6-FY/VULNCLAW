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
        for name in ("SQLiEngine", "XSSEngine", "OpenRedirectEngine", "SSRFEngine", "LFIEngine"):
            assert name in tl.ENGINE_LAB_MAP

    def test_all_mapped_labs_exist_in_factories(self):
        for lab in tl.ENGINE_LAB_MAP.values():
            assert lab in tl._LAB_FACTORIES

    def test_lab_param_covers_all_labs(self):
        for lab in tl.ENGINE_LAB_MAP.values():
            assert lab in tl._LAB_PARAM


class TestLfiLab:
    """LFI 靶机：归一化标记文件，Windows 可确定性复现。"""

    @pytest.mark.asyncio
    async def test_winini_backslash_payload_hits(self):
        async with tl.TargetLab("lfi_read") as lab:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    lab.base_url + "/vuln", params={"file": "..\\..\\..\\windows\\win.ini"}
                ) as r:
                    body = await r.text()
                    assert "[extensions]" in body

    @pytest.mark.asyncio
    async def test_etc_passwd_hits_strong_marker(self):
        async with tl.TargetLab("lfi_read") as lab:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    lab.base_url + "/vuln", params={"file": "../../../../etc/passwd"}
                ) as r:
                    body = await r.text()
                    assert "root:x:0:0:" in body

    @pytest.mark.asyncio
    async def test_double_encoded_variant_hits(self):
        # ..%252f 双重编码 → 解两次后归一化仍应命中 win.ini
        async with tl.TargetLab("lfi_read") as lab:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    lab.base_url + "/vuln", params={"file": "..%252f..%252fwindows%252fwin.ini"}
                ) as r:
                    assert "[extensions]" in await r.text()

    @pytest.mark.asyncio
    async def test_baseline_and_benign_no_indicator(self):
        async with tl.TargetLab("lfi_read") as lab:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(lab.base_url + "/vuln") as r:
                    assert "Target Lab Index Page" in await r.text()
                async with session.get(
                    lab.base_url + "/vuln", params={"file": "test.txt"}
                ) as r:
                    body = await r.text()
                    assert "root:x:0:0:" not in body and "[extensions]" not in body

    @pytest.mark.asyncio
    async def test_real_lfi_engine_hits_lab(self):
        """真引擎端到端：LFIEngine(check 型) 对 lfi_read 靶机确定性命中。"""
        from vulnclaw.engines.web_engines import LFIEngine
        async with tl.TargetLab("lfi_read") as lab:
            findings = await tl._run_engine_scan(LFIEngine, lab.base_url, param="file")
        assert findings, "LFIEngine 未命中 lfi_read 靶机（Windows 确定性复现失败）"
        assert "文件包含" in str(findings[0].get("type", ""))


class TestCoverageScore:
    def test_perfect_score_grade_a(self):
        s = tl.coverage_score({"total": 5, "hit": 5, "miss": 0, "no_lab": 2})
        assert s["score"] == 100 and s["grade"] == "A"
        assert s["gauge"] == "[##########] 100%"
        assert s["untested_no_lab"] == 2

    def test_zero_score_grade_d(self):
        s = tl.coverage_score({"total": 4, "hit": 0, "miss": 4})
        assert s["score"] == 0 and s["grade"] == "D"
        assert s["gauge"] == "[----------] 0%"

    def test_partial_grades(self):
        assert tl.coverage_score({"total": 10, "hit": 8})["grade"] == "B"
        assert tl.coverage_score({"total": 10, "hit": 6})["grade"] == "C"

    def test_empty_report_zero_not_inflated(self):
        s = tl.coverage_score({})
        assert s["score"] == 0 and s["tested"] == 0

    @pytest.mark.asyncio
    async def test_run_coverage_embeds_score(self, monkeypatch):
        async def _fake_scan(engine_cls, base_url, param=""):
            return [{"type": "X", "url": base_url}]
        monkeypatch.setattr(tl, "_run_engine_scan", _fake_scan)
        report = await tl.run_coverage(engine_names=["SQLiEngine"])
        assert report["score"]["score"] == 100 and report["score"]["grade"] == "A"


class TestRunCoverage:
    @pytest.mark.asyncio
    async def test_report_shape_with_mocked_scan(self, monkeypatch):
        async def _fake_scan(engine_cls, base_url, param=""):
            return [{"type": "X", "title": "hit", "url": base_url}]
        monkeypatch.setattr(tl, "_run_engine_scan", _fake_scan)
        report = await tl.run_coverage(engine_names=["SQLiEngine", "XSSEngine"])
        assert report["total"] == 2
        assert report["hit"] == 2
        assert report["miss"] == 0
        assert report["priority_gap"] == []

    @pytest.mark.asyncio
    async def test_expected_hit_respected(self, monkeypatch):
        async def _fake_scan_empty(engine_cls, base_url, param=""):
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