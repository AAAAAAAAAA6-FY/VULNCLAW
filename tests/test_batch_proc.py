# -*- coding: utf-8 -*-
"""P1-4 AI 批量判定验收测试：BatchProcessor 行为 + 串行/批量对照实验管线。

为什么钉死这些行为：
  批量判定的收益（调用次数下降）与风险（批量导致判定退化）必须可量化、可回归。
  BatchProcessor 的分组/解析/index 映射任何一处出错，都会把"未检测"静默变成
  "has_vuln=False"——那就是漏报。对照实验（bench_ai_batch）则证明：
  1) 管线本身不引入错误（mock 无退化时两管线准确率同为 100%、判定一致）；
  2) 收益真实存在（调用次数 = ceil(N/batch)）；
  3) 退化注入后批量准确率下降（证明"批量非纯无损"这条结论可被实验复现）。
"""
import asyncio
import importlib
import os
import sys

import pytest

_SCRIPTS = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts"
)
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

bench = importlib.import_module("bench_ai_batch")

from vulnclaw.ai.v100.batch_processor import BatchProcessor  # noqa: E402


def _task(i: int, target: str = "http://t/?q=1") -> dict:
    # 生产语义（优化7）：只有"同 (url, param)"才合并批量 → 这里 target 必须一致，
    # 仅用 task_id 区分条目。不同 target 的合并防护由 test_merge_no_cross_target 覆盖。
    return {"type": "sqli", "param": "q", "target": target,
            "payload": "p", "response_snippet": "s", "task_id": f"t{i}"}


def test_merge_no_cross_target():
    """不同 target 不得合并（防止 A 目标的响应污染 B 目标的判定上下文）。"""
    bp = BatchProcessor(max_batch_size=5)
    tasks = [_task(1, "http://a/"), _task(2, "http://b/")]
    merged = bp.merge_tasks(tasks)
    assert len(merged) == 2
    assert not any(m.get("is_batch") for m in merged)


class TestBatchProcessor:
    def test_merge_groups_same_key(self):
        bp = BatchProcessor(max_batch_size=5)
        tasks = [_task(1), _task(2), _task(3)]
        merged = bp.merge_tasks(tasks)
        assert len(merged) == 1
        assert merged[0]["is_batch"] is True
        assert merged[0]["count"] == 3
        assert merged[0]["task_ids"] == ["t1", "t2", "t3"]

    def test_merge_keeps_singleton_unbatched(self):
        bp = BatchProcessor(max_batch_size=5)
        merged = bp.merge_tasks([_task(1)])
        assert len(merged) == 1 and "is_batch" not in merged[0]

    def test_merge_respects_max_batch_size(self):
        bp = BatchProcessor(max_batch_size=2)
        merged = bp.merge_tasks([_task(i) for i in range(5)])
        batches = [m for m in merged if m.get("is_batch")]
        # 5 条 → [2,2] 两个批次；剩余 1 条按生产语义不打包（singleton 直接透传）
        assert [b["count"] for b in batches] == [2, 2]
        assert sum(1 for m in merged if not m.get("is_batch")) == 1

    def test_stats_saved_ratio(self):
        bp = BatchProcessor(max_batch_size=5)
        bp.merge_tasks([_task(i) for i in range(5)])
        stats = bp.get_stats()
        assert stats["api_calls_saved"] == 4
        assert stats["save_ratio"] == "80.0%"

    def test_batch_prompt_contains_targets_and_rules(self):
        bp = BatchProcessor(max_batch_size=5)
        merged = bp.merge_tasks([_task(i) for i in range(2)])
        assert len(merged) == 1 and merged[0]["is_batch"]
        prompt = bp.generate_batch_prompt(merged[0])
        assert prompt.count("http://t/?q=1") == 2  # 两条子任务各出现一次
        assert "JSON数组" in prompt

    def test_parse_batch_response_index_mapping(self):
        bp = BatchProcessor(max_batch_size=5)
        batch = {"tasks": [_task(0), _task(1), _task(2)]}
        raw = '[{"index":1,"has_vuln":true,"vuln_type":"SQL注入","confidence":"高","evidence":"e","severity":"High"},' \
              '{"index":3,"has_vuln":false,"confidence":"低","evidence":"x","severity":"Info"}]'
        results = bp.parse_batch_response(raw, batch)
        assert results[0]["has_vuln"] is True
        # index=3 越界 → 第 2 条必须 fail-closed 记"未检测/False"，不能猜
        assert results[1]["has_vuln"] is False
        assert results[2]["has_vuln"] is False

    def test_parse_garbage_fails_closed(self):
        bp = BatchProcessor(max_batch_size=5)
        batch = {"tasks": [_task(0)]}
        results = bp.parse_batch_response("这不是JSON", batch)
        assert results[0]["has_vuln"] is False


class TestBenchSerialVsBatch:
    """对照实验管线本身的可回归断言（全离线，mock 判定官）。"""

    def run(self, n, batch_size, degrade_p=0.0):
        judge = bench.MockJudge(latency_s=0.0, degrade_p=degrade_p)
        return asyncio.run(bench.experiment(n, batch_size, judge, latency_s=0.0))

    def test_pipeline_is_sound_no_degrade(self):
        """无退化注入：两条管线都必须 100% 命中真值且互相一致（管线正确性）。"""
        res = self.run(n=8, batch_size=4)
        assert res["serial"]["accuracy"] == 1.0
        assert res["batch"]["accuracy"] == 1.0
        assert res["consistency"] == 1.0

    def test_batch_saves_calls(self):
        """收益：批量 API 调用 = ceil(N/batch)；节省 = N - ceil(N/batch)。"""
        res = self.run(n=10, batch_size=4)
        assert res["batch"]["calls"] == 3
        assert res["calls_saved"] == 7
        assert res["serial"]["calls"] == 10

    def test_truth_is_content_based_not_positional(self):
        """真值必须内容式（embed 在证据里）：奇偶交替，任何管线无权靠位置猜。"""
        items = bench.build_items(6)
        assert [it["truth"] for it in items] == [True, False] * 3

    def test_degrade_shows_quality_risk(self):
        """退化注入=1.0：批量结论整体错位 → 批量准确率必然 < 串行。
        证明'批量不是纯无损'这一结论在实验框架里可复现、可量化。"""
        res = self.run(n=8, batch_size=4, degrade_p=1.0)
        assert res["batch"]["accuracy"] < res["serial"]["accuracy"]

    def test_parse_verdicts_fail_closed(self):
        """LLM 输出垃圾 → 全部 None（统计按 fail-closed 处理，绝不编造 confirmed）。"""
        assert bench._parse_verdicts("垃圾输出", 3) == [None, None, None]
