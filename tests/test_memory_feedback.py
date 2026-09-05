# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.

"""S3.1b/S3.1c 记忆系统双向接线离线测试。

  recon 阶段把侦察发现（host/技术栈/端口）写入 VectorMemory（_persist_recon_memory）；
  taskgen 阶段召回相似历史经验（_inject_task_memory_hints），命中高价值组合
  （引擎/URL 模式/参数）时给任务追加 memory_hint / memory_boost，且不改变
  既有任务必须字段。查询失败/空库/开关 scan_memory_enabled=False 一律静默跳过。

  全部用 asyncio.run 同步测试模式（项目不用 pytest-asyncio），不触网不调 AI。
"""
import asyncio
import json

from vulnclaw.ai.v100.phases import phases_recon as rm
from vulnclaw.ai.v100.phases import phases_taskgen as tm
from vulnclaw.ai.v100.smart_queue import SmartTaskQueue


class _FakeMemory:
    """VectorMemory 替身：recall 返回预设记录，add_experience 记录调用。"""

    def __init__(self, recalled=None, raise_on_recall=False):
        self.recalled = list(recalled or [])
        self.raise_on_recall = raise_on_recall
        self.added = []

    async def recall(self, query, n_results=3, exclude_failures=True):
        if self.raise_on_recall:
            raise RuntimeError("vector db down")
        return list(self.recalled)

    async def add_experience(self, target, vuln_type, payload, success, evidence, error_msg=""):
        self.added.append({
            "target": target, "vuln_type": vuln_type, "payload": payload,
            "success": success, "evidence": evidence, "error_msg": error_msg,
        })


class _StubFilter:
    def should_skip(self, *args, **kwargs):
        return (False, "")


class _SettingsStub:
    """测试替身：scan_memory_enabled 可控，其余属性缺省 None（getattr 兼容）。"""

    def __init__(self, scan_memory_enabled=True):
        self.scan_memory_enabled = scan_memory_enabled

    def __getattr__(self, name):
        return None


def _rec(vuln_type, payload, evidence="", host="t"):
    return json.dumps({
        "target": "hash0", "target_host": host, "vuln_type": vuln_type,
        "payload": payload, "success": True, "evidence": evidence or payload,
    })


class _TaskgenSelf:
    def __init__(self, brief, memory=None):
        self._recon_brief = brief
        self.target = "http://t/admin"
        self.task_queue = SmartTaskQueue()
        self.local_filter = _StubFilter()
        self.batch_processor = None
        self.memory = memory
        self._a32_skipped = 0
        self._rotation_offset = 0

    async def _gen_cve_task(self):
        return None

    async def _inject_task_memory_hints(self):
        # 模拟 orchestrator.bind_phase_methods 的绑定行为
        await tm._inject_task_memory_hints(self)


def _brief(**overrides):
    data = {
        "status": 200, "tech_stack": [], "url_params": ["id"],
        "forms": [], "apis": [], "js_endpoints": [], "crawled_endpoints": [],
        "intel": {},
    }
    data.update(overrides)
    return data


def _all_task_data(s):
    return [t.task_data for t in s.task_queue._pending_tasks.values()]


def _run_taskgen(s):
    asyncio.run(tm._generate_tasks(s))
    return s


# ------------------------------------------------------------------
# taskgen 读取注入
# ------------------------------------------------------------------
def test_taskgen_injects_memory_hint_and_boost():
    # 历史经验：第 3 条（rank=2）是 /admin 上的 sqli → 置信度 0.8
    mem = _FakeMemory(recalled=[
        _rec("xss", "/", evidence="reflected xss on /"),
        _rec("lfi", "/etc/passwd", evidence="lfi read /etc/passwd"),
        _rec("sqli", "/admin", evidence="sqli detected on /admin"),
    ])
    s = _run_taskgen(_TaskgenSelf(_brief(), memory=mem))
    tds = _all_task_data(s)
    assert any(td.get("type") == "engine_bundle" for td in tds), "engine_bundle 任务应正常生成"
    # 必须字段不被破坏
    for td in tds:
        if td.get("type") == "engine_bundle":
            for key in ("type", "engines", "target", "param", "priority", "created_at"):
                assert key in td, f"engine_bundle 必须字段缺失: {key}"
        elif td.get("type") == "global_scan":
            for key in ("type", "engine", "target", "priority"):
                assert key in td, f"global_scan 必须字段缺失: {key}"
    # 命中 /admin+sqli 的 bundle 任务注入 memory_hint / memory_boost
    hits = [td for td in tds if td.get("type") == "engine_bundle" and td.get("memory_hint")]
    assert hits, "命中历史高价值组合的任务应注入 memory_hint"
    td = hits[0]
    assert td["memory_hint"] == {"hint": "历史对 /admin 的 sqli 命中率高", "confidence": 0.8}
    assert 0.0 < td["memory_boost"] <= 1.0
    assert td["memory_boost"] == 0.8
    # 未命中组合的 global_scan 任务不注入 memory 字段
    assert all("memory_hint" not in g and "memory_boost" not in g
               for g in tds if g.get("type") == "global_scan")


def test_taskgen_memory_error_silently_skipped():
    mem = _FakeMemory(raise_on_recall=True)
    s = _run_taskgen(_TaskgenSelf(_brief(), memory=mem))  # 不抛错
    tds = _all_task_data(s)
    assert tds, "任务应正常生成"
    assert all("memory_hint" not in td and "memory_boost" not in td for td in tds)


def test_taskgen_memory_empty_silently_skipped():
    mem = _FakeMemory(recalled=[])
    s = _run_taskgen(_TaskgenSelf(_brief(), memory=mem))  # 不抛错
    tds = _all_task_data(s)
    assert tds, "任务应正常生成"
    assert all("memory_hint" not in td and "memory_boost" not in td for td in tds)


def test_taskgen_no_memory_attr_silently_skipped():
    s = _run_taskgen(_TaskgenSelf(_brief(), memory=None))  # 无 memory 也正常
    tds = _all_task_data(s)
    assert tds
    assert all("memory_hint" not in td and "memory_boost" not in td for td in tds)


# ------------------------------------------------------------------
# recon 写入
# ------------------------------------------------------------------
class _ReconSelf:
    def __init__(self, memory=None):
        self.target = "http://t/admin"
        self.session = None
        self._enable_deep_recon = False
        self.burp_available = False
        self.burp_client = None
        self._enable_ffuf = False
        self.memory = memory
        self._collaborator_domain = None
        self._normal_responses = {}

    async def _get_model_stats(self):
        return {"total_calls": 0, "per_model": {}}

    def _detect_tech(self, headers, text):
        return rm._detect_tech(self, headers, text)

    async def _persist_recon_memory(self):
        # 模拟 orchestrator.bind_phase_methods 的绑定行为
        await rm._persist_recon_memory(self)


def _patch_recon_offline(monkeypatch):
    async def _fake_get(*a, **k):
        return (200, "<html><input name='q'></html>", {"Server": "nginx", "X-Powered-By": "PHP/7.4"})

    async def _no_arjun(*a, **k):
        return []

    async def _no_crawl(*a, **k):
        return {}

    async def _no_intel(*a, **k):
        return None

    monkeypatch.setattr(rm, "async_get", _fake_get)
    monkeypatch.setattr(rm, "run_arjun", _no_arjun)
    monkeypatch.setattr("vulnclaw.modules.recon.crawl_same_origin", _no_crawl)
    monkeypatch.setattr("vulnclaw.modules.intelligence.enrich_brief_with_intel", _no_intel)


def test_recon_writes_recon_memory(monkeypatch):
    mem = _FakeMemory()
    s = _ReconSelf(memory=mem)
    _patch_recon_offline(monkeypatch)
    asyncio.run(rm._recon(s))
    assert len(mem.added) == 1, "recon 完成应写入 1 条侦察经验"
    entry = mem.added[0]
    assert entry["vuln_type"] == "recon_profile"
    assert entry["success"] is True
    assert entry["target"] == "http://t/admin"
    assert entry["payload"] == "t"           # host
    assert "nginx" in entry["evidence"]      # 技术栈进入 evidence
    assert "PHP/7.4" in entry["evidence"]


def test_recon_no_memory_attr_skips_write(monkeypatch):
    s = _ReconSelf(memory=None)
    _patch_recon_offline(monkeypatch)
    asyncio.run(rm._recon(s))  # 不抛错
    assert s._recon_brief is not None


# ------------------------------------------------------------------
# 开关 scan_memory_enabled=False → 全部静默跳过
# ------------------------------------------------------------------
def test_switch_off_skips_taskgen_injection(monkeypatch):
    monkeypatch.setattr(tm, "settings", _SettingsStub(scan_memory_enabled=False))
    mem = _FakeMemory(recalled=[_rec("sqli", "/admin")])
    s = _run_taskgen(_TaskgenSelf(_brief(), memory=mem))
    tds = _all_task_data(s)
    assert tds
    assert all("memory_hint" not in td and "memory_boost" not in td for td in tds)


def test_switch_off_skips_recon_write(monkeypatch):
    monkeypatch.setattr(rm, "settings", _SettingsStub(scan_memory_enabled=False))
    mem = _FakeMemory()
    s = _ReconSelf(memory=mem)
    _patch_recon_offline(monkeypatch)
    asyncio.run(rm._recon(s))
    assert mem.added == [], "开关关闭时 recon 不应写记忆"
