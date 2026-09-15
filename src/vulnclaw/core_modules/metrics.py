# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# core_modules/metrics.py（R3 迁移自 core/metrics.py）
"""
Prometheus 指标暴露模块 - 完整版
可选功能：通过 --metrics-port 启用
"""
import random

from vulnclaw.core.logger import logger

try:
    from prometheus_client import Counter, Gauge, Histogram, Summary, start_http_server, CollectorRegistry, REGISTRY  # noqa: F401  (可用性探测)
    PROMETHEUS_AVAILABLE = True
except ImportError:
    PROMETHEUS_AVAILABLE = False
    logger.warning("⚠️ prometheus_client 未安装，指标功能不可用。运行: pip install prometheus-client")


class DummyMetric:
    def set(self, value): pass
    def inc(self, value=1): pass
    def labels(self, **kwargs): return self
    def observe(self, value): pass
    def dec(self, value=1): pass
    def set_function(self, fn): pass
    def time(self): pass


class DummyCounter(DummyMetric):
    pass


class DummyGauge(DummyMetric):
    pass


class DummyHistogram(DummyMetric):
    pass


class DummySummary(DummyMetric):
    """无 prometheus_client 时的 Summary 垫片（兼容 observe / quantiles 语义）。

    含 ``quantiles`` 属性以对齐 prometheus Summary 的构造签名；无任何真实采样。
    """

    def __init__(self, name="", documentation="", labelnames=(), quantiles=(),
                 registry=None, **kwargs):
        super().__init__()
        self.quantiles = list(quantiles)
        self._name = name

    def observe(self, value):
        pass


class Metrics:
    """指标收集器"""

    def __init__(self, request_sample_rate: float = 1.0):
        # 高频请求埋点采样率：1.0=全量；0.1=仅记录 10% 请求（降低 CPU 开销）
        self._request_sample_rate = request_sample_rate
        if not PROMETHEUS_AVAILABLE:
            self._enabled = False
            self.vulns_found = DummyCounter()
            self.requests_total = DummyCounter()
            self.scan_progress = DummyGauge()
            self.ai_calls = DummyCounter()
            self.response_time = DummyHistogram()
            self.response_latency = DummySummary(
                quantiles=(0.5, 0.9, 0.95, 0.99, 0.999)
            )
            self.current_concurrency = DummyGauge()
            self.scanned_urls = DummyGauge()
            self.tokens_used = DummyGauge()
            self.engine_failures = DummyCounter()
            # 工作流8：可观测性补齐（扫描成功率/OOB/队列/worker/死信/引擎耗时）
            self.scan_results = DummyCounter()
            self.oob_events = DummyCounter()
            self.queue_length = DummyGauge()
            self.worker_utilization = DummyGauge()
            self.dead_letters = DummyCounter()
            self.engine_duration = DummyHistogram()
            self.registry = None
            return

        self._enabled = True
        self.registry = CollectorRegistry()

        self.vulns_found = Counter(
            'scanner_vulns_total',
            'Total vulnerabilities found',
            ['severity', 'type'],
            registry=self.registry
        )
        self.requests_total = Counter(
            'scanner_requests_total',
            'Total HTTP requests',
            ['method', 'status'],
            registry=self.registry
        )
        self.scan_progress = Gauge(
            'scanner_progress_percent',
            'Scan progress percentage',
            registry=self.registry
        )
        self.ai_calls = Counter(
            'scanner_ai_calls_total',
            'Total AI calls',
            ['model', 'success'],
            registry=self.registry
        )
        self.response_time = Histogram(
            'scanner_response_seconds',
            'HTTP response time',
            buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60],
            registry=self.registry
        )
        # 部分 prometheus_client 版本移除/不支持 Summary quantiles —— 尝试带分位数创建，
        # 失败则稳健降级（保留 count/sum，import/调用不炸）。
        try:
            self.response_latency = Summary(
                'scanner_response_latency_seconds',
                'HTTP response latency (P50/P90/P95/P99/P99.9)',
                quantiles=(0.5, 0.9, 0.95, 0.99, 0.999),
                registry=self.registry,
            )
        except TypeError:  # noqa: BLE001 - 该版本不支持 quantiles，回退纯 count/sum
            logger.warning("⚠️ prometheus_client 不支持 Summary quantiles，降级为 count/sum")
            self.response_latency = Summary(
                'scanner_response_latency_seconds',
                'HTTP response latency',
                registry=self.registry,
            )
        self.current_concurrency = Gauge(
            'scanner_current_concurrency',
            'Current concurrent requests',
            registry=self.registry
        )
        self.scanned_urls = Gauge(
            'scanner_scanned_urls',
            'Number of scanned URLs',
            registry=self.registry
        )
        self.tokens_used = Gauge(
            'scanner_tokens_used',
            'Total tokens used by AI',
            registry=self.registry
        )
        self.engine_failures = Counter(
            'scanner_engine_failures_total',
            'Total engine execution failures',
            ['engine'],
            registry=self.registry
        )
        # ===== 工作流8：可观测性补齐 =====
        self.scan_results = Counter(
            'scanner_scan_results_total',
            'Scan outcomes (success/failed/timeout/partial) — 扫描成功率',
            ['result'],
            registry=self.registry
        )
        self.oob_events = Counter(
            'scanner_oob_events_total',
            'OOB callback outcomes (hit/miss/blocked) — 带外交互成功率',
            ['result'],
            registry=self.registry
        )
        self.queue_length = Gauge(
            'scanner_queue_length',
            'Pending task queue length — Redis/内存队列积压',
            registry=self.registry
        )
        self.worker_utilization = Gauge(
            'scanner_worker_utilization',
            'Worker utilization ratio (0~1)',
            registry=self.registry
        )
        self.dead_letters = Counter(
            'scanner_dead_letters_total',
            'Tasks moved to dead-letter queue',
            registry=self.registry
        )
        self.engine_duration = Histogram(
            'scanner_engine_seconds',
            'Per-engine execution time (P95/P99 由 histogram_quantile 计算)',
            ['engine'],
            buckets=[0.1, 0.5, 1, 2, 5, 10, 30, 60, 120],
            registry=self.registry
        )

    def inc_vuln(self, severity: str, vuln_type: str):
        if self._enabled:
            self.vulns_found.labels(severity=severity, type=vuln_type).inc()

    def inc_request(self, method: str, status: int):
        if not self._enabled:
            return
        # 高频埋点采样：sample_rate < 1.0 时仅记录部分请求，降低 CPU 开销
        if self._request_sample_rate < 1.0 and random.random() >= self._request_sample_rate:
            return
        status_str = str(status)
        if status >= 500:
            status_str = "5xx"
        elif status >= 400:
            status_str = "4xx"
        elif status >= 300:
            status_str = "3xx"
        else:
            status_str = "2xx"
        self.requests_total.labels(method=method, status=status_str).inc()

    def inc_engine_failure(self, engine: str):
        """记录引擎执行失败（HTTP 请求彻底失败 / 引擎内部异常）。"""
        if self._enabled:
            self.engine_failures.labels(engine=engine).inc()

    def inc_ai_call(self, model: str, success: bool):
        if self._enabled:
            self.ai_calls.labels(model=model, success=str(success)).inc()

    def observe_response_time(self, seconds: float):
        if self._enabled:
            self.response_time.observe(seconds)
            self.response_latency.observe(seconds)

    def set_progress(self, percent: float):
        if self._enabled:
            self.scan_progress.set(percent)

    def set_concurrency(self, value: int):
        if self._enabled:
            self.current_concurrency.set(value)

    def set_scanned_urls(self, count: int):
        if self._enabled:
            self.scanned_urls.set(count)

    def set_tokens_used(self, tokens: int):
        if self._enabled:
            self.tokens_used.set(tokens)

    # ===== 工作流8：可观测性补齐（未启用时全部 no-op）=====
    def inc_scan_result(self, result: str):
        """扫描结局计数：success / failed / timeout / partial（成功率 = success / total）。"""
        if self._enabled:
            self.scan_results.labels(result=str(result or "unknown")).inc()

    def inc_oob_event(self, result: str):
        """OOB 事件计数：hit / miss / blocked（命中率 = hit / total）。"""
        if self._enabled:
            self.oob_events.labels(result=str(result or "unknown")).inc()

    def set_queue_length(self, count: int):
        if self._enabled:
            self.queue_length.set(int(count or 0))

    def set_worker_utilization(self, ratio: float):
        """worker 利用率（0~1）；越界值自动夹紧，避免脏数据污染面板。"""
        if self._enabled:
            try:
                self.worker_utilization.set(max(0.0, min(1.0, float(ratio or 0.0))))
            except (TypeError, ValueError):
                pass

    def inc_dead_letter(self):
        if self._enabled:
            self.dead_letters.inc()

    def observe_engine_duration(self, engine: str, seconds: float):
        if self._enabled:
            try:
                self.engine_duration.labels(engine=str(engine or "unknown")).observe(float(seconds or 0.0))
            except (TypeError, ValueError):
                pass


_metrics = None
_metrics_server_started = False


def get_metrics() -> Metrics:
    global _metrics
    if _metrics is None:
        _metrics = Metrics()
    return _metrics


def start_metrics_server(port: int = 9090):
    global _metrics_server_started
    if _metrics_server_started:
        return
    if not PROMETHEUS_AVAILABLE:
        logger.warning("⚠️ prometheus_client 未安装，无法启动指标服务器")
        return
    try:
        metrics = get_metrics()
        if metrics.registry is not None:
            start_http_server(port, registry=metrics.registry)
            _metrics_server_started = True
            logger.info(f"📊 Prometheus 指标服务器已启动: http://0.0.0.0:{port}/metrics")
        else:
            logger.warning("⚠️ 指标注册表为空，无法启动服务器")
    except Exception as e:
        logger.warning(f"⚠️ 启动指标服务器失败: {e}")


__all__ = ['get_metrics', 'start_metrics_server', 'Metrics']


# ============================================================
# SP8: AI 成本/用量台账（机器事实，JSONL 追加写）
# ============================================================
import json  # noqa: E402
import os  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

# src/vulnclaw/core_modules/metrics.py → 项目根（parents[3]）
ROOT = Path(__file__).resolve().parents[3]
_USAGE_LOCK = threading.Lock()


class UsageLedger:
    """SP8: AI 调用成本/用量台账。

    每行一条 {ts, provider, model, prompt_tokens, completion_tokens, ms, ok, site}，
    落盘 `_runtime_cache/metrics/usage.jsonl`（追加写、线程安全、写失败不影响业务）。
    breakdown() 默认按 provider×model 聚合，site 维度可出 provider×调用点成本表。
    """

    @staticmethod
    def path():
        p = ROOT / "_runtime_cache" / "metrics" / "usage.jsonl"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    @classmethod
    def record(cls, provider, model, prompt_tokens=0, completion_tokens=0,
               ms=0.0, ok=True, site=None):
        """记一行；任何异常都不上抛（台账失败必须静默）。"""
        try:
            row = {
                "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
                "provider": str(provider or ""),
                "model": str(model or ""),
                "prompt_tokens": int(prompt_tokens or 0),
                "completion_tokens": int(completion_tokens or 0),
                "ms": round(float(ms or 0), 1),
                "ok": bool(ok),
                "site": str(site or ""),
            }
            with _USAGE_LOCK:
                with cls.path().open("a", encoding="utf-8") as f:
                    f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:
            pass  # noqa: BLE001 —— 台账失败静默

    @classmethod
    def rows(cls):
        p = cls.path()
        if not p.exists():
            return []
        out = []
        with _USAGE_LOCK:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out

    @classmethod
    def breakdown(cls, by=("provider", "model")):
        agg = {}
        for r in cls.rows():
            key = tuple(r.get(k, "") for k in by)
            a = agg.setdefault(key, {
                "calls": 0, "ok": 0, "prompt_tokens": 0,
                "completion_tokens": 0, "ms": 0.0,
            })
            a["calls"] += 1
            if r.get("ok"):
                a["ok"] += 1
            a["prompt_tokens"] += int(r.get("prompt_tokens", 0))
            a["completion_tokens"] += int(r.get("completion_tokens", 0))
            a["ms"] += float(r.get("ms", 0))
        return agg

    @classmethod
    def table(cls, by=("provider", "model")):
        """Markdown 成本表：| 维度 | calls | ok | tokens | ms | ~usd |"""
        lines = ["| " + " | ".join(by) + " | calls | ok | tokens | ms | ~usd |",
                 "|---|---|---|---|---|---|"]
        for key in sorted(cls.breakdown(by)):
            a = cls.breakdown(by)[key]
            toks = a["prompt_tokens"] + a["completion_tokens"]
            usd = toks / 1000.0 * 0.01
            lines.append("| " + " | ".join(str(k) for k in key)
                         + " | %d | %d | %d | %.1f | %.4f |"
                         % (a["calls"], a["ok"], toks, a["ms"], usd))
        return "\n".join(lines)

    @classmethod
    def reset(cls):
        with _USAGE_LOCK:
            p = cls.path()
            if p.exists():
                os.remove(p)
