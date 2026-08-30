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
    from prometheus_client import Counter, Gauge, Histogram, start_http_server, CollectorRegistry, REGISTRY  # noqa: F401  (可用性探测)
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
            self.current_concurrency = DummyGauge()
            self.scanned_urls = DummyGauge()
            self.tokens_used = DummyGauge()
            self.engine_failures = DummyCounter()
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
