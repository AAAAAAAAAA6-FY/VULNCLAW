# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# Helm Chart 静态验收（与 test_deployment_static.py 同模式：不依赖 helm/k8s 环境）。
#
# 本文件不依赖 helm 二进制与 K8s 集群，只做：
#   1) Chart.yaml / values.yaml 结构与必填字段断言
#   2) templates 文本级断言：探针 / 资源限制 / 环境注入 / 服务端口 / 无硬编码凭据
#   3) helm 在 PATH 时追加 helm lint（不可用则 skip，如实标注）
# 真实渲染与集群行为（helm template / helm install / 滚动升级）需在具备 helm 的环境执行。
import os
import re
import shutil
import subprocess

import pytest
import yaml

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHART_DIR = os.path.join(ROOT, "deploy", "helm", "vulnclaw")
TEMPLATES_DIR = os.path.join(CHART_DIR, "templates")

# 凭据键名（同 tests/test_ci_workflow.py 口径；前置排除下划线防误伤 SCAN_API_KEY 类变量名）
_CRED_KEY_RE = re.compile(
    r"(?im)(?<![A-Za-z0-9_])(api[_-]?key|apikey|access[_-]?token|password|passwd|secret)\s*[:=]\s*(\S.*)?$"
)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _tpl(name: str) -> str:
    return _read(os.path.join(TEMPLATES_DIR, name))


# ---------- Chart.yaml / values.yaml ----------

def test_chart_metadata():
    chart = yaml.safe_load(_read(os.path.join(CHART_DIR, "Chart.yaml")))
    assert chart["apiVersion"] == "v2"
    assert chart["name"] == "vulnclaw"
    assert str(chart["version"]).count(".") == 2, "version 需为 semver"
    assert chart.get("appVersion"), "appVersion 缺失：镜像 tag 依赖它做回退"


def test_values_defaults_present():
    v = yaml.safe_load(_read(os.path.join(CHART_DIR, "values.yaml")))
    for key in ("image", "redis", "master", "worker", "env", "probes"):
        assert key in v, f"values.yaml 缺少 {key}"
    assert {"repository", "tag", "pullPolicy"} <= set(v["image"])
    for comp in ("redis", "master", "worker"):
        assert v[comp].get("resources", {}).get("limits"), f"{comp} 缺少资源上限"
    assert "existingSecret" in v, "缺少 existingSecret（凭据必须走 Secret，不进 values）"
    for k in ("DANGEROUS_MODE", "OOB_INTERACTSH_SERVER"):
        assert k in v["env"], f"env 缺少 {k}（与 compose 语义对齐）"


def test_templates_present():
    expected = {"_helpers.tpl", "redis.yaml", "master.yaml", "worker.yaml", "NOTES.txt"}
    found = set(os.listdir(TEMPLATES_DIR))
    assert expected <= found, f"templates 缺失: {expected - found}"


# ---------- 探针 / 资源 / 注入 ----------

@pytest.mark.parametrize("name,component", [("master.yaml", "master"), ("worker.yaml", "worker")])
def test_long_running_components_have_probes_and_resources(name, component):
    text = _tpl(name)
    assert "livenessProbe" in text, f"{component} 缺少 livenessProbe"
    assert "readinessProbe" in text, f"{component} 缺少 readinessProbe"
    assert f".Values.{component}.resources" in text, f"{component} 未引用 values 资源上限"
    assert ".Values.probes.intervalSeconds" in text, f"{component} 探针未参数化（probes.*）"


def test_redis_has_ping_probe():
    text = _tpl("redis.yaml")
    assert "redis-cli" in text and "ping" in text, "redis 探针应为 redis-cli ping（与 compose healthcheck 对齐）"
    assert "kind: Service" in text and "6379" in text, "redis 需暴露 ClusterIP Service:6379"


def test_env_injection_master_worker():
    for name in ("master.yaml", "worker.yaml"):
        text = _tpl(name)
        for key in ("REDIS_URL", "OOB_INTERACTSH_SERVER", "DANGEROUS_MODE"):
            assert key in text, f"{name} 未注入 {key}（与 compose 的 environment 对齐）"
        assert "vulnclaw.redisUrl" in text, f"{name} 的 REDIS_URL 应走集群内 Service 名（helpers）"


def test_distributed_args_match_compose():
    assert '"--distributed", "--master"' in _tpl("master.yaml")
    assert '"--distributed", "--worker"' in _tpl("worker.yaml")


def test_persistence_uses_pvc():
    for name in ("redis.yaml", "master.yaml", "worker.yaml"):
        text = _tpl(name)
        assert "PersistentVolumeClaim" in text or "persistentVolumeClaim" in text, (
            f"{name} 缺少持久化声明（_runtime_cache/redis 数据不应随 Pod 丢失）"
        )


def test_no_hardcoded_credentials():
    """非注释行不得出现凭据键赋值（除模板表达式/空值/values 引用）。"""
    targets = [os.path.join(CHART_DIR, "Chart.yaml"), os.path.join(CHART_DIR, "values.yaml")]
    targets += [os.path.join(TEMPLATES_DIR, n) for n in os.listdir(TEMPLATES_DIR)]
    for path in targets:
        for lineno, line in enumerate(_read(path).splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = _CRED_KEY_RE.search(line)
            if not m:
                continue
            value = (m.group(2) or "").strip().strip("'\"")
            if not value or value.lower() in ("null", "none", "~") or "{{" in value or "$" in value:
                continue
            raise AssertionError(f"{os.path.basename(path)}:{lineno} 疑似硬编码凭据: {stripped}")


# ---------- helm lint（有 helm 才跑） ----------

def test_helm_lint_when_available():
    helm = shutil.which("helm")
    if not helm:
        pytest.skip("环境无 helm 二进制，跳过 helm lint（渲染/升级行为需在具备 helm 的环境验证）")
    proc = subprocess.run(
        [helm, "lint", CHART_DIR],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"helm lint 失败:\n{proc.stdout}\n{proc.stderr}"


# ============================================================
# deploy/k8s/ 纯 manifest（kubectl apply -k 路径，与 Helm 语义对齐）
# ============================================================
K8S_DIR = os.path.join(ROOT, "deploy", "k8s")
_K8S_FILES = ("redis.yaml", "master.yaml", "worker.yaml")


def _k8s_docs(name: str) -> list:
    with open(os.path.join(K8S_DIR, name), encoding="utf-8") as f:
        return [d for d in yaml.safe_load_all(f) if d]


def _k8s_deployment(name: str) -> dict:
    for d in _k8s_docs(name):
        if d.get("kind") == "Deployment":
            return d
    raise AssertionError(f"{name} 缺少 Deployment")


def test_k8s_manifests_present_and_parseable():
    for name in _K8S_FILES + ("namespace.yaml", "kustomization.yaml"):
        path = os.path.join(K8S_DIR, name)
        assert os.path.isfile(path), f"缺少 {name}"
    ns = yaml.safe_load(_read(os.path.join(K8S_DIR, "namespace.yaml")))
    assert ns["kind"] == "Namespace" and ns["metadata"]["name"] == "vulnclaw"


def test_k8s_covers_three_components_and_service():
    kinds = set()
    for name in _K8S_FILES:
        for d in _k8s_docs(name):
            kinds.add((d.get("kind"), (d.get("metadata") or {}).get("name")))
    assert ("Deployment", "vulnclaw-redis") in kinds
    assert ("Deployment", "vulnclaw-master") in kinds
    assert ("Deployment", "vulnclaw-worker") in kinds
    assert ("Service", "vulnclaw-redis") in kinds


@pytest.mark.parametrize("name", _K8S_FILES)
def test_k8s_probes_and_resources(name):
    c = _k8s_deployment(name)["spec"]["template"]["spec"]["containers"][0]
    assert c.get("readinessProbe"), f"{name} 缺少 readinessProbe"
    assert c.get("livenessProbe"), f"{name} 缺少 livenessProbe"
    assert c.get("resources", {}).get("limits"), f"{name} 缺少资源上限"


@pytest.mark.parametrize("name,role", [("master.yaml", "master"), ("worker.yaml", "worker")])
def test_k8s_env_injection_and_distributed_args(name, role):
    c = _k8s_deployment(name)["spec"]["template"]["spec"]["containers"][0]
    env_names = {e["name"] for e in c.get("env", [])}
    for key in ("REDIS_URL", "OOB_INTERACTSH_SERVER", "DANGEROUS_MODE"):
        assert key in env_names, f"{name} 未注入 {key}"
    args = c.get("args", [])
    assert "--distributed" in args and f"--{role}" in args, f"{name} 缺少分布式启动参数（实际: {args}）"
    # 凭据走 Secret（optional，兼容无凭据启动，同 compose 的 required: false）
    refs = c.get("envFrom") or []
    assert any("vulnclaw-secrets" in str(r) for r in refs), f"{name} 未引用 Secret 注入凭据"


def test_k8s_semantics_match_helm_chart():
    """同一语义点必须在 Helm 与纯 manifest 两侧一致，防止两处部署方式漂移。"""
    pairs = [("master.yaml", "master.yaml"), ("worker.yaml", "worker.yaml")]
    tokens = (
        "--distributed", "--master", "--worker", "REDIS_URL",
        "OOB_INTERACTSH_SERVER", "DANGEROUS_MODE",
        "readinessProbe", "livenessProbe", "persistentVolumeClaim",
    )
    for helm_name, k8s_name in pairs:
        helm_text = _tpl(helm_name)
        k8s_text = _read(os.path.join(K8S_DIR, k8s_name))
        for token in tokens:
            if token in ("--master", "--worker") and not (
                (token == "--master" and helm_name == "master.yaml")
                or (token == "--worker" and helm_name == "worker.yaml")
            ):
                continue
            assert token in helm_text, f"Helm {helm_name} 缺少语义点 {token}"
            assert token in k8s_text, f"k8s {k8s_name} 缺少语义点 {token}（与 Helm 漂移）"


def test_kustomization_references_all_resources():
    k = yaml.safe_load(_read(os.path.join(K8S_DIR, "kustomization.yaml")))
    assert k["kind"] == "Kustomization"
    for r in ("namespace.yaml", *(_K8S_FILES)):
        assert r in k["resources"], f"kustomization 未引用 {r}"


def test_k8s_no_hardcoded_credentials():
    for name in os.listdir(K8S_DIR):
        if not name.endswith(".yaml"):
            continue
        for lineno, line in enumerate(_read(os.path.join(K8S_DIR, name)).splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            m = _CRED_KEY_RE.search(line)
            if not m:
                continue
            value = (m.group(2) or "").strip().strip("'\"")
            if not value or value.lower() in ("null", "none", "~"):
                continue
            raise AssertionError(f"deploy/k8s/{name}:{lineno} 疑似硬编码凭据: {stripped}")


def test_kubectl_dry_run_when_available():
    kubectl = shutil.which("kubectl")
    if not kubectl:
        pytest.skip("环境无 kubectl，跳过 kustomize 解析验证（kubectl apply -k 需真实集群/CLI）")
    # 离线第一关：kustomize 渲染（纯客户端，不需要任何集群）
    render = subprocess.run(
        [kubectl, "kustomize", K8S_DIR],
        capture_output=True, text=True, timeout=120,
    )
    assert render.returncode == 0, f"kubectl kustomize 渲染失败:\n{render.stderr}"
    assert "kind:" in render.stdout, "kustomize 渲染输出不含任何资源（kustomization.yaml 未生效）"

    # 有集群时才做 apply dry-run：`--dry-run=client` 仍会做 API 发现（拉 group list），
    # 无集群环境下必然 "dial tcp 127.0.0.1:8080 refused" → 那属于环境缺失，跳过而非判失败。
    probe = subprocess.run(
        [kubectl, "cluster-info"], capture_output=True, text=True, timeout=30,
    )
    if probe.returncode != 0:
        pytest.skip("无可用 k8s 集群，跳过 kubectl apply --dry-run（离线渲染校验已通过）")

    proc = subprocess.run(
        [kubectl, "apply", "-k", K8S_DIR, "--dry-run=client", "--validate=false", "-o", "yaml"],
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"kubectl apply -k --dry-run 失败:\n{proc.stdout}\n{proc.stderr}"
