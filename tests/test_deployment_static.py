# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# 离线静态验收：Dockerfile / docker-compose.yaml / 临时文件清理逻辑。
#
# 本文件不依赖 Docker daemon（本开发机无 Docker），只做：
#   1) compose 结构断言（服务齐全/healthcheck/restart/资源限制/环境注入/卷挂载/依赖顺序）
#   2) Dockerfile 文本断言（基础镜像/安装方式）
#   3) worker 级临时文件清理纯函数离线验收（cleanup_temp_file）
# 容器行为（build/up/down/重启恢复）需在具备 Docker 的环境真实执行，见 docs/DEPLOYMENT.md。

import os

import yaml

COMPOSE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docker-compose.yaml")
DOCKERFILE_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Dockerfile")


def _load_compose() -> dict:
    with open(COMPOSE_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


# ---------- compose 结构 ----------

def test_compose_has_three_services():
    compose = _load_compose()
    services = compose["services"]
    assert {"redis", "master", "worker"} <= set(services)


def test_redis_healthcheck_present():
    compose = _load_compose()
    hc = compose["services"]["redis"].get("healthcheck") or {}
    assert hc.get("test"), "redis 必须配置 healthcheck"
    assert "redis-cli" in " ".join(hc["test"])


def test_worker_restart_policy():
    compose = _load_compose()
    for svc in ("master", "worker"):
        restart = (compose["services"][svc].get("restart") or "").strip()
        assert restart in ("unless-stopped", "always"), f"{svc} 缺少崩溃自动拉起的 restart 策略"


def test_resource_limits_present():
    compose = _load_compose()
    for svc in ("redis", "master", "worker"):
        cfg = compose["services"][svc]
        assert cfg.get("mem_limit"), f"{svc} 缺少 mem_limit"
        assert cfg.get("cpus"), f"{svc} 缺少 cpus"


def test_env_injection_master_worker():
    compose = _load_compose()
    for svc in ("master", "worker"):
        env = compose["services"][svc].get("environment") or {}
        assert "REDIS_URL" in env, f"{svc} 未注入 REDIS_URL"
        assert "redis://redis:6379" in str(env["REDIS_URL"]), f"{svc} 的 REDIS_URL 应指向 redis 服务"
        assert "OOB_INTERACTSH_SERVER" in env, f"{svc} 未注入 OOB_INTERACTSH_SERVER（OOB 回调验证在 worker 侧）"
        assert "DANGEROUS_MODE" in env, f"{svc} 未注入 DANGEROUS_MODE"


def test_depends_on_redis_healthy():
    compose = _load_compose()
    for svc in ("master", "worker"):
        dep = compose["services"][svc].get("depends_on") or {}
        assert dep.get("redis", {}).get("condition") == "service_healthy", f"{svc} 应依赖 redis 健康"


def test_runtime_cache_volume_mounted():
    compose = _load_compose()
    # 报告/日志/死信队列都在 /app/_runtime_cache 下（PROJECT_CACHE_DIR）
    for svc in ("master", "worker"):
        mounts = compose["services"][svc].get("volumes") or []
        targets = [m.get("target") if isinstance(m, dict) else m for m in mounts]
        assert any("/app/_runtime_cache" in str(t) for t in targets), f"{svc} 未挂载 _runtime_cache"
    volumes = compose.get("volumes") or {}
    assert "scan-data" in volumes and "redis-data" in volumes


# ---------- Dockerfile ----------

def test_dockerfile_base_image():
    with open(DOCKERFILE_PATH, "r", encoding="utf-8") as f:
        text = f.read()
    assert "FROM python:3.11-slim" in text


def test_dockerfile_pip_install_full():
    with open(DOCKERFILE_PATH, "r", encoding="utf-8") as f:
        text = f.read()
    assert "pip install --no-cache-dir .[full]" in text


# ---------- worker 级临时文件清理（纯函数，离线验收） ----------

def test_cleanup_temp_file_removes_existing(tmp_path):
    from vulnclaw.core.auth.auth_helper import cleanup_temp_file

    f = tmp_path / "cookies.txt"
    f.write_text("k=v", encoding="utf-8")
    cleanup_temp_file(str(f))
    assert not f.exists()


def test_cleanup_temp_file_tolerates_missing_and_none():
    from vulnclaw.core.auth.auth_helper import cleanup_temp_file

    # 不存在的路径 / None：清理失败必须静默，不允许向 worker 抛异常
    cleanup_temp_file(str(os.path.join(os.sep, "nonexistent", "x")))
    cleanup_temp_file(None)
