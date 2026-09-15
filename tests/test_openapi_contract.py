# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
"""OpenAPI 契约件验收（scripts/gen_openapi.py + docs/openapi.json）。

覆盖：
  1) 运行时能产出合法 OpenAPI（info/paths/openapi 版本），且路径覆盖 dashboard 关键端点
  2) 序列化确定性：两次生成逐字节一致（CI 可做 drift 检查）
  3) 入库契约件与运行时一致（文件缺失时 skip 并提示生成命令，不静默通过）
"""
import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPTS_DIR = os.path.join(ROOT, "scripts")
if SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, SCRIPTS_DIR)

from gen_openapi import OUT_PATH, build_spec, dumps  # noqa: E402

#: dashboard 必须对外暴露的关键端点（防路由被误删/改名）
_REQUIRED_PATHS = (
    "/api/status",
    "/api/scans",
    "/api/scans/{scan_id}",
    "/api/findings",
    "/api/dag/{scan_id}",
    "/api/workers",
    "/api/webhook/ingest",
    "/health",
    "/ready",
    "/metrics",
)


@pytest.fixture(scope="module")
def spec() -> dict:
    return build_spec()


def test_spec_is_valid_openapi(spec):
    assert isinstance(spec, dict)
    assert str(spec.get("openapi", "")).startswith("3."), f"openapi 版本异常: {spec.get('openapi')}"
    info = spec.get("info") or {}
    assert info.get("title"), "info.title 缺失"
    assert info.get("version"), "info.version 缺失"
    assert spec.get("paths"), "paths 为空"


def test_required_paths_present(spec):
    paths = set((spec.get("paths") or {}).keys())
    missing = [p for p in _REQUIRED_PATHS if p not in paths]
    assert not missing, f"OpenAPI 缺少关键端点: {missing}（现有: {sorted(paths)}）"


def test_spec_serialization_is_deterministic(spec):
    assert dumps(spec) == dumps(build_spec())


def test_committed_contract_matches_runtime(spec):
    if not os.path.exists(OUT_PATH):
        pytest.skip(
            f"契约件未生成: {OUT_PATH}（运行 python scripts/gen_openapi.py 后本用例转为强校验）"
        )
    with open(OUT_PATH, encoding="utf-8") as f:
        committed = json.loads(f.read())
    assert committed == spec, "docs/openapi.json 与运行时漂移：请重新运行 python scripts/gen_openapi.py"
