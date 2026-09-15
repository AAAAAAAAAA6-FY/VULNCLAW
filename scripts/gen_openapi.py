#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""生成 docs/openapi.json —— dashboard REST API 的 OpenAPI 契约件（真缺口 ③）。

为什么需要
----------
dashboard 的 FastAPI 应用**运行时**能产出 OpenAPI，但生态集成（生成 SDK、CI 契约
校验、对接方评审）需要一份**入库的静态契约件**。本脚本把它导出为确定性 JSON：

- 只入业务契约：``paths`` / ``components`` / ``info`` 等全部保留；
- **确定性序列化**：``sort_keys=True`` + 固定缩进 + 结尾换行 → 同代码必然同字节，
  可直接在 CI 做 `git diff --exit-code docs/openapi.json` 漂移检查；
- **无副作用**：只调 ``DashboardServer.create_app()``（建路由，不连 Redis、不启动服务）。

用法
----
    python scripts/gen_openapi.py            # 写入 docs/openapi.json
    python scripts/gen_openapi.py --check    # 只校验是否与入库件一致（CI 用，不一致 exit 1）

退出码：0 成功/一致；1 校验不一致；2 生成失败。
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Windows 控制台可能是 GBK：显式降级不可编码字符，避免 print emoji 抛 UnicodeEncodeError
# （写盘始终 UTF-8，不受影响）。
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(errors="replace")  # type: ignore[union-attr]
    except Exception:  # noqa: BLE001 - 非 TTY / 旧解释器兼容
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_PATH = os.path.join(ROOT, "docs", "openapi.json")


def _ensure_src_on_path() -> None:
    src = os.path.join(ROOT, "src")
    if src not in sys.path:
        sys.path.insert(0, src)


def build_spec() -> dict:
    """构建 OpenAPI spec（纯内存，不联网）。"""
    _ensure_src_on_path()
    from vulnclaw.dashboard.server import DashboardServer

    # 占位参数：仅用于建路由表，不建立任何连接
    app = DashboardServer(
        host="127.0.0.1",
        port=8080,
        redis_url="redis://127.0.0.1:6379/0",
    ).create_app()
    return app.openapi()


def dumps(spec: dict) -> str:
    """确定性序列化（与测试共用，避免两处格式漂移）。"""
    return json.dumps(spec, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="生成/校验 OpenAPI 契约件 docs/openapi.json")
    parser.add_argument("--check", action="store_true", help="只校验入库件与运行时是否一致（不写盘）")
    args = parser.parse_args(argv)

    try:
        spec = build_spec()
    except Exception as exc:  # noqa: BLE001 - 生成失败必须显式失败退出
        print(f"❌ OpenAPI 生成失败: {exc}", file=sys.stderr)
        return 2

    text = dumps(spec)
    paths = spec.get("paths", {}) if isinstance(spec, dict) else {}

    if args.check:
        if not os.path.exists(OUT_PATH):
            print(f"❌ 契约件缺失: {OUT_PATH}（先运行 python scripts/gen_openapi.py）", file=sys.stderr)
            return 1
        current = open(OUT_PATH, encoding="utf-8").read()
        if current != text:
            print(
                f"❌ OpenAPI 契约漂移: {OUT_PATH} 与运行时不一致"
                "（运行 python scripts/gen_openapi.py 重新生成并提交）",
                file=sys.stderr,
            )
            return 1
        print(f"✅ OpenAPI 契约一致（paths={len(paths)}）")
        return 0

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"✅ OpenAPI 契约已生成: {OUT_PATH}（paths={len(paths)}）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
