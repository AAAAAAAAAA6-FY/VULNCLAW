#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""H.4 工具治理覆盖评估（只读工具目录，不重装/不扫描）。

清单 v2 组 H：评审关注「所有会出网/会写本地的工具都有熔断」——danger_guard 已按
DANGEROUS_OPS / DANGEROUS_TOOL_PARAMS 做参数级熔断。本脚本从治理权威声明
`core/data/tool_directory.yaml` 角度，评估「受管覆盖」与「风险分类」：
  - 受管工具总数 / 按 danger(safe/guarded/destructive) 分布；
  - 按 capability 分布；
  - 完整性校验开关（defaults.verify_on_use）；
  - 未钉定版本（缺 ver）的工具——供应链不可复现风险点；
  - 治理评分（受管率 + 版本钉定率 + 校验开关）。
用法：
    python scripts/tool_governance_audit.py
输出：
    控制台评估表 + 一行 GOVERNANCE 指标
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIR_YAML = ROOT / "src" / "vulnclaw" / "core" / "data" / "tool_directory.yaml"


def main() -> int:
    if not DIR_YAML.exists():
        print(f"NO_TOOL_DIRECTORY {DIR_YAML}")
        return 0
    try:
        import yaml
    except Exception:  # noqa: BLE001
        print("PyYAML 未安装，无法解析工具目录")
        return 0

    data = yaml.safe_load(DIR_YAML.read_text(encoding="utf-8")) or {}
    tools: dict = data.get("tools", {}) or {}
    defaults: dict = data.get("defaults", {}) or {}
    total = len(tools)
    by_danger: dict[str, int] = {}
    by_cap: dict[str, int] = {}
    unpinned = 0
    for name, spec in tools.items():
        spec = spec or {}
        d = str(spec.get("danger", "unknown"))
        by_danger[d] = by_danger.get(d, 0) + 1
        c = str(spec.get("capability", "unknown"))
        by_cap[c] = by_cap.get(c, 0) + 1
        if not spec.get("ver"):
            unpinned += 1

    verify = bool(defaults.get("verify_on_use", False))
    health = defaults.get("health", {}) or {}
    print(f"TOOL_DIRECTORY tools={total} verify_on_use={verify}")
    print("| danger | count |")
    print("|---|---|")
    for k in ("safe", "guarded", "destructive", "unknown"):
        if by_danger.get(k):
            print(f"| {k} | {by_danger[k]} |")
    print("| capability | count |")
    print("|---|---|")
    for c, n in sorted(by_cap.items(), key=lambda x: -x[1]):
        print(f"| `{c}` | {n} |")
    print(f"UNPINNED_VERSION={unpinned} HEALTH_MAX_FAIL={health.get('max_consecutive_failures','-')} "
          f"HEALTH_TTL={health.get('degraded_ttl_seconds','-')}s")
    # 治理评分：受管率 100%（都在目录中）+ 版本钉定率 + 校验开关
    pin_rate = (total - unpinned) / total if total else 0
    score = round((1.0 * (1 if total else 0) + pin_rate + (1 if verify else 0)) / 3 * 100)
    gov = {"managed": total, "unpinned": unpinned, "pin_rate": round(pin_rate, 3),
           "verify_on_use": verify, "score": score}
    print(f"GOVERNANCE={json.dumps(gov, ensure_ascii=False)}")
    print(f"评分说明：受管率100% + 版本钉定率{pin_rate*100:.0f}% + 校验开关{1 if verify else 0} -> {score}/100")
    return 0


if __name__ == "__main__":
    sys.exit(main())
