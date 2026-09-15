#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组件漏洞知识库构建器：**用数据替代手写阈值**（组件库宽度解法）。

为什么需要它
============
手写签名（`{"lib": ..., "vulnerable_below": ...}`）的问题：
  1) 宽度受限于人力（我们写了 26 条，真实项目动辄几百个依赖）；
  2) 会过期（新 CVE 持续披露，手写阈值不变 → 相对覆盖率单调下降）。
OSV 提供**每个包的影响版本区间**（introduced/fixed），且是公开批量数据。
把它落成一份本地 KB，组件判据就从"手写阈值"升级为"查表"，宽度 = KB 覆盖面。

用法（仓库根目录）
    python scripts/build_component_kb.py                 # 用 thirdparty/osv/*.zip
    python scripts/build_component_kb.py --stats         # 只打统计
产物
    thirdparty/osv/component_kb.json   （生成物，不入库；缺失时判据自动降级为内置签名）
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import zipfile
from collections import defaultdict
from typing import Any, Dict, List

# 独立脚本：先把 src 挂进 sys.path（与 scan.py / eval_prf.py 同口径）
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from vulnclaw.paths import PROJECT_ROOT  # noqa: E402

OSV_DIR = os.path.join(PROJECT_ROOT, "thirdparty", "osv")
DEFAULT_OUT = os.path.join(OSV_DIR, "component_kb.json")

# 每个生态对应的 zip 文件名（OSV 批量数据命名）
ECOSYSTEMS = ("Maven", "PyPI", "npm")


def _events_to_ranges(affected: Dict[str, Any]) -> List[Dict[str, str]]:
    """把 OSV 的 ranges 展开成若干区间。

    只取 SEMVER / ECOSYSTEM 两种区间类型；GIT 区间（commit 粒度）无法用于
    版本字符串判定，直接跳过（跳过而非猜测——猜了就是误报）。

    上界两种写法都要认：
      - `fixed: X`         → **开区间**（X 已修复，不含 X）
      - `last_affected: X` → **闭区间**（X 仍受影响，含 X）
    只认 fixed 会把 last_affected 当成"无上界"→ 高版本被误报（实测 aws-sdk 就踩到）。
    """
    out: List[Dict[str, str]] = []
    for rng in (affected.get("ranges") or []):
        if str(rng.get("type") or "").upper() not in ("SEMVER", "ECOSYSTEM"):
            continue
        intro, fixed, last_aff = "", "", ""
        for ev in rng.get("events") or []:
            if "introduced" in ev:
                intro = str(ev["introduced"] or "")
            elif "fixed" in ev:
                fixed = str(ev["fixed"] or "")
                out.append({"i": intro, "f": fixed, "la": last_aff, "id": ""})
            elif "last_affected" in ev:
                last_aff = str(ev["last_affected"] or "")
                out.append({"i": intro, "f": "", "la": last_aff, "id": ""})
        # 只有 introduced、没有上界（至今未修）→ 也记录（无上界）
        if intro and not fixed and not last_aff and not out:
            out.append({"i": intro, "f": "", "la": "", "id": ""})
    return out


def build(eco: str, path: str) -> Dict[str, List[Dict[str, str]]]:
    kb: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    if not os.path.isfile(path):
        return {}
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        # 常见：下载被中断留下半包。**跳过而不是猜**——半包会产出残缺 KB，
        # 残缺 KB 会让"没命中"看起来像"包是安全的"，那是最坏的假阴性。
        print(f"[kb] 跳过 {eco}：{os.path.basename(path)} 不是有效 zip（多半是下载中断的残包）")
        return {}
    with zf as z:
        for name in z.namelist():
            if not name.endswith(".json"):
                continue
            try:
                rec = json.loads(z.open(name).read())
            except (json.JSONDecodeError, OSError):
                continue
            # 已撤回的公告必须排除：撤回通常意味着"判定有误/不适用"，报出来就是误报
            if rec.get("withdrawn"):
                continue
            vid = str(rec.get("id") or "")
            for aff in (rec.get("affected") or []):
                pkg = (aff.get("package") or {}).get("name")
                if not pkg:
                    continue
                for r in _events_to_ranges(aff):
                    if not (r["i"] or r["f"]):
                        continue
                    r = dict(r)
                    r["id"] = vid
                    kb[pkg].append(r)
    return dict(kb)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--stats", action="store_true", help="只打统计，不写文件")
    ap.add_argument("--ecosystems", default=",".join(ECOSYSTEMS))
    _a = ap.parse_args()

    os.makedirs(OSV_DIR, exist_ok=True)
    data: Dict[str, Dict[str, list]] = {}
    for eco in [e.strip() for e in _a.ecosystems.split(",") if e.strip()]:
        zpath = os.path.join(OSV_DIR, f"{eco}.zip")
        if not os.path.isfile(zpath):
            print(f"[kb] 跳过 {eco}：缺少 {zpath}（可先下载 OSV 批量数据）")
            continue
        t0 = time.time()
        kb = build(eco, zpath)
        data[eco] = kb
        n_adv = sum(len(v) for v in kb.values())
        print(f"[kb] {eco}: {len(kb)} 个包 / {n_adv} 条影响区间，{time.time()-t0:.1f}s")

    if not data:
        print("[kb] 没有任何可用数据 → 不生成（判据将降级为内置手写签名，不会误报）")
        return 2

    payload = {
        "version": 1,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": "OSV (https://osv.dev)",
        "stats": {e: {"packages": len(v), "ranges": sum(len(x) for x in v.values())}
                  for e, v in data.items()},
        "ecosystems": data,
    }
    if _a.stats:
        print(json.dumps(payload["stats"], ensure_ascii=False, indent=2))
        return 0

    with open(_a.out, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, ensure_ascii=False, separators=(",", ":"))
    size = os.path.getsize(_a.out) / 1048576
    print(f"[kb] 已写入 {_a.out}（{size:.1f} MB）")
    print(f"[kb] 总覆盖：{sum(len(v) for v in data.values())} 个包")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
