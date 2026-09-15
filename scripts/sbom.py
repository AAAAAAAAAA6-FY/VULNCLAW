#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F1-1 离线 SBOM 生成器（CycloneDX 风格 JSON）。

设计约束（离线优先）：
  - 不联网、不 pip、不调用外部 SBOM 工具；只用 stdlib（tomllib + importlib.metadata）。
  - 组件来源两路合并：
      1. pyproject.toml 的 [project].dependencies 与 [project.optional-dependencies]（直接依赖）；
      2. 本机已安装发行包（importlib.metadata.distributions()）——含传递依赖与环境包。
  - 许可证一律从包元数据取（License-Expression → License 分类器 → License 字段），
    取不到就写 UNKNOWN，**不编造、不猜测**。

用法：
    python scripts/sbom.py                              # 写 <repo>/SBOM.json
    python scripts/sbom.py --output SBOM.json
    python scripts/sbom.py --licenses-md docs/LICENSES.md
    python scripts/sbom.py --stdout                     # 打到标准输出（不落盘）

可复现性：设置 SOURCE_DATE_EPOCH（秒）可固定 metadata.timestamp 与 serialNumber 之外的
时间字段，便于 diff 与测试。
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover - 理论上不可达（requires-python >=3.11）
    tomllib = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
DEFAULT_OUTPUT = ROOT / "SBOM.json"

BOM_TOOL_NAME = "vulnclaw-sbom"
BOM_TOOL_VERSION = "1.0.0"
_SCHEMA = 1

# PEP 503 名称归一化：-_. 连续折叠为单个 '-'
_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
_SPDX_LIKE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{1,63}$")


def normalize_name(name: str) -> str:
    """PEP 503 归一化包名（比较/去重用）。"""
    return re.sub(r"[-_.]+", "-", str(name or "").strip()).lower()


def _pep508_name(spec: str) -> str:
    """从 PEP 508 依赖串里取包名：'httpx[http2]>=0.27.0' -> 'httpx'。"""
    m = _NAME_RE.match(str(spec or ""))
    return normalize_name(m.group(1)) if m else ""


def load_declared(path: Path = PYPROJECT) -> dict:
    """读 pyproject：返回 {'name','version','dependencies':{norm_name: raw_spec}}。"""
    if tomllib is None or not path.is_file():
        return {"name": "", "version": "", "dependencies": {}}
    with open(path, "rb") as fh:
        data = tomllib.load(fh)
    project = data.get("project") or {}
    deps: dict[str, str] = {}
    for spec in project.get("dependencies") or []:
        name = _pep508_name(spec)
        if name:
            deps[name] = str(spec)
    for group, items in (project.get("optional-dependencies") or {}).items():
        for spec in items or []:
            name = _pep508_name(spec)
            if name and name not in deps:
                deps[name] = f"{spec}  [extra:{group}]"
    return {
        "name": str(project.get("name") or ""),
        "version": str(project.get("version") or ""),
        "dependencies": deps,
    }


def _dist_requires(dist_name: str) -> list[str]:
    """某发行包的基础依赖（跳过 optional extra 的 marker），返回归一化包名列表。"""
    try:
        reqs = md.requires(dist_name) or []
    except Exception:  # noqa: BLE001 - 元数据缺失/异常一律当无依赖
        return []
    out = []
    for raw in reqs:
        text = str(raw or "")
        if ";" in text:
            marker = text.split(";", 1)[1].lower()
            if "extra" in marker:
                continue
        name = _pep508_name(text)
        if name:
            out.append(name)
    return out


def installed_distributions() -> dict:
    """本机已安装发行包：{norm_name: (display_name, version)}（同名取最高版本）。"""
    found: dict[str, tuple[str, str]] = {}
    for dist in md.distributions():
        try:
            raw_name = dist.metadata["Name"]
            version = dist.version or ""
        except Exception:  # noqa: BLE001
            continue
        if not raw_name:
            continue
        key = normalize_name(raw_name)
        prev = found.get(key)
        if prev is None or _version_key(version) > _version_key(prev[1]):
            found[key] = (str(raw_name), str(version))
    return found


def _version_key(version: str) -> tuple:
    """宽松版本排序键（不依赖 packaging）：数字段按数值比，其余按字符串。"""
    parts = re.split(r"[.\-+]", str(version or ""))
    key = []
    for p in parts:
        key.append((0, int(p)) if p.isdigit() else (1, str(p)))
    return tuple(key)


def license_of(dist_name: str) -> str:
    """从包元数据取许可证标识；取不到返回 UNKNOWN（不编造）。"""
    try:
        meta = md.metadata(dist_name)
    except Exception:  # noqa: BLE001
        return "UNKNOWN"
    expr = (meta.get("License-Expression") or "").strip()
    if expr:
        return expr
    for classifier in (meta.get_all("Classifier") or []):
        if classifier.startswith("License ::"):
            leaf = classifier.split("::")[-1].strip()
            if leaf:
                return leaf
    lic = (meta.get("License") or "").strip()
    # License 字段常塞整篇许可证正文；只接受单行短标识，否则一律 UNKNOWN
    if lic and "\n" not in lic and len(lic) <= 80:
        return lic
    return "UNKNOWN"


def _license_entry(lic: str) -> list[dict]:
    if lic and lic != "UNKNOWN" and _SPDX_LIKE_RE.match(lic):
        return [{"license": {"id": lic}}]
    return [{"license": {"name": lic or "UNKNOWN"}}]


def _reachable(direct: list[str]) -> set:
    """从直接依赖出发做基础依赖闭包（BFS，跳过 optional extra）。"""
    seen: set = set()
    queue = [d for d in direct]
    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)
        queue.extend(_dist_requires(name))
    return seen


def build_bom(declared: dict | None = None) -> dict:
    """组装 CycloneDX 风格 BOM 字典（纯函数，便于测试）。"""
    declared = declared if declared is not None else load_declared()
    direct: dict[str, str] = declared.get("dependencies") or {}
    installed = installed_distributions()
    transitive = _reachable([d for d in direct if d in installed])

    components: list[dict] = []
    for key in sorted(set(direct) | set(installed)):
        if key in direct and key in installed:
            display, version = installed[key]
            scope = "direct"
        elif key in installed:
            display, version = installed[key]
            scope = "transitive" if key in transitive else "environment"
        else:
            # 声明了但本机未安装：留名、版本空、范围 declared-missing
            display, version, scope = key, "", "declared-missing"
        version = version or ""
        lic = license_of(key) if key in installed else "UNKNOWN"
        purl = f"pkg:pypi/{key}" + (f"@{version}" if version else "")
        props = [
            {"name": "vulnclaw:dependency-scope", "value": scope},
            {"name": "vulnclaw:installed", "value": "true" if key in installed else "false"},
            {"name": "vulnclaw:license-source",
             "value": "metadata" if lic != "UNKNOWN" else "unavailable"},
        ]
        if key in direct:
            props.append({"name": "vulnclaw:declared-spec", "value": direct[key][:120]})
        components.append({
            "type": "library",
            "bom-ref": purl,
            "name": display,
            "version": version,
            "purl": purl,
            "licenses": _license_entry(lic),
            "properties": props,
        })

    app_name = declared.get("name") or "vulnclaw"
    app_version = declared.get("version") or ""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"vulnclaw/sbom/{app_name}/{app_version}")
        ),
        "version": _SCHEMA,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": [{"vendor": app_name, "name": BOM_TOOL_NAME, "version": BOM_TOOL_VERSION}],
            "component": {
                "type": "application",
                "bom-ref": f"pkg:pypi/{normalize_name(app_name)}"
                          + (f"@{app_version}" if app_version else ""),
                "name": app_name,
                "version": app_version,
            },
            "properties": [
                {"name": "vulnclaw:python-version", "value": sys.version.split()[0]},
                {"name": "vulnclaw:generator", "value": "scripts/sbom.py（离线，stdlib only）"},
                {"name": "vulnclaw:license-policy",
                 "value": "许可证取自安装包元数据，缺失记 UNKNOWN，不编造"},
            ],
        },
        "components": components,
    }


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH", "")
    if epoch.isdigit():
        dt = datetime.fromtimestamp(int(epoch), tz=timezone.utc)
    else:
        dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def license_rows(bom: dict) -> list[tuple[str, str, str, str]]:
    """(组件名, 版本, 许可证, 依赖范围) 列表，按许可证再按名称排序。"""
    rows = []
    for comp in bom["components"]:
        lic = "UNKNOWN"
        for entry in comp.get("licenses") or []:
            inner = entry.get("license") or {}
            lic = inner.get("id") or inner.get("name") or "UNKNOWN"
            break
        scope = "unknown"
        for prop in comp.get("properties") or []:
            if prop.get("name") == "vulnclaw:dependency-scope":
                scope = prop.get("value") or "unknown"
        rows.append((comp["name"], comp.get("version") or "", lic, scope))
    rows.sort(key=lambda r: (r[2].lower(), r[0].lower()))
    return rows


def render_licenses_md(bom: dict) -> str:
    """生成 docs/LICENSES.md 文本（确定性输出）。"""
    rows = license_rows(bom)
    total = len(rows)
    unknown = sum(1 for r in rows if r[2] == "UNKNOWN")
    dist: dict[str, int] = {}
    for r in rows:
        dist[r[2]] = dist.get(r[2], 0) + 1
    lines = [
        "# 第三方依赖许可证清单（LICENSES）",
        "",
        "> 本文件由 `python scripts/sbom.py --licenses-md docs/LICENSES.md` **离线生成**，请勿手改。",
        "> 许可证信息全部取自本机已安装发行包的元数据（`importlib.metadata`），",
        "> 取不到即记 `UNKNOWN`——如实呈现，不做推测。",
        "",
        f"- 组件总数（已安装 + pyproject 声明）：**{total}**",
        f"- 许可证未标注（UNKNOWN）：**{unknown}**",
        f"- 数据源：`pyproject.toml` + 本机 `importlib.metadata`",
        f"- 生成时间（UTC）：{bom['metadata']['timestamp']}",
        "- 命名口径：许可证字符串**原样取自上游元数据**（既有 SPDX 标识如 `MIT`/`Apache-2.0`，",
        "  也有分类器叶子名如 `MIT License`/`BSD License`），不做归一化改写，避免引入错误推断。",
        "",
        "## 许可证分布",
        "",
        "| 许可证 | 组件数 |",
        "| --- | ---: |",
    ]
    for lic, cnt in sorted(dist.items(), key=lambda kv: (-kv[1], kv[0].lower())):
        lines.append(f"| {lic} | {cnt} |")
    lines += [
        "",
        "## 组件明细",
        "",
        "| 包名 | 版本 | 许可证 | 依赖范围 |",
        "| --- | --- | --- | --- |",
    ]
    for name, version, lic, scope in rows:
        lines.append(f"| {name} | {version or '-'} | {lic} | {scope} |")
    lines += [
        "",
        "## 依赖范围说明",
        "",
        "- `direct`：`pyproject.toml` 直接声明且本机已安装；",
        "- `transitive`：由直接依赖的基础依赖（非 optional extra）传递引入；",
        "- `environment`：本机已安装但不在依赖闭包内（多为开发/工具类包）；",
        "- `declared-missing`：`pyproject.toml` 声明了但本机未安装（版本字段为空）。",
        "",
    ]
    return "\n".join(lines)


def _print_summary(bom: dict) -> None:
    rows = license_rows(bom)
    dist: dict[str, int] = {}
    for r in rows:
        dist[r[2]] = dist.get(r[2], 0) + 1
    print(f"组件数: {len(rows)}（UNKNOWN 许可证 {dist.get('UNKNOWN', 0)} 个）")
    print("许可证分布: " + ", ".join(
        f"{k}={v}" for k, v in sorted(dist.items(), key=lambda kv: (-kv[1], kv[0].lower()))[:12]
    ))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="离线生成 CycloneDX 风格 SBOM（F1-1）")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="SBOM JSON 输出路径")
    parser.add_argument("--licenses-md", default="", help="同时生成许可证清单 Markdown 到该路径")
    parser.add_argument("--stdout", action="store_true", help="只打印 SBOM 到标准输出，不落盘")
    args = parser.parse_args(argv)

    declared = load_declared()
    if not declared.get("name"):
        print(f"❌ 无法读取 {PYPROJECT}（缺 [project] 段）", file=sys.stderr)
        return 1
    bom = build_bom(declared)
    text = json.dumps(bom, ensure_ascii=False, indent=2, sort_keys=False)

    if args.stdout:
        print(text)
    else:
        out = Path(args.output)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text + "\n", encoding="utf-8")
        print(f"✅ SBOM 已写入 {out}")
    if args.licenses_md:
        target = Path(args.licenses_md)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_licenses_md(bom), encoding="utf-8")
        print(f"✅ 许可证清单已写入 {target}")
    _print_summary(bom)
    return 0


if __name__ == "__main__":
    sys.exit(main())
