#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F1-3 第三方工具 SHA256 完整性校验（离线、fail-open 记录、不下载）。

背景：`thirdparty/` 下是外部下载的二进制（nuclei/ffuf/httpx…），一旦被替换/投毒，
扫描结论就不可信。本脚本按 `thirdparty/tools.yaml` 登记的工具名，对**本机存在**的
二进制计算 SHA256，与 `thirdparty/tools_integrity.json` 清单比对。

行为约定（刻意设计，避免"没有工具就报红"）：
  - 工具缺失 → **跳过并计数**，打印明确原因（`SKIP`），不算失败（fail-open 记录）；
  - 哈希与清单不一致 → 打印 `MISMATCH` 明细并 **exit 2**（硬失败）；
  - 存在但清单未登记 → 打印 `UNTRACKED` 警告（`--strict` 时 exit 2）；
  - 与安装期清单 `thirdparty/tool_manifest.json`（每次下载时记录）交叉比对，可发现"装完被换"。

用法：
    python scripts/verify_tools.py                 # 校验（清单不存在则生成）
    python scripts/verify_tools.py --update        # 用当前文件刷新清单（已存在项合并保留）
    python scripts/verify_tools.py --strict        # UNTRACKED 也算失败（exit 2）
    python scripts/verify_tools.py --json          # 机器可读输出
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
THIRDPARTY = ROOT / "thirdparty"
DEFAULT_REGISTRY = THIRDPARTY / "tools.yaml"
DEFAULT_MANIFEST = THIRDPARTY / "tools_integrity.json"
INSTALL_MANIFEST = THIRDPARTY / "tool_manifest.json"

MANIFEST_SCHEMA = 1
EXIT_OK = 0
EXIT_USAGE = 1
EXIT_MISMATCH = 2
# 低于该体积基本可判定为残留/损坏文件（与 utils.plan_tool_install 的 100KB 判据一致）
_MIN_TOOL_SIZE = 100 * 1024


def load_registry(path: Path = DEFAULT_REGISTRY) -> dict:
    """读 tools.yaml 的 tools 段；文件缺失/无法解析返回 {}。"""
    if not path.is_file():
        return {}
    try:
        import yaml
    except ImportError:  # pragma: no cover - pyyaml 是项目依赖
        print(f"❌ 需要 pyyaml 才能解析 {path}（pip install pyyaml）", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        print(f"❌ 解析 {path} 失败: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    tools = data.get("tools") or {}
    return tools if isinstance(tools, dict) else {}


def resolve_executable(executable: str, third_dir: Path = THIRDPARTY) -> tuple[str, str]:
    """定位二进制：先在 thirdparty/ 内递归找同名文件，再回退系统 PATH。

    返回 (绝对路径, 来源) ；找不到返回 ("", "")。
    注：此处**刻意不用** `shutil.which` 作首选——扫描器运行时统一走
    `core.tool_registry.tool_available`，而 thirdparty 下的工具通常不在 PATH 上。
    """
    name = str(executable or "").strip()
    if not name:
        return "", ""
    if third_dir.is_dir():
        direct = third_dir / name
        if direct.is_file():
            return str(direct), "thirdparty"
        # 目录型分发（如 thirdparty/<tool>/<tool>.exe）：限制深度避免全盘遍历
        for cand in sorted(third_dir.glob(f"*/{name}")):
            if cand.is_file():
                return str(cand), "thirdparty"
        for cand in sorted(third_dir.glob(f"*/*/{name}")):
            if cand.is_file():
                return str(cand), "thirdparty"
    found = shutil.which(name)
    if found:
        return found, "PATH"
    return "", ""


def sha256_file(path: Path | str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    tools = data.get("tools") if isinstance(data, dict) else None
    return tools if isinstance(tools, dict) else {}


def load_install_manifest(path: Path = INSTALL_MANIFEST) -> dict:
    """安装期清单（core.utils._record_tool_manifest 写入）：{name: {ver, sha256}}。"""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return {}
    return data if isinstance(data, dict) else {}


def scan_present(registry: dict) -> tuple[dict, list]:
    """扫描本机实际存在的工具：返回 ({name: record}, [(name, 跳过原因)])。"""
    records: dict[str, dict] = {}
    skipped: list[tuple[str, str]] = []
    for name in sorted(registry):
        entry = registry.get(name) or {}
        executable = str(entry.get("executable") or name)
        path, source = resolve_executable(executable)
        if not path:
            skipped.append((name, f"未找到 {executable}（thirdparty/ 与 PATH 均无）"))
            continue
        size = Path(path).stat().st_size
        if size < _MIN_TOOL_SIZE:
            skipped.append((name, f"{executable} 仅 {size} 字节，疑似残留/损坏，不纳入清单"))
            continue
        records[name] = {
            "executable": executable,
            "sha256": sha256_file(path),
            "size": size,
            "source": source,
            "path": _relative_hint(path, source),
        }
    return records, skipped


def _relative_hint(path: str, source: str) -> str:
    """可移植路径提示：只存相对 thirdparty/ 或文件名，绝不写本机绝对路径。"""
    p = Path(path)
    if source == "thirdparty":
        try:
            return p.relative_to(THIRDPARTY).as_posix()
        except ValueError:
            return p.name
    return p.name


def merge_manifest(old: dict, present: dict) -> dict:
    """刷新语义：本机存在的工具更新记录，缺失的保留旧记录（跨平台跑不互相抹掉）。"""
    merged = {k: dict(v) for k, v in old.items()}
    merged.update({k: dict(v) for k, v in present.items()})
    return {k: merged[k] for k in sorted(merged)}


def write_manifest(path: Path, tools: dict) -> None:
    payload = {
        "schema": MANIFEST_SCHEMA,
        "note": "第三方工具 SHA256 完整性清单；由 python scripts/verify_tools.py --update 生成，"
                "已存在项合并保留，勿手工编辑。缺失工具不移除记录（跨平台安全）。",
        "registry": "thirdparty/tools.yaml",
        "algorithms": ["SHA-256"],
        "tools": {k: tools[k] for k in sorted(tools)},
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def verify(present: dict, manifest: dict, install_manifest: dict) -> dict:
    """比对：返回 {"mismatch": [...], "untracked": [...], "ok": [...]}。"""
    mismatch, untracked, ok = [], [], []
    for name in sorted(present):
        rec = present[name]
        ref = manifest.get(name)
        if not ref:
            untracked.append({"name": name, "sha256": rec["sha256"], "size": rec["size"]})
            continue
        if str(ref.get("sha256") or "") != rec["sha256"]:
            mismatch.append({
                "name": name,
                "expected": str(ref.get("sha256") or "")[:16],
                "actual": rec["sha256"][:16],
                "size": rec["size"],
                "reason": "清单不符（文件被替换/损坏/版本被覆盖）",
            })
            continue
        install_ref = install_manifest.get(name) or {}
        install_hash = str(install_ref.get("sha256") or "")
        if install_hash and install_hash != rec["sha256"]:
            mismatch.append({
                "name": name,
                "expected": install_hash[:16],
                "actual": rec["sha256"][:16],
                "size": rec["size"],
                "reason": "安装期 tool_manifest.json 记录不符（下载后被改动）",
            })
            continue
        ok.append({"name": name, "sha256": rec["sha256"], "size": rec["size"]})
    return {"mismatch": mismatch, "untracked": untracked, "ok": ok}


def _human_size(n: int) -> str:
    return f"{n / 1024 / 1024:.1f}MB"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="第三方工具 SHA256 完整性校验（F1-3，离线）")
    parser.add_argument("--registry", default=str(DEFAULT_REGISTRY), help="工具注册表 YAML")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="完整性清单 JSON")
    parser.add_argument("--update", action="store_true", help="用当前文件刷新清单（缺失项保留）")
    parser.add_argument("--strict", action="store_true", help="未登记的新工具也视为失败（exit 2）")
    parser.add_argument("--json", action="store_true", help="输出机器可读 JSON 摘要")
    args = parser.parse_args(argv)

    registry_path = Path(args.registry)
    manifest_path = Path(args.manifest)
    registry = load_registry(registry_path)
    if not registry:
        print(f"⚠️ 注册表为空或不存在: {registry_path}（跳过校验，exit 0）")
        if args.json:
            print(json.dumps({"registry_found": False, "total": 0}, ensure_ascii=False))
        return EXIT_OK

    present, skipped = scan_present(registry)
    manifest = load_manifest(manifest_path)
    first_run = not manifest

    if args.update or first_run:
        merged = merge_manifest(manifest, present)
        write_manifest(manifest_path, merged)
        action = "刷新" if args.update else "首次生成"
        print(f"📝 完整性清单已{action}: {manifest_path}"
              f"（登记 {len(merged)} 项，其中本机可见 {len(present)} 项）")
        manifest = merged

    result = verify(present, manifest, load_install_manifest())
    summary = {
        "registry": str(registry_path.as_posix()),
        "manifest": str(manifest_path.as_posix()),
        "registry_total": len(registry),
        "present": len(present),
        "verified": len(result["ok"]),
        "skipped": len(skipped),
        "mismatch": len(result["mismatch"]),
        "untracked": len(result["untracked"]),
    }

    if not args.json:
        print("=" * 68)
        print(f"🔐 工具完整性校验：注册表 {len(registry)} 项 / 本机可见 {len(present)} 项")
        for item in result["ok"]:
            print(f"  OK        {item['name']:<20s} {item['sha256'][:16]}…  {_human_size(item['size'])}")
        for item in result["mismatch"]:
            print(f"  MISMATCH  {item['name']:<20s} 期望 {item['expected']}… 实际 {item['actual']}…"
                  f"  ← {item['reason']}")
        for item in result["untracked"]:
            print(f"  UNTRACKED {item['name']:<20s} {item['sha256'][:16]}…（清单未登记）")
        for name, reason in skipped:
            print(f"  SKIP      {name:<20s} {reason}")
        print("-" * 68)
        print(f"结果：通过 {summary['verified']} / 不符 {summary['mismatch']} / "
              f"未登记 {summary['untracked']} / 跳过 {summary['skipped']}")
        if summary["skipped"]:
            print("ℹ️  跳过项为「本机未安装该工具」，属预期（thirdparty/ 不入库）——"
                  "fail-open 记录，不阻断；需要哈希请在装有工具的机器上跑 --update。")
        print("=" * 68)
    else:
        summary["details"] = {
            "ok": [i["name"] for i in result["ok"]],
            "mismatch": result["mismatch"],
            "untracked": [i["name"] for i in result["untracked"]],
            "skipped": [{"name": n, "reason": r} for n, r in skipped],
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))

    if result["mismatch"]:
        return EXIT_MISMATCH
    if args.strict and result["untracked"]:
        return EXIT_MISMATCH
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
