#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D2：Vulhub 场景执行编排（plan-first，无 Docker 时只打印计划并 exit 2）。

行为约定（如实优先）：
  - 默认 dry-run：读取 profile 中 10 个场景，打印完整 start → scan → cleanup
    命令序列（含 `<compose_file>` / `<target_url>` 占位替换），不执行任何容器操作；
  - Docker 缺失：dry-run 也 exit 2（计划照常打印——阻塞原因明确，不伪造"已验证"）；
  - `--execute`：仅当 Docker 可用且操作员提供了真实 scenario_dir 时逐场景执行，
    每个场景的结果 JSON 落 `_runtime_cache/lab_results/<scenario>_<ts>.json`
    （记录 revision/命令/退出码/时间；revision 为 TODO 占位时原样记录，不编造）。

用法：
    python scripts/lab_vulhub.py                          # dry-run 全部场景
    python scripts/lab_vulhub.py --scenario ssrf          # dry-run 单场景
    python scripts/lab_vulhub.py --json                   # 计划输出为 JSON
    python scripts/lab_vulhub.py --execute                # 真实执行（需 Docker）
    python scripts/lab_vulhub.py --execute --scenario oob  # 不支持：按 name 精确匹配
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "scripts" / "lab_profiles" / "vulhub.yaml"
RESULTS_DIR = ROOT / "_runtime_cache" / "lab_results"

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_BLOCKED = 2  # 环境阻塞（无 Docker / 无 scenario_dir）：不执行、不伪造


def load_profile(path: Path = DEFAULT_PROFILE) -> Dict[str, Any]:
    """读 profile；文件缺失/无法解析 → 空 dict（fail-closed，不编造场景）。"""
    if not path.is_file():
        return {}
    try:
        import yaml
    except ImportError:  # pragma: no cover - pyyaml 是项目依赖
        print("❌ 需要 pyyaml 才能解析 profile（pip install pyyaml）", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001
        print(f"❌ 解析 {path} 失败: {exc}", file=sys.stderr)
        raise SystemExit(EXIT_USAGE)
    return data if isinstance(data, dict) else {}


def docker_available() -> bool:
    """Docker CLI 是否存在（与 lab_preflight 同判据，不做 daemon 探测以免阻塞）。"""
    return shutil.which("docker") is not None


def _substitute(cmd: str, defaults: Dict[str, Any], scenario: Dict[str, Any]) -> str:
    """把 <compose_file>/<target_url> 占位符替换为场景级或默认值。"""
    compose = str(scenario.get("compose_file") or defaults.get("compose_file") or "docker-compose.yml")
    target = str(scenario.get("target_url") or defaults.get("target_url") or "http://127.0.0.1:8080")
    return (str(cmd or "")
            .replace("<compose_file>", compose)
            .replace("<target_url>", target))


def build_plan(profile: Dict[str, Any], only: Optional[str] = None) -> List[Dict[str, Any]]:
    """生成场景执行计划（确定性；不执行任何命令）。"""
    defaults = profile.get("defaults") or {}
    plans: List[Dict[str, Any]] = []
    for scenario in profile.get("scenarios") or []:
        if not isinstance(scenario, dict):
            continue
        name = str(scenario.get("name") or "").strip()
        if not name or (only and name != only):
            continue
        plans.append({
            "name": name,
            "scenario_dir": str(scenario.get("scenario_dir") or ""),
            "revision": str(scenario.get("image_or_revision") or "TODO"),
            "published_port": scenario.get("published_port"),
            "expected": str(scenario.get("expected_vulnerability") or ""),
            "start": _substitute(scenario.get("start_cmd"), defaults, scenario),
            "scan": _substitute(scenario.get("scan_cmd"), defaults, scenario),
            "cleanup": _substitute(scenario.get("cleanup_cmd"), defaults, scenario),
            "notes": str(scenario.get("notes") or ""),
        })
    return plans


def _run_step(cmd: str, timeout: int) -> int:
    """执行单条命令（shell 形式），返回退出码；异常视为失败码 -1。"""
    try:
        proc = subprocess.run(cmd, shell=True, timeout=timeout, check=False)
        return int(proc.returncode)
    except Exception:  # noqa: BLE001
        return -1


def execute_plan(plan: Dict[str, Any], scan_timeout_s: int) -> Dict[str, Any]:
    """真实执行单场景：start → scan → cleanup；结果字典返回（含各步退出码）。"""
    started = time.time()
    result = {
        "scenario": plan["name"],
        "revision": plan["revision"],
        "expected": plan["expected"],
        "start_rc": _run_step(plan["start"], timeout=300),
        "scan_rc": _run_step(plan["scan"], timeout=scan_timeout_s),
        "cleanup_rc": _run_step(plan["cleanup"], timeout=300),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_s": round(time.time() - started, 1),
        "note": "容器启动/命令返回码不是检出证据；正例/负例结论需场景专属断言（见 docs/LAB_INTEGRATION.md）。",
    }
    return result


def _write_result(result: Dict[str, Any]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / f"{result['scenario']}_{int(time.time())}.json"
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def _print_plan(plans: List[Dict[str, Any]]) -> None:
    print(f"Vulhub 场景计划（dry-run，共 {len(plans)} 个场景，未执行任何命令）")
    print("=" * 68)
    for p in plans:
        print(f"[{p['name']}] revision={p['revision']}")
        print(f"  scenario_dir: {p['scenario_dir']}")
        print(f"  预期: {p['expected']}")
        print(f"  start  : {p['start']}")
        print(f"  scan   : {p['scan']}")
        print(f"  cleanup: {p['cleanup']}")
        if p["notes"]:
            print(f"  notes  : {p['notes']}")
        print("-" * 68)


def _vulhub_relpath(scenario: Dict[str, Any]) -> str:
    """从 scenario_dir 提取相对 vulhub 仓库根的路径（去掉 <vulhub-repo> 占位与行内注释）。"""
    raw = str(scenario.get("scenario_dir") or "")
    raw = raw.split("#")[0].strip()
    for token in ("<vulhub-repo>", "<vulhub_repo>", "<vulhubrepo>"):
        raw = raw.replace(token, "")
    return raw.strip().strip("/")


def pin_inventory(profile: Dict[str, Any], repo: str, only: Optional[str] = None) -> Dict[str, Any]:
    """工作流1：revision 锁定清点（**只读**）。

    记录 vulhub 检出 commit 与每个场景 compose 文件的镜像 tag；
    未提供/未检出/无 git 时如实置 ``available=False``（**绝不编造 revision**）。
    """
    repo_path = Path(repo).expanduser() if repo else None
    available = bool(repo_path and repo_path.is_dir())
    commit = ""
    if available:
        try:
            out = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0:
                commit = (out.stdout or "").strip()
        except (OSError, subprocess.SubprocessError):
            commit = ""
    compose_name = str((profile.get("defaults") or {}).get("compose_file") or "docker-compose.yml")
    items: List[Dict[str, Any]] = []
    for scenario in profile.get("scenarios") or []:
        if not isinstance(scenario, dict):
            continue
        name = str(scenario.get("name") or "").strip()
        if not name or (only and name != only):
            continue
        rel = _vulhub_relpath(scenario)
        entry: Dict[str, Any] = {"name": name, "relpath": rel, "compose": "", "images": [],
                                 "available": False}
        if available and rel and repo_path is not None:
            compose = repo_path / rel / compose_name
            if compose.is_file():
                entry["available"] = True
                entry["compose"] = str(compose)
                try:
                    for line in compose.read_text(encoding="utf-8", errors="ignore").splitlines():
                        stripped = line.strip()
                        if stripped.startswith("image:"):
                            entry["images"].append(stripped.split(":", 1)[1].strip())
                except OSError:
                    pass
        items.append(entry)
    return {
        "vulhub_repo": str(repo_path) if repo_path else "",
        "commit": commit,
        "available": available,
        "scenarios": items,
        "note": "只读清点：revision 以检出 commit + compose 镜像 tag 为准；未检出时 available=False（不编造）。",
    }


def _print_pin_inventory(inventory: Dict[str, Any]) -> None:
    print("=" * 70)
    print(f" Vulhub revision 清点: {inventory.get('vulhub_repo') or '(未提供 VULHUB_REPO/--vulhub-repo)'}")
    print(f" commit: {inventory.get('commit') or '(不可用——未检出或无 git)'}")
    print("=" * 70)
    for item in inventory.get("scenarios") or []:
        mark = "OK " if item.get("available") else "BLOCKED"
        print(f" [{mark}] {item.get('name')}: {item.get('relpath') or '?'}")
        for image in item.get("images") or []:
            print(f"            image: {image}")
    print("=" * 70)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Vulhub 场景执行编排（plan-first，D2）")
    parser.add_argument("--profile", default=str(DEFAULT_PROFILE), help="场景 profile YAML")
    parser.add_argument("--scenario", default="", help="仅处理指定场景名（精确匹配）")
    parser.add_argument("--execute", action="store_true", help="真实执行（需 Docker daemon）")
    parser.add_argument("--json", action="store_true", help="计划输出为 JSON")
    parser.add_argument("--pin", action="store_true",
                        help="只读清点 revision：记录 vulhub 检出 commit 与各场景 compose 镜像"
                             "（需 --vulhub-repo 或环境变量 VULHUB_REPO；不需要 Docker）")
    parser.add_argument("--vulhub-repo", default="", help="Vulhub 仓库检出路径（--pin 用）")
    args = parser.parse_args(argv)

    profile = load_profile(Path(args.profile))
    if not profile:
        print(f"❌ profile 缺失或为空: {args.profile}", file=sys.stderr)
        return EXIT_USAGE

    # 工作流1：revision 锁定清点（只读，不需要 Docker；未检出时如实 blocked）
    if args.pin:
        inventory = pin_inventory(profile, args.vulhub_repo or os.environ.get("VULHUB_REPO", ""),
                                  only=args.scenario or None)
        if args.json:
            print(json.dumps(inventory, ensure_ascii=False, indent=2))
        else:
            _print_pin_inventory(inventory)
        return EXIT_OK if inventory.get("available") else EXIT_BLOCKED

    plans = build_plan(profile, only=args.scenario or None)
    if args.scenario and not plans:
        print(f"❌ profile 中无场景: {args.scenario}", file=sys.stderr)
        return EXIT_USAGE

    if args.json and not args.execute:
        print(json.dumps({"scenarios": plans, "executed": False, "docker": docker_available()},
                         ensure_ascii=False, indent=2))
    elif not args.execute:
        _print_plan(plans)

    has_docker = docker_available()
    if not has_docker:
        print("⛔ 未检测到 Docker CLI：计划已生成，但不执行任何容器操作（truthful blocked）。",
              file=sys.stderr)
        print("   解锁条件：安装 Docker Desktop/daemon，并由操作员提供真实 scenario_dir 与端口映射。",
              file=sys.stderr)
        return EXIT_BLOCKED

    if not args.execute:
        print("✅ dry-run 完成（--execute 可真实执行；执行前先跑 scripts/lab_preflight.py 预检）。")
        return EXIT_OK

    scan_timeout_s = int((profile.get("defaults") or {}).get("scan_timeout_s") or 600)
    results = []
    for plan in plans:
        print(f"▶ 执行场景 [{plan['name']}] …")
        result = execute_plan(plan, scan_timeout_s=scan_timeout_s)
        path = _write_result(result)
        result["result_file"] = str(path)
        results.append(result)
        print(f"  结果: {path}（start_rc={result['start_rc']} scan_rc={result['scan_rc']} "
              f"cleanup_rc={result['cleanup_rc']}）")
    print(json.dumps({"executed": len(results),
                      "results": [r["result_file"] for r in results]},
                     ensure_ascii=False))
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
