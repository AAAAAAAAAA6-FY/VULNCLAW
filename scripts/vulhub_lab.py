# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""T06：WSL2 + Vulhub 靶场环境脚本（Windows 侧驱动）。

用途（为 T08「靶场检出率矩阵」提供真实目标）：
  1. --check      环境自检（WSL2 发行版 / Docker / vulhub 仓库），缺失时给安装指引；
  2. --list       列出本地 vulhub 仓库里的可用靶场目录；
  3. --up PATH    拉起一个靶场（docker compose up -d），支持多实例；
  4. --down PATH  停止并清理该靶场容器；
  5. --endpoints  输出当前运行中的靶场端点 JSON（供检出率矩阵消费）；
  6. --status     汇总：环境状态 + 已拉起靶场 + 端点。

设计约束：
  - **本机 WSL2 未装发行版时脚本必须"优雅失败"**：打印可复制的安装指引并以
    退出码 2 结束，绝不抛栈、绝不静默假装成功（靶场没起来却返回 0 是最坏情况 ——
    下游矩阵会拿空端点跑出"零检出"的假结论）。
  - 所有 WSL 调用统一走 `_wsl()`，集中处理编码（UTF-8）/超时/错误，避免各处拼字符串。
  - 靶场目录默认 `~/vulhub`，可用 --vulhub-dir 覆盖；仓库缺失时给 clone 指引。

用法（Windows 侧，任意 Python 3.10+）：
    python scripts/vulhub_lab.py --check
    python scripts/vulhub_lab.py --list
    python scripts/vulhub_lab.py --up struts2/s2-045
    python scripts/vulhub_lab.py --endpoints
    python scripts/vulhub_lab.py --down struts2/s2-045
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

DEFAULT_VULHUB_DIR = "~/vulhub"
DEFAULT_TIMEOUT = 60

EXIT_ENV_MISSING = 2  # 环境不具备（区别于"命令执行失败"的 1）


# ---------------------------------------------------------------------------
# WSL 调用层
# ---------------------------------------------------------------------------

def _wsl_available() -> bool:
    """Windows 侧是否有 wsl.exe。"""
    return shutil.which("wsl") is not None


def _wsl(cmd: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    """在 WSL 默认发行版里执行 bash 命令。

    Returns:
        {"ok": bool, "rc": int, "out": str, "err": str}
        rc == -1 表示调用本身失败（超时/无 wsl.exe）。
    """
    if not _wsl_available():
        return {"ok": False, "rc": -1, "out": "", "err": "wsl.exe not found"}
    try:
        proc = subprocess.run(
            ["wsl", "bash", "-lc", cmd],
            capture_output=True, timeout=timeout,
        )
        out = proc.stdout.decode("utf-8", errors="replace").strip()
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        return {"ok": proc.returncode == 0, "rc": proc.returncode, "out": out, "err": err}
    except subprocess.TimeoutExpired:
        return {"ok": False, "rc": -1, "out": "", "err": f"timeout after {timeout}s"}
    except Exception as exc:  # noqa: BLE001 - 平台差异大，统一成结构化结果
        return {"ok": False, "rc": -1, "out": "", "err": str(exc)}


def _print_install_guide() -> None:
    """环境缺失时的可复制安装指引（不抛栈）。"""
    print("""
[环境缺失] 未检测到可用的 WSL2 发行版。

按顺序执行（Windows PowerShell / 终端，管理员）：
  1) 安装 WSL2 与发行版：   wsl --install -d Ubuntu
  2) 重启终端后进入发行版： wsl
  3) 发行版内安装 Docker：  curl -fsSL https://get.docker.com | sh
                            sudo service docker start   (或 sudo systemctl start docker)
  4) 拉取 Vulhub 靶场仓库： git clone --depth 1 https://github.com/vulhub/vulhub.git ~/vulhub
  5) 回到本脚本复检：       python scripts/vulhub_lab.py --check

提示：第 4 步若 GitHub 不通，可改用镜像（gh-proxy.com）或手动下载 zip 解压到 ~/vulhub。
""")


# ---------------------------------------------------------------------------
# 环境自检
# ---------------------------------------------------------------------------

def check_env(vulhub_dir: str = DEFAULT_VULHUB_DIR) -> Dict[str, Any]:
    """自检 WSL2 / Docker / vulhub 仓库三项，返回结构化状态。"""
    status: Dict[str, Any] = {
        "wsl_exe": _wsl_available(),
        "distro": False, "docker": False, "vulhub_repo": False,
        "vulhub_dir": vulhub_dir, "distro_list": "",
    }
    if not status["wsl_exe"]:
        return status

    # 发行版：`wsl -l -q` 有输出即视为已装（注意输出可能是 UTF-16 或含 \x00）
    try:
        p = subprocess.run(["wsl", "-l", "-q"], capture_output=True, timeout=20)
        raw = p.stdout.decode("utf-8", errors="replace")
        if "\x00" in raw:
            raw = raw.replace("\x00", "")
        lines = [l.strip() for l in raw.splitlines() if l.strip()]
        status["distro_list"] = "; ".join(lines)
        status["distro"] = bool(lines)
    except Exception as exc:  # noqa: BLE001
        status["distro_err"] = str(exc)

    if status["distro"]:
        d = _wsl("docker --version", timeout=30)
        status["docker"] = bool(d["ok"] and "Docker version" in d["out"])
        if not status["docker"] and d["err"]:
            status["docker_err"] = d["err"][:200]

        r = _wsl(f"test -d {vulhub_dir} && echo yes", timeout=20)
        status["vulhub_repo"] = bool(r["ok"] and "yes" in r["out"])
    return status


def cmd_check(vulhub_dir: str) -> int:
    st = check_env(vulhub_dir)
    print(json.dumps(st, ensure_ascii=False, indent=2))
    if not (st["wsl_exe"] and st["distro"]):
        _print_install_guide()
        return EXIT_ENV_MISSING
    if not st["docker"]:
        print("\n[待办] WSL2 已就绪，但 Docker 不可用。请在发行版内执行：")
        print("  curl -fsSL https://get.docker.com | sh && sudo service docker start")
        return EXIT_ENV_MISSING
    if not st["vulhub_repo"]:
        print(f"\n[待办] 未找到 vulhub 仓库（{vulhub_dir}）。请在发行版内执行：")
        print(f"  git clone --depth 1 https://github.com/vulhub/vulhub.git {vulhub_dir}")
        return EXIT_ENV_MISSING
    print("\n[OK] 环境就绪：WSL2 + Docker + vulhub 仓库全部可用。")
    return 0


# ---------------------------------------------------------------------------
# 靶场生命周期
# ---------------------------------------------------------------------------

def cmd_list(vulhub_dir: str) -> int:
    r = _wsl(
        f"cd {vulhub_dir} 2>/dev/null && "
        "find . -maxdepth 2 -name 'docker-compose.yml' -o -maxdepth 2 -name 'docker-compose.yaml' "
        "| sed 's|^\\./||; s|/docker-compose\\.ya\\?ml$||' | sort | head -200",
        timeout=40,
    )
    if not r["ok"]:
        print(f"[失败] 无法列出靶场：{r['err'] or r['out']}", file=sys.stderr)
        _print_install_guide()
        return EXIT_ENV_MISSING
    items = [l for l in r["out"].splitlines() if l.strip()]
    print(json.dumps({"count": len(items), "labs": items}, ensure_ascii=False, indent=2))
    return 0


def cmd_up(vulhub_dir: str, rel_path: str) -> int:
    """拉起一个靶场（后台）。已拉起时幂等返回 0。"""
    target = f"{vulhub_dir}/{rel_path.strip('/')}"
    chk = _wsl(f"test -f {target}/docker-compose.yml -o -f {target}/docker-compose.yaml && echo yes",
               timeout=20)
    if not (chk["ok"] and "yes" in chk["out"]):
        print(f"[失败] 靶场目录不存在或不含 compose 文件：{target}", file=sys.stderr)
        print("提示：用 --list 查看可用靶场名。", file=sys.stderr)
        return 1
    r = _wsl(f"cd {target} && docker compose up -d 2>&1 | tail -20", timeout=300)
    if not r["ok"]:
        print(f"[失败] 拉起失败：\n{r['out']}\n{r['err']}", file=sys.stderr)
        return 1
    print(f"[OK] 已拉起：{rel_path}\n{r['out']}")
    print("提示：用 --endpoints 查看端点（含映射端口）。")
    return 0


def cmd_down(vulhub_dir: str, rel_path: str) -> int:
    target = f"{vulhub_dir}/{rel_path.strip('/')}"
    r = _wsl(f"cd {target} && docker compose down -v 2>&1 | tail -10", timeout=180)
    if not r["ok"]:
        print(f"[失败] 停止失败：{r['err'] or r['out']}", file=sys.stderr)
        return 1
    print(f"[OK] 已停止：{rel_path}\n{r['out']}")
    return 0


def cmd_endpoints(vulhub_dir: str) -> int:
    """输出运行中的 vulhub 容器端点（供 T08 检出率矩阵消费）。

    端口取自 `docker ps` 的 Ports 列（形如 0.0.0.0:8080->8080/tcp），
    拼成 http://127.0.0.1:<host_port> —— WSL2 的端口在 Windows 侧可直连。
    """
    r = _wsl(
        "docker ps --format '{{.Names}}\t{{.Ports}}\t{{.Label \"com.docker.compose.project.working_dir\"}}'",
        timeout=40,
    )
    if not r["ok"]:
        print(json.dumps({"ok": False, "error": r["err"] or r["out"]}, ensure_ascii=False))
        return EXIT_ENV_MISSING

    eps: List[Dict[str, str]] = []
    for line in r["out"].splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        name, ports = parts[0], parts[1]
        workdir = parts[2] if len(parts) > 2 else ""
        # 只要 vulhub 相关容器（working_dir 含 vulhub）
        if "vulhub" not in workdir and "vulhub" not in name:
            continue
        for seg in ports.split(", "):
            if "->" not in seg:
                continue
            host_part, container_part = seg.split("->", 1)
            host_port = host_part.rsplit(":", 1)[-1].strip()
            cport = container_part.split("/")[0].strip()
            if not host_port.isdigit():
                continue
            lab = workdir.replace(f"{vulhub_dir}/", "").replace("\\", "/") if workdir else name
            eps.append({
                "lab": lab,
                "container": name,
                "url": f"http://127.0.0.1:{host_port}",
                "host_port": host_port,
                "container_port": cport,
            })
    print(json.dumps({"ok": True, "count": len(eps), "endpoints": eps},
                     ensure_ascii=False, indent=2))
    return 0


def cmd_status(vulhub_dir: str) -> int:
    st = check_env(vulhub_dir)
    out: Dict[str, Any] = {"env": st}
    if st["distro"] and st["docker"]:
        r = _wsl("docker ps --format '{{.Names}}' | grep -c vulhub || true", timeout=30)
        out["running_containers"] = r["out"].strip()
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if (st["wsl_exe"] and st["distro"] and st["docker"] and st["vulhub_repo"]) \
        else EXIT_ENV_MISSING


# ---------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="WSL2 + Vulhub 靶场环境脚本（T06）")
    ap.add_argument("--check", action="store_true", help="环境自检（WSL2/Docker/vulhub）")
    ap.add_argument("--list", action="store_true", help="列出本地可用靶场")
    ap.add_argument("--up", metavar="PATH", help="拉起靶场，如 struts2/s2-045")
    ap.add_argument("--down", metavar="PATH", help="停止靶场")
    ap.add_argument("--endpoints", action="store_true", help="输出运行中靶场端点 JSON")
    ap.add_argument("--status", action="store_true", help="环境+运行状态汇总")
    ap.add_argument("--vulhub-dir", default=os.environ.get("VULHUB_DIR", DEFAULT_VULHUB_DIR),
                    help=f"WSL 内 vulhub 仓库路径（默认 {DEFAULT_VULHUB_DIR}）")
    args = ap.parse_args(argv)

    vd = args.vulhub_dir
    if args.check:
        return cmd_check(vd)
    if args.list:
        return cmd_list(vd)
    if args.up:
        return cmd_up(vd, args.up)
    if args.down:
        return cmd_down(vd, args.down)
    if args.endpoints:
        return cmd_endpoints(vd)
    if args.status:
        return cmd_status(vd)

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
