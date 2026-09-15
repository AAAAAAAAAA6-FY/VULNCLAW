"""Offline preflight for a real Docker/Vulhub run.

The command only checks local prerequisites and never pulls images, starts
containers, contacts a target, or reports scan findings.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def _docker_ready() -> tuple[bool, str]:
    docker = shutil.which("docker")
    if not docker:
        return False, "docker executable not found"
    try:
        result = subprocess.run(
            [docker, "info", "--format", "{{.ServerVersion}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"docker info failed: {exc}"
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        return False, f"Docker daemon unavailable: {detail or 'unknown error'}"
    return True, f"Docker daemon available (server {result.stdout.strip() or 'unknown'})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", default="scripts/lab_profiles/vulhub.yaml")
    parser.add_argument("--compose-file", type=Path)
    parser.add_argument("--target-url", default="http://127.0.0.1:8080")
    args = parser.parse_args()

    profile = Path(args.profile)
    checks = [(profile.is_file(), f"profile: {profile}")]
    compose = args.compose_file
    if compose is not None:
        checks.append((compose.is_file(), f"compose file: {compose}"))
    docker_ok, docker_message = _docker_ready()
    checks.append((docker_ok, docker_message))

    print("Vulhub preflight (no network, no containers started)")
    failed = False
    for ok, message in checks:
        print(f"[{'ok' if ok else 'blocked'}] {message}")
        failed |= not ok
    print(f"[info] target URL is operator-supplied: {args.target_url}")
    if failed:
        print("Preflight blocked: resolve local prerequisites before a real lab run.", file=sys.stderr)
        return 2
    print("Preflight passed. Start the operator-selected compose project explicitly.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
