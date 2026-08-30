#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
入口脚本自动触发测试：测试 Skill pentest_platform_entry_bootstrap 是否自动注入 3 层保护。

测试内容：
  1. 打印 sys.dont_write_bytecode（应为 True）
  2. 打印所有 3 层保护的环境变量
  3. 打印项目路径解析（PROJECT_ROOT 启发式是否正确识别 scripts/ -> 上级）
  4. 尝试 import 一个项目模块（core.settings）证明 sys.path 插入成功
  5. 打印 "入口脚本自动触发测试 PASS" 表示业务部分也跑了
"""

# ============================================================
# 3-Layer Entry Header (from Skill: pentest_platform_entry_bootstrap)
# 必须放在所有真实业务 import 之前。
# ============================================================
import os
import sys

# ============================================================
# 1. Block bytecode cache (covers py_compile + child processes too)
# ============================================================
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
os.environ.setdefault("PYTHONPYCACHEPREFIX", "")
sys.dont_write_bytecode = True

# ============================================================
# 2. Redirect Nuclei / uncover HOME into _runtime_cache/tools/
#    Prevents project-root .config/ from reappearing.
# ============================================================
_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(_HERE) in {"scripts","tests","dashboard","thirdparty","distributed","_runtime_cache","code","deepsec","dag","engines","ai","core","modules","config"}:
    _PROJECT_ROOT = os.path.dirname(_HERE)
else:
    _PROJECT_ROOT = _HERE
_RT = os.path.join(_PROJECT_ROOT, "_runtime_cache", "tools")
for _sub in ("", "nuclei", "uncover"):
    try:
        os.makedirs(os.path.join(_RT, _sub), exist_ok=True)
    except Exception:
        pass
for _k, _v in (
    ("HOME",               _RT),
    ("USERPROFILE",        _RT),
    ("NUCLEI_CONFIG_DIR",  os.path.join(_RT, "nuclei")),
    ("UNCOVER_CONFIG_DIR", os.path.join(_RT, "uncover")),
):
    os.environ[_k] = _v

# ============================================================
# 3. Windows stdout/stderr UTF-8 + disable tqdm bars
# ============================================================
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("TQDM_DISABLE", "1")
if sys.platform.startswith("win"):
    import io as _io
    for _name in ("stdout", "stderr"):
        _stream = getattr(sys, _name)
        try:
            if hasattr(_stream, "reconfigure"):
                _stream.reconfigure(encoding="utf-8", errors="replace")
                continue
        except Exception:
            pass
        if hasattr(_stream, "buffer"):
            try:
                setattr(sys, _name,
                        _io.TextIOWrapper(_stream.buffer, encoding="utf-8",
                                          errors="replace", line_buffering=True))
            except Exception:
                pass
del _HERE, _PROJECT_ROOT, _RT, _sub, _k, _v, _name, _stream

# ===== REAL business imports start BELOW this line =====
import time
from pathlib import Path

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def run_checks() -> int:
    print("\n" + "=" * 60)
    print("  Skill Auto-Trigger Test: scripts/entry_trigger_test.py")
    print("=" * 60)

    results: list[tuple[str, bool, str]] = []

    # Layer 1 — bytecode block
    v = sys.dont_write_bytecode
    results.append(("sys.dont_write_bytecode == True", v, str(v)))
    v2 = os.environ.get("PYTHONDONTWRITEBYTECODE") == "1"
    results.append(("PYTHONDONTWRITEBYTECODE=1", v2, os.environ.get("PYTHONDONTWRITEBYTECODE", "<unset>")))

    # Layer 2 — Nuclei HOME redirect
    project_root_abs = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    expected_tools = os.path.join(project_root_abs, "_runtime_cache", "tools")
    for k in ("HOME", "USERPROFILE", "NUCLEI_CONFIG_DIR", "UNCOVER_CONFIG_DIR"):
        val = os.environ.get(k, "")
        ok = val.startswith(expected_tools) if k in {"HOME", "USERPROFILE"} else expected_tools in val
        results.append((f"{k} points into _runtime_cache/tools", ok, val or "<unset>"))
    nuclei_dir = os.environ.get("NUCLEI_CONFIG_DIR", "")
    results.append(("NUCLEI_CONFIG_DIR  exists on disk", nuclei_dir and os.path.isdir(nuclei_dir), nuclei_dir))

    # Layer 3 — UTF-8 / tqdm disable
    results.append(("PYTHONIOENCODING=utf-8",
                    os.environ.get("PYTHONIOENCODING", "").lower().startswith("utf"),
                    os.environ.get("PYTHONIOENCODING", "<unset>")))
    results.append(("TQDM_DISABLE=1", os.environ.get("TQDM_DISABLE") == "1",
                    os.environ.get("TQDM_DISABLE", "<unset>")))

    # Path heuristic sanity check
    results.append(("PROJECT_ROOT heuristic: scripts/ -> one-up -> has scan.py",
                    os.path.isfile(os.path.join(project_root_abs, "scan.py")),
                    project_root_abs))

    # Project module import
    try:
        from core.settings import PROJECT_CACHE_DIR  # noqa: F401
        results.append(("from core.settings import PROJECT_CACHE_DIR", True, PROJECT_CACHE_DIR))
    except Exception as exc:  # pragma: no cover
        results.append(("from core.settings import PROJECT_CACHE_DIR", False, repr(exc)))

    # Print report
    all_pass = True
    print()
    print(f"{'#':<3} {'CHECK':<55} {'ACTUAL':<25}")
    print("-" * 85)
    for i, (name, ok, actual) in enumerate(results, 1):
        mark = "✅" if ok else "❌"
        if not ok:
            all_pass = False
        print(f"{i:<3} {mark} {name:<52} {actual:<25}")

    print()
    print("VERDICT:", "ALL 3-LAYER GUARDS PASS ✅" if all_pass else "SOME GUARDS FAILED ❌")
    print()
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(run_checks())
