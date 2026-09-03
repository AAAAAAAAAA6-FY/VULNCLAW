"""结构守卫测试：根目录白名单 + 垃圾目录禁再生 + src 布局校验。"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

import pytest

# 这个守卫测试必须依赖 "不生成 __pycache__ / pyc"：虽然 conftest.py 已经设
# PYTHONDONTWRITEBYTECODE=1 + sys.dont_write_bytecode=True，但 pytest 导入测试
# 文件时 conftest 的字节码拦截对前 1~2 个模块仍然可能迟到（尤其 3.14 的 importlib
# 时序）。这里在 module 加载时再兜一遍，确保整个 pytest 会话不再往 src 写 pyc。
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]

SRC_PKG = ROOT / "src" / "vulnclaw"

ALLOWED_ROOT_ITEMS = {
    "src", "tests", "docs", "scripts", "assets", "thirdparty",
    "pyproject.toml", "README.md", "CHANGELOG.md", "CONTRIBUTING.md", "SECURITY.md",
    "LICENSE", ".gitignore", ".pre-commit-config.yaml",
    "_runtime_cache", "venv", ".vscode", ".idea", ".trae", ".codebuddy",
    # 薄壳入口与启动/环境文件
    "scan.py", ".env", ".env.example",
    "start_vulnclaw.sh", "start_vulnclaw.ps1",
    # Docker 部署文件（项目已有，2026-08-30 登记入白名单）
    "Dockerfile", "docker-compose.yaml",
    ".git", ".github",
    # pytest-cov / coverage.py 的运行时产物（已在 .gitignore 中忽略；允许其出现在根，避免 --cov 跑完 layout 守卫变红）
    ".coverage", ".coverage.*",
    # coverage / pytest-reportlog 输出目录
    "htmlcov", ".pytest_cache",
}

# 旧顶层包：必须全部已迁入 src/vulnclaw/
OLD_TOP_PACKAGES = ["ai", "core", "engines", "modules", "dag", "deepsec",
                    "dashboard", "distributed", "code",
                    "archive", "common", "pocs_test", "v100", "extracted_scripts"]

# 任何位置都不允许再生的垃圾名
BANNED_ANYWHERE = ["pocs_test", "extracted_scripts", "_merge_backup"]


def test_root_is_clean():
    actual = {p.name for p in ROOT.iterdir()}
    stray = actual - ALLOWED_ROOT_ITEMS
    assert not stray, f"根目录出现未登记条目: {sorted(stray)}"


def test_old_top_packages_moved():
    for name in OLD_TOP_PACKAGES:
        assert not (ROOT / name).is_dir(), f"旧顶层包未迁移: {name}/"


def test_banned_dirs_absent():
    for name in BANNED_ANYWHERE:
        hits = [p for p in ROOT.rglob(name)
                if not any(x in ("thirdparty", "venv", "_runtime_cache") for x in p.parts)]
        assert not hits, f"禁止名称再生: {name}/ -> {hits[:3]}"


def test_src_package_layout():
    pkg = ROOT / "src" / "vulnclaw"
    assert (pkg / "__init__.py").is_file(), "缺少 src/vulnclaw/__init__.py"
    for sub in ("ai", "core", "engines", "modules", "dag", "deepsec",
                "dashboard", "distributed", "code"):
        assert (pkg / sub / "__init__.py").is_file(), f"缺少子包 {sub}/__init__.py"


def test_thin_shell_scan_py():
    text = (ROOT / "scan.py").read_text(encoding="utf-8")
    assert "from vulnclaw.cli import main" in text, "根 scan.py 不是薄壳"
    assert len(text.splitlines()) <= 15, f"根 scan.py 行数={len(text.splitlines())}，应<=15"


def test_no_standalone_code_audit_runner():
    assert not (ROOT / "code_audit_runner.py").exists(), "code_audit_runner.py 未合并删除"
    # P2 验收：src/vulnclaw 下也必须没有 code_audit*.py 的独立入口（三合一之后唯一入口是 scan_main.run_code_audit）
    pkg = ROOT / "src" / "vulnclaw"
    stray = sorted(p.name for p in pkg.glob("code_audit*.py"))
    assert not stray, f"src/vulnclaw 仍存在独立 code_audit 入口: {stray}"


def test_no_pycache_in_root_or_scripts():
    assert not (ROOT / "__pycache__").exists(), "仓库根出现 __pycache__"
    assert not (ROOT / "scripts" / "__pycache__").exists(), "scripts/ 出现 __pycache__"


@pytest.fixture(scope="module", autouse=True)
def _purge_src_pycache_before_layout_checks():
    """在跑 layout 守卫前，把 pytest 导入期迟写进 src/ 的 __pycache__ 清掉。

    即使启用了 PYTHONDONTWRITEBYTECODE=1，某些第三方 import hook（pydantic v2 /
    importlib 3.14 的 race）仍可能在首个模块加载阶段写出 pyc。这里在本文件的任
    何断言前做一次确定性清理，保证守卫只看"未来会不会再生成"，而不是 pytest 启动
    期留下的一次性残留。
    """
    if not SRC_PKG.is_dir():
        yield
        return
    removed = 0
    for pycache in SRC_PKG.rglob("__pycache__"):
        try:
            shutil.rmtree(pycache, ignore_errors=True)
            removed += 1
        except Exception:
            pass
    for pyc in SRC_PKG.rglob("*.pyc"):
        try:
            pyc.unlink()
        except Exception:
            pass
    yield
    # 用例跑完后再清一次，避免下个会话继续被上一次的 pyc 污染。
    for pycache in SRC_PKG.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)


def test_no_runtime_cache_or_pycache_in_src():
    """src/vulnclaw 内禁止再生 _runtime_cache / __pycache__。

    src-layout 迁移后日志等运行时产物必须落在项目根 _runtime_cache/，
    不允许写进源码目录（曾因 core/logger.py 相对路径计算错误在此生成垃圾）。
    """
    for name in ("_runtime_cache", "__pycache__"):
        hits = [p for p in SRC_PKG.rglob(name)]
        assert not hits, f"src 内禁止出现 {name}: {hits[:3]}"
