# SPDX-License-Identifier: AGPL-3.0-or-later
# VULNCLAW CI/CD workflow 文件轻量校验。
#
# 校验点：
#   1. .github/workflows/scan.yml / regression.yml 可被 YAML 解析
#      （pyyaml 不可用时降级为正则粗校验：on: / jobs: / steps: / runs-on: 键存在）
#   2. workflow 中引用的 vulnclaw 子命令都真实存在于 src/vulnclaw/cli.py 的 add_parser 列表
#   3. 除 ${{ secrets.XXX }} 注入外，无硬编码凭据
from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_DIR = PROJECT_ROOT / ".github" / "workflows"
CLI_PATH = PROJECT_ROOT / "src" / "vulnclaw" / "cli.py"
# 校验全部 workflow（glob 自动纳入新增门禁文件：version-regression / mutation_fuzz /
# fastjson_log4shell / egress_ssrf_guard 等，避免新文件绕过 YAML/凭据/子命令校验）。
WORKFLOW_FILES = sorted(WORKFLOW_DIR.glob("*.yml"))

# 凭据键名（大小写不敏感）。前置 (?<![A-Za-z0-9_]) 防止误命中
# SCAN_API_KEY / SECRET_TARGET 这类环境变量名（它们前一个字符是下划线/字母）。
_CRED_KEY_RE = re.compile(
    r"(?im)(?<![A-Za-z0-9_])(api[_-]?key|apikey|access[_-]?token|auth(?:orization)?|"
    r"password|passwd|secret|token)\s*[:=]\s*(\S.*)?$"
)


def _workflow_texts():
    for path in WORKFLOW_FILES:
        assert path.is_file(), f"缺少 workflow 文件: {path}"
        yield path, path.read_text(encoding="utf-8")


def _cli_subcommands() -> set[str]:
    """正则提取 cli.py 中所有 add_parser 注册的子命令名（含 mcp/tools 嵌套）。"""
    src = CLI_PATH.read_text(encoding="utf-8")
    names = set(re.findall(r"add_parser\(\s*[\"']([a-z][a-z0-9-]*)[\"']", src))
    # main() 兼容转发白名单兜底（如 resume 等走旧 scan 风格转发的命令）
    for m in re.finditer(r"argv\[0\]\s+not in\s+\(([^)]*)\)", src):
        names.update(re.findall(r"[\"']([a-z][a-z0-9-]*)[\"']", m.group(1)))
    return names


def test_workflow_yaml_parseable_or_regex_fallback():
    """YAML 可解析（pyyaml 缺失时用正则粗校验关键键）。"""
    for path, text in _workflow_texts():
        try:
            import yaml
        except ImportError:
            yaml = None
        if yaml is None:
            for key in (r"(?m)^\s*on\s*:", r"(?m)^\s*jobs\s*:", r"(?m)^\s*steps\s*:"):
                assert re.search(key, text), f"{path.name}: 缺少关键键 {key.strip()}"
            assert re.search(r"(?m)^\s*runs-on\s*:", text), f"{path.name}: 缺少 runs-on:"
            continue
        data = yaml.safe_load(text)
        assert isinstance(data, dict), f"{path.name}: 不是合法 YAML 映射"
        # PyYAML(YAML 1.1) 会把裸键 on 解析为布尔 True，需兼容两种键
        assert ("on" in data) or (True in data), f"{path.name}: 缺少顶层 on: 触发器"
        assert "jobs" in data, f"{path.name}: 缺少顶层 jobs:"
        assert data["jobs"], f"{path.name}: jobs 为空"
        for job_name, job in data["jobs"].items():
            assert isinstance(job, dict) and "steps" in job, f"{path.name}: job {job_name} 缺少 steps:"
            steps = job["steps"]
            assert isinstance(steps, list) and steps, f"{path.name}: job {job_name} 的 steps 为空"
            for step in steps:
                assert ("uses" in step) or ("run" in step), (
                    f"{path.name}: job {job_name} 有既无 uses 也无 run 的 step"
                )


def test_workflow_referenced_subcommands_exist():
    """workflow 引用的 vulnclaw 子命令必须存在于 cli.py。"""
    known = _cli_subcommands()
    assert {"scan", "archive", "verify"} <= known, f"cli.py 子命令提取异常: {sorted(known)}"
    for path, text in _workflow_texts():
        referenced = set(re.findall(r"\bvulnclaw\s+([a-z][a-z0-9-]*)", text))
        missing = referenced - known
        assert not missing, f"{path.name}: 引用了 cli.py 中不存在的子命令 {sorted(missing)}"


def test_no_hardcoded_credentials_outside_secrets():
    """除 ${{ secrets.XXX }} 注入外，不允许出现硬编码凭据。"""
    for path, text in _workflow_texts():
        for lineno, line in enumerate(text.splitlines(), 1):
            m = _CRED_KEY_RE.search(line)
            if not m:
                continue
            value = (m.group(2) or "").strip().strip("'\"")
            # 允许：空值、YAML 空值、${{ secrets.X }} / $ 变量注入
            if not value or value.lower() in ("null", "none", "~") or "$" in value:
                continue
            raise AssertionError(f"{path.name}:{lineno} 疑似硬编码凭据: {line.strip()}")
