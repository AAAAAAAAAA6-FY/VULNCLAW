#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
一键合并脚本 - 将 68 个文件安全合并为 48 个
用法: python merge_tool.py
"""

import os
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
import sys
sys.dont_write_bytecode = True
import shutil
import re
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.absolute()
BACKUP_DIR = PROJECT_ROOT / "_merge_backup"
BACKUP_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
BACKUP_PATH = BACKUP_DIR / BACKUP_TIMESTAMP

# ============================================================
# 合并配置
# ============================================================

# 格式: (目标文件, [源文件列表], 模式)
# 模式: 'append' 表示追加到目标文件末尾，'create' 表示创建新文件
MERGE_ACTIONS = [
    # 1. AI 核心合并
    {
        "target": "ai/core.py",
        "sources": [
            "ai/adaptive_ml.py",
            "ai/local_llm.py",
            "ai/model_router.py",
            "ai/rule_engine.py",
            "ai/memory.py",
            "ai/clue_engine.py",
            "ai/context_manager.py",
        ],
        "mode": "append",
    },
    # 2. 删除重复文件
    {
        "target": None,  # 表示仅删除
        "sources": ["core/exploit_plus.py"],
        "mode": "delete",
    },
    # 3. 合并 misc_engines 到 input_engines
    {
        "target": "engines/input_engines.py",
        "sources": ["engines/misc_engines.py"],
        "mode": "append",
    },
    # 4. 新建 modules/recon.py (合并侦察模块)
    {
        "target": "modules/recon.py",
        "sources": [
            "modules/alive.py",
            "modules/subdomain.py",
            "modules/port_scan.py",
            "modules/endpoint_collector.py",
        ],
        "mode": "create",
    },
    # 5. 新建 modules/collectors.py (合并收集/解析模块)
    {
        "target": "modules/collectors.py",
        "sources": [
            "modules/js_deep_analyzer.py",
            "modules/burp_plugin_emulator.py",
            "modules/browser_collector.py",
            "modules/api_spec_parser.py",
            "modules/session_scanner.py",
        ],
        "mode": "create",
    },
    # 6. 追加工具/漏洞扫描到 modules/vuln_scanner.py
    {
        "target": "modules/vuln_scanner.py",
        "sources": [
            "modules/tools.py",
            "modules/idor_scanner.py",
            "modules/default_cred_checker.py",
            "modules/advanced_ai_modules.py",
        ],
        "mode": "append",
    },
]

# 需要删除的旧文件（除了上面单独删除的，这里列出其他将被替换的）
DELETE_FILES = [
    "ai/adaptive_ml.py",
    "ai/local_llm.py",
    "ai/model_router.py",
    "ai/rule_engine.py",
    "ai/memory.py",
    "ai/clue_engine.py",
    "ai/context_manager.py",
    "engines/misc_engines.py",
    "modules/alive.py",
    "modules/subdomain.py",
    "modules/port_scan.py",
    "modules/endpoint_collector.py",
    "modules/js_deep_analyzer.py",
    "modules/burp_plugin_emulator.py",
    "modules/browser_collector.py",
    "modules/api_spec_parser.py",
    "modules/session_scanner.py",
    "modules/tools.py",
    "modules/idor_scanner.py",
    "modules/default_cred_checker.py",
    "modules/advanced_ai_modules.py",
]

# 导入路径替换映射 (旧模块名 -> 新模块名)
IMPORT_REPLACEMENTS = [
    (r'from modules\.tools import', 'from vulnclaw.modules.vuln_scanner import'),
    (r'from modules\.idor_scanner import', 'from vulnclaw.modules.vuln_scanner import'),
    (r'from modules\.default_cred_checker import', 'from vulnclaw.modules.vuln_scanner import'),
    (r'from modules\.advanced_ai_modules import', 'from vulnclaw.modules.vuln_scanner import'),
    (r'from modules\.alive import', 'from vulnclaw.modules.recon import'),
    (r'from modules\.subdomain import', 'from vulnclaw.modules.recon import'),
    (r'from modules\.port_scan import', 'from vulnclaw.modules.recon import'),
    (r'from modules\.endpoint_collector import', 'from vulnclaw.modules.recon import'),
    (r'from modules\.js_deep_analyzer import', 'from vulnclaw.modules.collectors import'),
    (r'from modules\.burp_plugin_emulator import', 'from vulnclaw.modules.collectors import'),
    (r'from modules\.browser_collector import', 'from vulnclaw.modules.collectors import'),
    (r'from modules\.api_spec_parser import', 'from vulnclaw.modules.collectors import'),
    (r'from modules\.session_scanner import', 'from vulnclaw.modules.collectors import'),
]

# ============================================================
# 工具函数
# ============================================================

def backup_file(path: Path):
    """备份单个文件到备份目录"""
    if not path.exists():
        return
    rel = path.relative_to(PROJECT_ROOT)
    dest = BACKUP_PATH / rel
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest)
    print(f"   📦 备份: {rel}")

def backup_all_targets():
    """备份所有将要修改或删除的文件"""
    all_paths = set()
    for action in MERGE_ACTIONS:
        if action["target"]:
            all_paths.add(PROJECT_ROOT / action["target"])
        for src in action["sources"]:
            all_paths.add(PROJECT_ROOT / src)
    for f in DELETE_FILES:
        all_paths.add(PROJECT_ROOT / f)
    # 额外备份可能被覆盖的目标文件（如 vuln_scanner.py）
    for path in all_paths:
        if path.exists():
            backup_file(path)

def read_file(path: Path) -> str:
    """读取文件内容，忽略编码错误"""
    try:
        return path.read_text(encoding='utf-8')
    except UnicodeDecodeError:
        return path.read_text(encoding='gbk', errors='ignore')

def write_file(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding='utf-8')

def append_to_file(target: Path, source_files: list):
    """将多个源文件的内容追加到目标文件末尾（添加分隔注释）"""
    if not target.exists():
        print(f"   ⚠️ 目标文件不存在，将创建: {target}")
        content = ""
    else:
        content = read_file(target)
    for src in source_files:
        src_path = PROJECT_ROOT / src
        if not src_path.exists():
            print(f"   ⚠️ 源文件不存在，跳过: {src}")
            continue
        print(f"   ➕ 追加: {src} -> {target}")
        src_content = read_file(src_path)
        # 去掉源文件开头的 shebang 和 coding 注释（如果有）
        lines = src_content.splitlines()
        new_lines = []
        skip = True
        for line in lines:
            if skip and (line.startswith('#!') or line.startswith('# -*- coding:')):
                continue
            skip = False
            new_lines.append(line)
        src_content = '\n'.join(new_lines)
        # 添加分隔标记
        content += f"\n\n# ============================================================\n"
        content += f"# 合并自: {src}\n"
        content += f"# ============================================================\n\n"
        content += src_content
    write_file(target, content)
    print(f"   ✅ 合并完成: {target}")

def create_file(target: Path, source_files: list):
    """创建新文件，合并多个源文件的内容"""
    content = ""
    for src in source_files:
        src_path = PROJECT_ROOT / src
        if not src_path.exists():
            print(f"   ⚠️ 源文件不存在，跳过: {src}")
            continue
        print(f"   ➕ 合并: {src} -> {target}")
        src_content = read_file(src_path)
        # 去除 shebang 和 coding 行
        lines = src_content.splitlines()
        new_lines = []
        skip = True
        for line in lines:
            if skip and (line.startswith('#!') or line.startswith('# -*- coding:')):
                continue
            skip = False
            new_lines.append(line)
        src_content = '\n'.join(new_lines)
        content += f"# ============================================================\n"
        content += f"# 合并自: {src}\n"
        content += f"# ============================================================\n\n"
        content += src_content
        content += "\n\n"
    write_file(target, content)
    print(f"   ✅ 创建完成: {target}")

def update_imports_in_file(file_path: Path):
    """在单个文件中替换导入语句"""
    if not file_path.exists():
        return
    content = read_file(file_path)
    changed = False
    for old, new in IMPORT_REPLACEMENTS:
        new_content = re.sub(old, new, content)
        if new_content != content:
            content = new_content
            changed = True
    if changed:
        write_file(file_path, content)
        print(f"   🔄 更新导入: {file_path.relative_to(PROJECT_ROOT)}")

def update_all_imports():
    """遍历所有 Python 文件更新导入"""
    print("\n🔄 更新所有 Python 文件中的导入语句...")
    for py_file in PROJECT_ROOT.rglob("*.py"):
        # 跳过备份目录
        if BACKUP_DIR in py_file.parents:
            continue
        # 跳过可能被删除的旧文件（但仍在备份中）
        rel = py_file.relative_to(PROJECT_ROOT)
        if str(rel) in DELETE_FILES:
            continue
        update_imports_in_file(py_file)

def delete_old_files():
    """删除旧文件"""
    print("\n🗑️ 删除旧文件...")
    for f in DELETE_FILES:
        path = PROJECT_ROOT / f
        if path.exists():
            path.unlink()
            print(f"   ✅ 删除: {f}")
        else:
            print(f"   ⏭️ 已不存在: {f}")

# ============================================================
# 主函数
# ============================================================

def main():
    print("=" * 70)
    print("  🔧 一键合并脚本")
    print("=" * 70)
    print(f"项目根目录: {PROJECT_ROOT}")
    print(f"备份目录: {BACKUP_PATH}")
    print()

    # 1. 创建备份目录
    BACKUP_PATH.mkdir(parents=True, exist_ok=True)

    # 2. 备份所有受影响文件
    print("📦 备份受影响文件...")
    backup_all_targets()

    # 3. 执行合并操作
    print("\n📂 执行合并操作...")
    for action in MERGE_ACTIONS:
        target = action["target"]
        sources = action["sources"]
        mode = action["mode"]
        if mode == "delete":
            # 单独删除
            for src in sources:
                path = PROJECT_ROOT / src
                if path.exists():
                    # 已备份，直接删除
                    path.unlink()
                    print(f"   ✅ 删除: {src}")
                else:
                    print(f"   ⏭️ 已不存在: {src}")
        elif mode == "append":
            target_path = PROJECT_ROOT / target
            # 确保目标存在，如果不存在则先创建空文件
            if not target_path.exists():
                target_path.parent.mkdir(parents=True, exist_ok=True)
                target_path.write_text("", encoding='utf-8')
            append_to_file(target_path, sources)
        elif mode == "create":
            target_path = PROJECT_ROOT / target
            create_file(target_path, sources)
        else:
            print(f"   ❌ 未知模式: {mode}")

    # 4. 删除所有旧文件
    delete_old_files()

    # 5. 更新导入语句
    update_all_imports()

    # 6. 更新 __init__.py 文件（简单的补充，实际可能需要手动调整）
    # 这里我们尝试更新 modules/__init__.py 和 ai/__init__.py
    print("\n📝 更新模块 __init__.py ...")
    # 对于 ai/__init__.py，我们添加新导出（但原有导出保留）
    ai_init = PROJECT_ROOT / "ai/__init__.py"
    if ai_init.exists():
        content = read_file(ai_init)
        # 检查是否已包含新导出，如果没有则追加
        new_exports = """
# 合并后新增导出
from .core import (
    AdaptiveML, get_adaptive_ml,
    LocalLLM, get_local_llm,
    ModelRouter, get_model_router, TASK_MODEL_MAPPING,
    AgentRuleEngine, get_rule_engine,
    VectorMemory, get_memory,
    ClueEngine, process_url_for_clues, get_clue_engine,
    ScanBrief, ContextManager,
)
"""
        if "AdaptiveML" not in content:
            content += new_exports
            write_file(ai_init, content)
            print("   ✅ 更新 ai/__init__.py")
        else:
            print("   ℹ️ ai/__init__.py 已包含新导出")

    # 对 modules/__init__.py 做类似处理（但可能没有，我们创建或更新）
    modules_init = PROJECT_ROOT / "modules/__init__.py"
    if modules_init.exists():
        content = read_file(modules_init)
        # 我们添加从 recon, collectors, vuln_scanner 的导入
        new_imports = """
# 合并后新增导出
from .recon import alive_scan, port_scan, get_subdomains, get_subdomains_async, EndpointCollector
from .collectors import (
    JSDeepAnalyzer, analyze_js_deep,
    run_all_burp_plugins_checks,
    BrowserAIAgent, create_browser_agent, HAS_PLAYWRIGHT,
    APISpecParser,
    scan_session_security,
)
from .vuln_scanner import (
    verify_with_ai, batch_verify_with_ai, verify_nuclei_with_ai_async,
    is_waf_block, extract_params_from_html, test_post_json,
    get_vuln_llm_client, safe_extract_json, normalize_response,
    run_arjun, run_nuclei_async, run_ffuf_async,
    get_interactsh_domain_async, get_interactsh_poll,
    IDORScanner, scan_idor, scan_vertical_privilege,
    check_default_credentials,
    scan_llm_injection, scan_spring_actuator, scan_oauth_hijack,
    scan_graphql_introspection, scan_dns_rebinding,
    run_all_advanced_ai_checks,
)
"""
        if "recon" not in content:
            content += new_imports
            write_file(modules_init, content)
            print("   ✅ 更新 modules/__init__.py")
        else:
            print("   ℹ️ modules/__init__.py 已包含新导出")
    else:
        # 创建 modules/__init__.py
        content = "# modules/__init__.py\n" + new_imports
        write_file(modules_init, content)
        print("   ✅ 创建 modules/__init__.py")

    # 7. 检查是否还有遗漏的 import 替换（针对 core/scanner.py 中加载引擎的修改）
    # 我们手动更新 core/scanner.py 中的 _load_engines 函数，将 misc_engines 改为 input_engines
    scanner_py = PROJECT_ROOT / "core/scanner.py"
    if scanner_py.exists():
        content = read_file(scanner_py)
        # 替换 from vulnclaw.engines.input_engines import ... 为 from vulnclaw.engines.input_engines import ...
        old_import = "from vulnclaw.engines.input_engines import BusinessLogicEngine, InfoLeakEngine"
        new_import = "from vulnclaw.engines.input_engines import BusinessLogicEngine, InfoLeakEngine"
        if old_import in content:
            content = content.replace(old_import, new_import)
            write_file(scanner_py, content)
            print("   ✅ 更新 core/scanner.py 中的引擎导入")
        else:
            # 可能使用通配符导入，我们替换整个行
            pattern = r'from engines\.misc_engines import (.*)'
            def repl(m):
                return f"from vulnclaw.engines.input_engines import {m.group(1)}"
            new_content, n = re.subn(pattern, repl, content)
            if n:
                write_file(scanner_py, new_content)
                print("   ✅ 更新 core/scanner.py 中的引擎导入")

    # 8. 处理 core/exploit_verify.py 的引用（已删除 exploit_plus.py，但引用可能还在）
    # 我们已经在导入替换中处理了 from vulnclaw.core.exploit_plus，但如果没有，可以单独处理
    print("\n🔍 检查 core/exploit_plus 引用...")
    for py_file in PROJECT_ROOT.rglob("*.py"):
        if BACKUP_DIR in py_file.parents:
            continue
        content = read_file(py_file)
        if "from vulnclaw.core.exploit_verify import" in content:
            new_content = content.replace("from vulnclaw.core.exploit_verify import", "from vulnclaw.core.exploit_verify import")
            write_file(py_file, new_content)
            print(f"   ✅ 更新 {py_file.relative_to(PROJECT_ROOT)}")

    print("\n" + "=" * 70)
    print("  ✅ 合并完成！")
    print("=" * 70)
    print(f"备份已保存至: {BACKUP_PATH}")
    print("如果一切正常，您可以删除该备份目录。")
    print("如有问题，可从备份恢复。")
    print("请运行 'python -m compileall .' 检查语法错误。")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断，部分操作可能未完成。请检查项目状态。")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ 发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)