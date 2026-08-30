#!/usr/bin/env python3
"""
一键代码审计执行脚本（带错误处理和降级）
执行方式：python scripts/run_code_audit.py
"""

import os
import sys
import subprocess
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
os.chdir(PROJECT_ROOT)

REPO_URL = "https://github.com/Anon-Artist/vulnpy.git"
REPO_DIR = PROJECT_ROOT / "_runtime_cache" / "target_repos" / "vulnpy"

def run_cmd(cmd, description=""):
    print(f"\n[+] {description or cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=False)
    return result.returncode == 0

def main():
    print("=" * 60)
    print("  🔍 代码审计实战验证脚本")
    print("=" * 60)
    
    # 1. 安装依赖
    print("\n[1/4] 安装依赖...")
    run_cmd("pip install semgrep pip-audit", "安装 Semgrep 和 pip-audit")
    
    # 2. 克隆仓库
    print("\n[2/4] 克隆测试仓库...")
    if REPO_DIR.exists():
        print(f"   ⚠️ 目录已存在: {REPO_DIR}，跳过 clone")
    else:
        REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
        run_cmd(f"git clone {REPO_URL} {REPO_DIR}", "克隆 vulnpy")
    
    # 3. 运行代码审计（跳过 AI 审计，只跑 Semgrep，避免 LLM 超时）
    print("\n[3/4] 运行代码审计扫描（仅 Semgrep，跳过 AI）...")
    cmd = f'python scan.py --code "{REPO_DIR}" --no-cookie --skip-ai-audit 2>&1'
    # 注意：如果 --skip-ai-audit 未实现，可以临时修改 code/ai_auditor.py 直接返回空结果，或用环境变量控制
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout)
    if result.stderr:
        print("[stderr]", result.stderr[:500])
    
    # 4. 查找报告
    print("\n[4/4] 查找生成报告...")
    report_files = list((PROJECT_ROOT / "_runtime_cache" / "reports").glob("report_*.json"))
    if report_files:
        latest = max(report_files, key=lambda f: f.stat().st_mtime)
        print(f"   ✅ 最新报告: {latest}")
        print(f"   📄 大小: {latest.stat().st_size} bytes")
    else:
        print("   ⚠️ 未找到报告文件，扫描可能未成功")
    
    print("\n" + "=" * 60)
    print("  ✅ 代码审计执行完成")
    print("=" * 60)

if __name__ == "__main__":
    main()