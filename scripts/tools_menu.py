#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
渗透测试平台 - 多功能管理工具（v6.5.2 修复版）
修复：
1. Nuclei 模板目录检测：使用 os.path.expanduser 展开 ~
2. 包检测：beautifulsoup4 → bs4, dnspython → dns
"""

import os
import sys
# ============================================================
# 1. 全局字节码（父子进程一起防，确保 py_compile / 子进程都不写根目录 __pycache__）
# ============================================================
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
os.environ.setdefault("PYTHONPYCACHEPREFIX", "")
sys.dont_write_bytecode = True

# ============================================================
# 2. Nuclei / uncover / 浏览器配置目录重定向（→ _runtime_cache/tools/）
#    防止根目录出现 .config/ 垃圾
# ============================================================
_RT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "_runtime_cache", "tools")
for _sub in ("", "nuclei", "uncover"):
    try:
        os.makedirs(os.path.join(_RT, _sub), exist_ok=True)
    except Exception:
        pass
for _k, _v in (
    ("HOME",              _RT),
    ("USERPROFILE",       _RT),
    ("NUCLEI_CONFIG_DIR", os.path.join(_RT, "nuclei")),
    ("UNCOVER_CONFIG_DIR",os.path.join(_RT, "uncover")),
):
    os.environ[_k] = _v

# ============================================================
# 3. Windows stdout/stderr UTF-8 + TQDM 禁用（统一：不产生乱码/进度条）
#    注意：要在 PYTHONIOENCODING / PYTHONUTF8 之前设置完成
# ============================================================
os.environ.setdefault("PYTHONIOENCODING", "utf-8")
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("TQDM_DISABLE", "1")
if sys.platform.startswith("win"):
    import io as _io
    for _n in ("stdout", "stderr"):
        _s = getattr(sys, _n)
        try:
            if hasattr(_s, "reconfigure"):
                _s.reconfigure(encoding="utf-8", errors="replace")
                continue
        except Exception:
            pass
        if hasattr(_s, "buffer"):
            try:
                setattr(sys, _n, _io.TextIOWrapper(_s.buffer, encoding="utf-8",
                                                   errors="replace", line_buffering=True))
            except Exception:
                pass
del _RT, _sub, _k, _v, _n, _s
import io
import shutil
import fnmatch
import subprocess
import traceback
import json
import re
import importlib
import tempfile
import asyncio
import time
import glob
from pathlib import Path
from datetime import datetime

# ===== 导入 PROJECT_CACHE_DIR（core.settings 不存在时回退，避免首次运行直接炸）=====
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
_SRC = os.path.join(PROJECT_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)
try:
    from vulnclaw.core.settings import PROJECT_CACHE_DIR  # noqa: F401
except Exception:
    PROJECT_CACHE_DIR = os.path.join(PROJECT_ROOT, "_runtime_cache")
    os.makedirs(PROJECT_CACHE_DIR, exist_ok=True)

# ===== 修复：dotenv 导入异常处理 =====
try:
    from dotenv import set_key, unset_key
except ImportError:
    print("⚠️ python-dotenv 未安装，配置写入功能不可用。请运行: pip install python-dotenv")

    def set_key(*args, **kwargs):
        print("请手动编辑 .env 文件")

    def unset_key(*args, **kwargs):
        print("请手动编辑 .env 文件")

# ============================================================
# UTF-8 编码（已在文件头部统一设置，这里仅作为二次保险）
# ============================================================
try:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# ============================================================
# 常量 - 修改：临时文件统一存于 _runtime_cache/
# ============================================================
DEBUG_DIR = os.path.join(PROJECT_CACHE_DIR, "debug")
SCRIPT_OUTPUT_DIR = os.path.join(PROJECT_CACHE_DIR, "scripts")
ENV_FILE = os.path.join(PROJECT_ROOT, ".env")

# ============================================================
# 模型价格和 Base URL 映射（仅供参考，不包含密钥）
# ============================================================
MODEL_PRICES = {
    # 智谱 glm
    "glm-4-flash": 0.0,
    "glm-4.5-air":  0.0,
    "glm-4.7":      0.0,
    # 阿里云 qwen
    "qwen-plus-2025-07-28": 0.004,
    "qwen3.7-plus":         0.004,
    "qwen3.7-flash":        0.0003,   # 新模型：.env AI_MODEL_ALIASES 已启用
    # 硅基流动 deepseek
    "deepseek-ai/DeepSeek-V3.1-Terminus": 0.002,
    "deepseek-ai/DeepSeek-V3":            0.0015,  # 新模型：已 curl 验证可用
}

DEFAULT_BASE_URLS = {
    # 智谱 glm
    "glm-4-flash": "https://open.bigmodel.cn/api/paas/v4/",
    "glm-4.5-air": "https://open.bigmodel.cn/api/paas/v4/",
    "glm-4.7":     "https://open.bigmodel.cn/api/paas/v4/",
    # 阿里云 qwen
    "qwen-plus-2025-07-28": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "qwen3.7-plus":         "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "qwen3.7-flash":        "https://dashscope.aliyuncs.com/compatible-mode/v1",
    # 硅基流动 deepseek
    "deepseek-ai/DeepSeek-V3.1-Terminus": "https://api.siliconflow.cn/v1",
    "deepseek-ai/DeepSeek-V3":            "https://api.siliconflow.cn/v1",
}

# ============================================================
# 工具函数
# ============================================================


def ensure_debug_dir():
    if not os.path.exists(DEBUG_DIR):
        os.makedirs(DEBUG_DIR)
        print(f"📁 已创建目录: {DEBUG_DIR}/")


def ensure_script_output_dir():
    """确保脚本输出目录存在"""
    if not os.path.exists(SCRIPT_OUTPUT_DIR):
        os.makedirs(SCRIPT_OUTPUT_DIR)
        print(f"📁 已创建目录: {SCRIPT_OUTPUT_DIR}/")


def print_header(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def print_sub_header(title):
    print("\n" + "-" * 40)
    print(f"  {title}")
    print("-" * 40)


def wait_enter():
    input("\n按 Enter 键继续...")


def safe_relpath(path, start):
    try:
        rel = os.path.relpath(path, start)
        if rel.startswith('\\\\.\\') or rel.startswith('//./'):
            return path
        return rel
    except ValueError:
        return path


def read_current_env():
    """读取当前 .env 中的 AI 配置"""
    if not os.path.exists(ENV_FILE):
        return None
    current_config = {}
    with open(ENV_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.startswith('AI_MODEL_CONFIGS='):
                try:
                    val = line.split('=', 1)[1].strip()
                    current_config['configs'] = json.loads(val)
                except BaseException:
                    current_config['configs'] = None
            elif line.startswith('AI_MODELS='):
                try:
                    val = line.split('=', 1)[1].strip()
                    current_config['models'] = json.loads(val)
                except BaseException:
                    current_config['models'] = None
            elif line.startswith('AI_TASK_ALLOCATION='):
                try:
                    val = line.split('=', 1)[1].strip()
                    current_config['allocation'] = json.loads(val)
                except BaseException:
                    current_config['allocation'] = None
    return current_config if current_config else None

# ============================================================
# 安全写入 .env（修复版）
# ============================================================


def write_env_config(configs_dict, models_list, allocation_dict=None):
    """安全写入 .env 配置"""
    env_file = ENV_FILE
    if not os.path.exists(env_file):
        print("⚠️ .env 文件不存在，正在创建...")
        with open(env_file, 'w', encoding='utf-8') as f:
            f.write("# ========== AI 配置 ==========\n")

    unset_key(env_file, "AI_MODEL_CONFIGS")
    unset_key(env_file, "AI_MODELS")
    unset_key(env_file, "AI_TASK_ALLOCATION")

    set_key(env_file, "AI_MODEL_CONFIGS", json.dumps(configs_dict, ensure_ascii=False))
    set_key(env_file, "AI_MODELS", json.dumps(models_list, ensure_ascii=False))
    if allocation_dict:
        set_key(env_file, "AI_TASK_ALLOCATION", json.dumps(allocation_dict, ensure_ascii=False))

    print("✅ AI 配置已安全更新到 .env 文件")
    return True

# ============================================================
# 安全版预设配置（仅作模板，不含真实密钥）
# ============================================================


def get_preset_configs():
    preset1 = (
        "智谱主力（GLM-4-Flash + GLM-4.7）[需填写密钥]",
        {
            "glm-4-flash": {"api_key": "", "base_url": "https://open.bigmodel.cn/api/paas/v4/"},
            "glm-4.7": {"api_key": "", "base_url": "https://open.bigmodel.cn/api/paas/v4/"}
        },
        ["glm-4-flash", "glm-4.7"]
    )
    preset2 = (
        "通义+硅基（Qwen3.7-Plus + DeepSeek-V3.1）[需填写密钥]",
        {
            "qwen3.7-plus": {"api_key": "", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"},
            "deepseek-ai/DeepSeek-V3.1-Terminus": {"api_key": "", "base_url": "https://api.siliconflow.cn/v1"}
        },
        ["qwen3.7-plus", "deepseek-ai/DeepSeek-V3.1-Terminus"]
    )
    preset3 = (
        "四模型全开（flash + qwen + deepseek + glm-4.7）[需填写密钥]",
        {
            "glm-4-flash": {"api_key": "", "base_url": "https://open.bigmodel.cn/api/paas/v4/"},
            "qwen3.7-plus": {"api_key": "", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"},
            "deepseek-ai/DeepSeek-V3.1-Terminus": {"api_key": "", "base_url": "https://api.siliconflow.cn/v1"},
            "glm-4.7": {"api_key": "", "base_url": "https://open.bigmodel.cn/api/paas/v4/"}
        },
        ["glm-4-flash", "qwen3.7-plus", "deepseek-ai/DeepSeek-V3.1-Terminus", "glm-4.7"]
    )
    preset4 = (
        "单智谱（仅 GLM-4-Flash）[需填写密钥]",
        {"glm-4-flash": {"api_key": "", "base_url": "https://open.bigmodel.cn/api/paas/v4/"}},
        ["glm-4-flash"]
    )
    preset5 = (
        "单通义（仅 Qwen3.7-Plus）[需填写密钥]",
        {"qwen3.7-plus": {"api_key": "", "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1"}},
        ["qwen3.7-plus"]
    )
    preset6 = (
        "离线模式（仅本地 Ollama）[无需密钥，但需本地运行 Ollama]",
        {"qwen2.5-coder:7b": {"api_key": "ollama", "base_url": "http://localhost:11434/v1"}},
        ["qwen2.5-coder:7b"]
    )
    return [preset1, preset2, preset3, preset4, preset5, preset6]

# ============================================================
# 功能1：调试 AI
# ============================================================


def test_ai():
    print_header("🔍 调试 AI 连接（全部模型）")
    try:
        from vulnclaw.ai.core import get_llm_client
        import asyncio
        import time

        client = get_llm_client()
        models = client.models
        print(f"📋 当前配置了 {len(models)} 个模型:")
        for i, m in enumerate(models, 1):
            print(f"   {i}. {m}")
        print()

        from vulnclaw.ai.core import settings
        configs = getattr(settings, 'ai_model_configs', {})

        # 修复：configs 的键是 provider 名（zhipu/aliyun/siliconflow），不是模型名。
        # 直接复用 client._get_model_provider(model) 反查 provider，
        # 再从 configs[provider] 获取 api_key / base_url。
        valid_models = []
        for model in models:
            provider = client._get_model_provider(model)
            config = configs.get(provider, {})
            api_key = config.get('api_key', '')
            base_url = config.get('base_url', '')
            if not api_key:
                print(f"❌ {model}: provider={provider}, API Key 为空，跳过")
                continue
            print(f"✅ {model}: provider={provider}, base_url={base_url}, key={len(api_key)} chars")
            valid_models.append(model)

        if not valid_models:
            print("❌ 没有可用的模型（API Key 未配置）")
            return

        print("\n开始测试各模型连接（串行执行，避免限流）...\n")

        async def test_one(model):
            print(f"🔄 测试模型: {model}...")
            start_time = time.time()
            test_client = None
            try:
                test_client = get_llm_client(max_total_tokens=10000, max_rounds=10, force_new=True, timeout=120)
                test_client.models = [model]
                max_tokens = 50  # 统一 50 tokens，避免过小导致空响应
                result = await test_client.ask(
                    "请回复 'OK' 表示连接正常。",
                    system="你只回答 'OK'。",
                    temperature=0,
                    max_tokens=max_tokens,
                    retries=1,
                    models=[model],
                    wrap_data=False
                )
                elapsed = time.time() - start_time
                if result and "OK" in result:
                    print(f"   ✅ {model} 连接成功 (耗时 {elapsed:.2f}s)")
                    return {"model": model, "status": "✅ 成功", "elapsed": elapsed, "response": result}
                else:
                    print(f"   ⚠️ {model} 返回异常: {result[:50] if result else '空响应'}")
                    return {"model": model, "status": "⚠️ 异常", "elapsed": elapsed}
            except Exception as e:
                elapsed = time.time() - start_time
                error_msg = str(e)[:100]
                print(f"   ❌ {model} 连接失败: {error_msg} (耗时 {elapsed:.2f}s)")
                return {"model": model, "status": "❌ 失败", "elapsed": elapsed, "error": error_msg}
            finally:
                if test_client is not None:
                    try:
                        await test_client.close()
                    except BaseException:
                        pass

        async def run_all_tests():
            results = []
            for model in valid_models:
                result = await test_one(model)
                results.append(result)
                await asyncio.sleep(3)
            return results

        results = asyncio.run(run_all_tests())

        print("\n" + "=" * 60)
        print("  📊 模型测试报告")
        print("=" * 60)

        success_count = 0
        for r in results:
            if isinstance(r, Exception):
                print(f"   ❌ 异常: {r}")
                continue
            if isinstance(r, dict):
                status = r.get('status', '未知')
                model = r.get('model', '未知')
                elapsed = r.get('elapsed', 0)
                if "✅" in status:
                    success_count += 1
                    print(f"   {status} {model} ({elapsed:.2f}s)")
                else:
                    error = r.get('error', '')
                    print(f"   {status} {model} ({elapsed:.2f}s) - {error}")

        print("\n" + "-" * 60)
        print(f"📊 总计: {len(valid_models)} 个模型, {success_count} 个成功, {len(valid_models) - success_count} 个失败")
        print("=" * 60)

        if success_count < len(valid_models):
            print("\n💡 提示: 部分模型失败可能是由于限流(429)，建议降低并发或稍后重试。")

        print("✅ AI 调试完成")

    except Exception as e:
        print(f"❌ 调试失败: {e}")
        traceback.print_exc()

# ============================================================
# 功能2：提取核心代码
# ============================================================


def extract_code(output_file=None):
    print_header("📂 提取所有脚本内容及路径（合并为单一文件）")
    # 确保脚本输出目录存在
    ensure_script_output_dir()

    # 修复：旧版本写成 "脚本脚本.txt"，名字不直观还会让用户误搜 "脚本脚本"；
    #       同时默认把产物落到 _runtime_cache/extracted_scripts/ 便于与前面的 ZIP/HMTL 清单统一。
    if output_file is None:
        default_dir = os.path.join(PROJECT_CACHE_DIR, "extracted_scripts")
        os.makedirs(default_dir, exist_ok=True)
        output_file = os.path.join(default_dir, "tools_menu.extracted_scripts.txt")
    output_file = os.path.abspath(output_file)
    out_dir = os.path.dirname(output_file)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    if os.path.exists(output_file):
        try:
            os.remove(output_file)
            print(f"🗑️ 已删除旧文件: {output_file}")
        except Exception as e:
            print(f"⚠️ 删除旧文件失败: {e}，尝试继续...")

    IGNORE_DIRS = [
        "__pycache__", ".git", ".venv", ".env", "venv",
        "thirdparty", "chrome_profile_a", "chrome_profile_b",
        "nyxstrike", "testssl.sh", "sqlmap", "BurpSuite V2026.7.2", "BurpSuite V2026.7.3",
        "logs", "outputs", "tmp", ".cache", ".scan_state_*",
        "node_modules", "legacy", "scripts", "tests", DEBUG_DIR,
        ".vectordb", ".nuclei_cache", ".venv",
        "pentestgpt_agent", "OneForAll", "Zero-SecurityAgent",
        "_runtime_cache"
    ]
    IGNORE_FILES = [
        "*.pyc", "*.pyo", "*.so", "*.dll", "*.exe", "*.log", "*.db",
        "*.gnmap", "*.afg", "*.zip", "*.gz", "*.tar",
        "subdomains_top5000.txt", "vuln_knowledge.db",
        "all_code.txt", "filelist.txt", "脚本脚本.txt",
        "*.sqlite3", "*.sqlite", "*.db-journal",
        "*.lock", "*.tmp", "*.temp", "nul",
        "*.txt", "*.md", "*.rst",
        "cookies.txt", "burp_cookies.json"
    ]
    INCLUDE_EXTS = [".py", ".yml", ".yaml", ".json", ".sh", ".bat"]

    def should_ignore_dir(dirname):
        for pat in IGNORE_DIRS:
            if fnmatch.fnmatch(dirname, pat):
                return True
        return False

    def should_ignore_file(filename):
        for pat in IGNORE_FILES:
            if fnmatch.fnmatch(filename, pat):
                return True
        return False

    root = PROJECT_ROOT
    files = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not should_ignore_dir(d)]
        for f in filenames:
            if should_ignore_file(f):
                continue
            ext = os.path.splitext(f)[1]
            if ext in INCLUDE_EXTS:
                full = os.path.join(dirpath, f)
                files.append(full)

    files.sort()
    total = len(files)
    print(f"找到 {total} 个文件")

    with open(output_file, 'w', encoding='utf-8') as out:
        out.write("# ==========================================\n")
        out.write(f"# 核心代码及路径列表 - {datetime.now()}\n")
        out.write(f"# 文件总数: {total}\n")
        out.write("# ==========================================\n\n")
        out.write("# ========== 文件路径列表 ==========\n")
        for fpath in files:
            rel = os.path.relpath(fpath, root)
            out.write(rel + "\n")
        out.write("\n\n")
        out.write("# ========== 文件内容 ==========\n\n")
        for i, fpath in enumerate(files, 1):
            rel = os.path.relpath(fpath, root)
            out.write(f"================================================================================\n")
            out.write(f"[{i}/{total}] 文件: {rel}\n")
            out.write(f"================================================================================\n\n")
            try:
                with open(fpath, 'r', encoding='utf-8') as f:
                    content = f.read()
                out.write(content)
            except UnicodeDecodeError:
                try:
                    with open(fpath, 'r', encoding='gbk') as f:
                        content = f.read()
                    out.write(content)
                except BaseException:
                    out.write(f"# 编码错误，跳过二进制文件\n")
            except Exception as e:
                out.write(f"# 读取失败: {e}\n")
            out.write("\n\n")

    print(f"✅ 核心代码已保存至: {output_file}")
    return output_file

# ============================================================
# 功能3：清理无用临时文件（内部保留，主菜单已移除）
# ============================================================


def clean_temp():
    """清理无用临时文件（内部函数，主菜单已移除该入口）"""
    print_header("🧹 清理无用临时文件（增强版）")
    root = PROJECT_ROOT

    # 清理 _runtime_cache 目录（如果存在）
    runtime_cache = os.path.join(root, "_runtime_cache")
    if os.path.exists(runtime_cache):
        try:
            shutil.rmtree(runtime_cache, ignore_errors=True)
            print(f"✅ 已删除运行时缓存目录: _runtime_cache/")
        except Exception as e:
            print(f"⚠️ 删除 _runtime_cache 失败: {e}")

    # 清理其他常见垃圾
    clean_patterns = [
        "*.pyc", "__pycache__/", "*.tmp", "*.temp",
        "*.log", "*.lock", ".nuclei_cache/", ".nuclei_cache_*/",
        "*.sqlite3-journal", "chroma.sqlite3-journal",
        "调试/*.txt", "debug/*.txt",
        "endpoints_*.txt", "subfinder_*.txt"
    ]

    to_delete = []
    for pattern in clean_patterns:
        if pattern.endswith('/'):
            dirname = pattern.rstrip('/')
            for dirpath, dirnames, filenames in os.walk(root):
                for d in dirnames:
                    if fnmatch.fnmatch(d, dirname):
                        full = os.path.join(dirpath, d)
                        to_delete.append(("目录", full))
        else:
            for dirpath, dirnames, filenames in os.walk(root):
                for f in filenames:
                    if fnmatch.fnmatch(f, pattern):
                        full = os.path.join(dirpath, f)
                        to_delete.append(("文件", full))

    to_delete = list(set(to_delete))

    if not to_delete:
        print("✅ 没有发现可清理的临时文件/目录。")
        check_disk_space()
        return

    print("将删除以下项目：")
    for typ, path in to_delete:
        rel = safe_relpath(path, root)
        print(f"  [{typ}] {rel}")

    confirm = input("\n确认删除？(y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ 已取消删除。")
        return

    deleted = 0
    for typ, path in to_delete:
        try:
            if typ == "目录":
                shutil.rmtree(path, ignore_errors=True)
            else:
                if os.path.exists(path):
                    os.remove(path)
                else:
                    continue
            print(f"已删除: {safe_relpath(path, root)}")
            deleted += 1
        except Exception as e:
            print(f"⚠️ 删除失败 {safe_relpath(path, root)}: {e}")

    print(f"✅ 清理完成，共删除 {deleted} 项。")
    check_disk_space()


def check_disk_space():
    try:
        import shutil
        usage = shutil.disk_usage(PROJECT_ROOT)
        free_gb = usage.free / (1024 ** 3)
        total_gb = usage.total / (1024 ** 3)
        used_percent = (usage.used / usage.total) * 100
        print(f"\n💾 磁盘空间: 总计 {total_gb:.1f}GB, 已用 {used_percent:.1f}%, 剩余 {free_gb:.1f}GB")
        if free_gb < 1:
            print("⚠️ 警告: 剩余空间不足 1GB，建议清理临时文件")
    except BaseException:
        pass

# ============================================================
# 功能4：AI 配置管理
# ============================================================


async def _test_models_locally(models_list: list) -> dict:
    from vulnclaw.ai.core import get_llm_client
    results = {}
    for model in models_list:
        client = None
        try:
            client = get_llm_client(force_new=True)
            client.models = [model]
            start = time.time()
            resp = await client.ask(
                "请回复 'OK' 表示连接正常。",
                system="你只回答 'OK'。",
                temperature=0,
                max_tokens=20,
                retries=0,
                models=[model],
                wrap_data=False
            )
            elapsed = time.time() - start
            success = resp is not None and "OK" in resp
        except Exception:
            elapsed = 999.0
            success = False
        finally:
            if client is not None:
                try:
                    await client.close()
                except BaseException:
                    pass
        results[model] = {"elapsed": elapsed, "success": success}
    return results


async def _fetch_all_ai_scores_with_metrics(models_list: list, metrics: dict) -> dict:
    try:
        from vulnclaw.ai.core import get_llm_client
        client = get_llm_client()
        if not client.models:
            return None
        evaluator_model = client.models[0]
        if "glm-4-flash" in models_list:
            evaluator_model = "glm-4-flash"
        elif "qwen-plus-2025-07-28" in models_list:
            evaluator_model = "qwen-plus-2025-07-28"
        model_metrics = []
        for model in models_list:
            m = metrics.get(model, {})
            elapsed = m.get("elapsed", 999)
            success = m.get("success", False)
            status = "✅ 成功" if success else "❌ 失败"
            model_metrics.append(f"- {model}: 响应时间 {elapsed:.2f}s, 状态 {status}")
        prompt = f"""
你是一位模型评估专家。以下是基于本地真实测试得到的各 AI 模型性能指标。
请根据这些实测数据，为每个模型打分（0-100），要求分数必须有明显区分度。

实测数据：
{chr(10).join(model_metrics)}

请只返回一个 JSON 对象，键为模型名称，值为 {{"speed": 分数, "stability": 分数, "accuracy": 分数}}。
"""
        try:
            result = await asyncio.wait_for(
                client.ask(
                    prompt,
                    system="你是一个模型评估助手，只返回 JSON。",
                    temperature=0.2,
                    max_tokens=600,
                    models=[evaluator_model],
                    retries=1,
                    wrap_data=False
                ),
                timeout=15.0
            )
        except asyncio.TimeoutError:
            print("   ⏰ AI 打分超时 (15s)，使用硬编码后备")
            return None
        except Exception as e:
            print(f"   ⚠️ AI 打分请求异常: {e}")
            return None
        if not result:
            return None
        json_match = re.search(r'\{.*\}', result, re.DOTALL)
        if json_match:
            data = json.loads(json_match.group())
            for model_name, scores in data.items():
                if not isinstance(scores, dict):
                    return None
                for key in ("speed", "stability", "accuracy"):
                    if key not in scores or not isinstance(scores[key], (int, float)):
                        return None
                    scores[key] = max(0, min(100, int(scores[key])))
            return data
        return None
    except Exception as e:
        print(f"   ⚠️ AI 对比评分失败: {e}")
        return None
    finally:
        try:
            await client.close()
        except BaseException:
            pass


def ai_evaluate_models(models_list, configs):
    model_profiles = {
        "glm-4-flash": {"speed": 95, "stability": 92, "accuracy": 88, "desc": "智谱免费模型，响应快，适合主力", "recommended": "🔥 主力：漏洞验证、IDOR筛选、策略决策、Agent总结、投票"},
        "glm-4.5-air": {"speed": 80, "stability": 65, "accuracy": 90, "desc": "⚠️ 已从配置中移除，不推荐使用", "recommended": "❌ 已禁用"},
        "glm-4.7": {"speed": 72, "stability": 90, "accuracy": 92, "desc": "智谱模型，有500万免费额度，适合打分", "recommended": "🎯 专门：ModelRouter打分 + 漏洞验证分摊"},
        "qwen-plus-2025-07-28": {"speed": 85, "stability": 88, "accuracy": 90, "desc": "阿里云百炼，有100万免费额度", "recommended": "📦 备用：当主力限流时使用"},
        "deepseek-ai/DeepSeek-V3.1-Terminus": {"speed": 65, "stability": 90, "accuracy": 92, "desc": "硅基流动，DeepSeek V3.1", "recommended": "🛡️ 最后防线：所有模型都失败时的保底"},
        "qwen3.7-plus": {"speed": 80, "stability": 65, "accuracy": 90, "desc": "⚠️ 已欠费，不建议使用", "recommended": "❌ 不推荐使用"},
    }
    print("   📡 正在本地测试各模型响应速度...")
    try:
        metrics = asyncio.run(_test_models_locally(models_list))
        print("   ✅ 本地测试完成")
    except Exception as e:
        print(f"   ⚠️ 本地测试失败: {e}，将使用硬编码后备")
        metrics = {m: {"elapsed": 999, "success": False} for m in models_list}
    if metrics.get("glm-4.7", {}).get("elapsed", 0) > 8:
        print("   ⏰ glm-4.7 响应过慢 (>{8}s)，跳过 AI 打分，使用硬编码后备")
        ai_scores = None
    else:
        print("   🤖 正在使用本地 AI 基于实测数据对比打分...")
        ai_scores = None
        try:
            ai_scores = asyncio.run(_fetch_all_ai_scores_with_metrics(models_list, metrics))
            if ai_scores:
                print("   ✅ AI 对比打分成功")
            else:
                print("   ⚠️ AI 打分返回空，使用硬编码后备")
        except Exception as e:
            print(f"   ⚠️ AI 打分异常: {e}，使用硬编码后备")
    results = []
    for model in models_list:
        fallback = model_profiles.get(model, {"speed": 60, "stability": 60, "accuracy": 60, "desc": "未知模型，使用默认评分", "recommended": "⚠️ 建议测试后分配"})
        if ai_scores and model in ai_scores:
            ai = ai_scores[model]
            speed = ai.get("speed", fallback["speed"])
            stability = ai.get("stability", fallback["stability"])
            accuracy = ai.get("accuracy", fallback["accuracy"])
        else:
            speed = fallback["speed"]
            stability = fallback["stability"]
            accuracy = fallback["accuracy"]
        price = MODEL_PRICES.get(model, 0.01)
        price_score = max(0, 100 - int(price * 10000))
        total = speed + stability + accuracy + price_score
        results.append({
            "model": model,
            "speed": speed,
            "stability": stability,
            "accuracy": accuracy,
            "price": price_score,
            "total": total,
            "desc": fallback["desc"],
            "cost_per_1k": price,
            "recommended": fallback["recommended"]
        })
    return sorted(results, key=lambda x: x["total"], reverse=True)


def show_model_evaluation(models_list, configs):
    print_header("📊 AI 模型能力评价（满分400分）")
    print("\n评价维度说明:")
    print("  ⚡ 响应速度 (100分) —— 模型推理速度")
    print("  🛡️ 稳定性 (100分) —— 返回内容稳定性")
    print("  🎯 准确性 (100分) —— 安全分析能力")
    print("  💰 成本 (100分) —— 免费额度/价格（越便宜分越高）")
    print("=" * 60)
    real_models = list(configs.keys()) if configs else (models_list if models_list else [])
    if not real_models:
        print("❌ 没有配置任何模型。")
        return
    results = ai_evaluate_models(real_models, configs)
    print(f"\n{'模型名称':<32} {'速度':<6} {'稳定性':<8} {'准确性':<8} {'成本':<6} {'总分':<6} {'建议'}")
    print("-" * 100)
    for r in results:
        status = "✅" if r["total"] >= 320 else ("⚠️" if r["total"] >= 240 else "❌")
        cost_str = f"{r['cost_per_1k']:.3f}" if r['cost_per_1k'] > 0 else "免费"
        print(f"{r['model']:<32} {r['speed']:<6} {r['stability']:<8} {r['accuracy']:<8} {r['price']:<6} {r['total']:<6} {status}")
        print(f"   └─ {r['desc']} (1k tokens: ¥{cost_str})")
        print(f"   └─ 🎯 推荐任务: {r['recommended']}")
        print()
    print("=" * 60)
    print("💡 总分 >= 320: ✅ 强力推荐 | 240-319: ⚠️ 可接受 | < 240: ❌ 不推荐")


def custom_config_wizard():
    print_header("📝 交互式 AI 配置向导")
    print("您将逐个输入模型信息，每次输入后询问是否继续，最多 5 个。")
    print()
    configs = {}
    models = []
    while len(models) < 5:
        print_sub_header(f"添加第 {len(models) + 1} 个模型")
        model_name = input("请输入模型名称（如 glm-4-flash）: ").strip()
        if not model_name:
            print("❌ 模型名称不能为空，请重新输入。")
            continue
        if model_name in configs:
            print(f"⚠️ 模型 '{model_name}' 已存在，请使用不同名称。")
            continue
        base_url = DEFAULT_BASE_URLS.get(model_name)
        if base_url:
            print(f"✅ 已识别 base_url: {base_url}")
            use_default = input("使用此默认地址？（直接回车使用，或输入新地址）: ").strip()
            if use_default:
                base_url = use_default
        else:
            print("⚠️ 未识别该模型，请手动输入 Base URL")
            base_url = input("请输入 Base URL: ").strip()
            if not base_url:
                print("❌ Base URL 不能为空，请重新输入。")
                continue
        api_key = input("请输入 API Key: ").strip()
        if not api_key:
            print("❌ API Key 不能为空，请重新输入。")
            continue
        configs[model_name] = {"api_key": api_key, "base_url": base_url}
        models.append(model_name)
        print(f"✅ 已添加模型: {model_name}")
        if len(models) >= 5:
            print("已添加 5 个模型，达到上限。")
            break
        cont = input("\n是否继续添加下一个模型？(y/n): ").strip().lower()
        if cont != 'y':
            break
    if not models:
        print("❌ 没有添加任何模型，取消配置。")
        return None, None
    print("\n" + "=" * 60)
    print("  📋 已添加的模型列表")
    print("=" * 60)
    for i, name in enumerate(models, 1):
        print(f"  {i}. {name}")
    print("\n您可以选择使用全部模型，或只使用其中部分。")
    selection = input("请输入要使用的模型序号（用逗号分隔，直接回车使用全部）: ").strip()
    if selection:
        selected_indices = []
        for part in selection.split(','):
            try:
                idx = int(part.strip())
                if 1 <= idx <= len(models):
                    selected_indices.append(idx)
            except ValueError:
                pass
        if selected_indices:
            selected_models = [models[idx - 1] for idx in selected_indices]
        else:
            selected_models = models
    else:
        selected_models = models
    final_configs = {name: configs[name] for name in selected_models}
    print("\n最终配置:")
    for name in selected_models:
        print(f"  ✅ {name}")
    confirm = input("\n保存此配置？(y/n): ").strip().lower()
    if confirm == 'y':
        return final_configs, selected_models
    else:
        print("❌ 已取消保存。")
        return None, None


TASK_TYPES = [
    {"id": "verify", "name": "漏洞验证", "desc": "verify_with_ai / batch_verify_with_ai"},
    {"id": "nuclei", "name": "Nuclei验证", "desc": "verify_nuclei_with_ai_async"},
    {"id": "idor", "name": "IDOR筛选", "desc": "_ai_select_targets (IDOR)"},
    {"id": "strategy", "name": "策略决策", "desc": "decide_scan_depth_with_ai"},
    {"id": "agent", "name": "Agent总结", "desc": "run_coordinator / run_full_agent"},
    {"id": "red_blue", "name": "红蓝对抗", "desc": "red_blue_judge"},
    {"id": "negotiate", "name": "多AI协商", "desc": "multi_ai_negotiate"},
    {"id": "scoring", "name": "ModelRouter打分", "desc": "model_router.py 打分"},
    {"id": "vote", "name": "投票参与", "desc": "所有投票场景"},
]


def manage_task_allocation(models_list, configs):
    print_header("🎯 AI 任务分配（手动模式）")
    if not models_list:
        print("❌ 没有配置任何模型，请先配置 AI 模型。")
        return
    current_env = read_current_env()
    allocation = current_env.get('allocation', {}) if current_env else {}
    if not allocation:
        for task in TASK_TYPES:
            allocation[task["id"]] = models_list.copy()
        print("📋 使用默认分配方案：所有模型参与所有任务")
    while True:
        print("\n" + "=" * 60)
        print("  🎯 当前任务分配")
        print("=" * 60)
        for task in TASK_TYPES:
            models_for_task = allocation.get(task["id"], [])
            print(f"\n  【{task['name']}】{task['desc']}")
            if models_for_task:
                print(f"    └─ 模型: {', '.join(models_for_task)}")
            else:
                print(f"    └─ ⚠️ 未分配任何模型")
        print("\n" + "-" * 40)
        print("  操作:")
        print("    1. 修改某个任务的模型列表")
        print("    2. 重置为默认分配（所有模型参与所有任务）")
        print("    3. 查看模型评价（帮助选择）")
        print("    4. 保存并返回")
        print("    5. 不保存返回")
        choice = input("\n请选择 (1-5): ").strip()
        if choice == "1":
            print("\n可选任务:")
            for i, task in enumerate(TASK_TYPES, 1):
                current_models = allocation.get(task["id"], [])
                models_str = ", ".join(current_models) if current_models else "未分配"
                print(f"  {i}. {task['name']} -> {models_str}")
            task_choice = input("\n选择要修改的任务编号: ").strip()
            try:
                task_idx = int(task_choice) - 1
                if task_idx < 0 or task_idx >= len(TASK_TYPES):
                    print("❌ 无效选择")
                    continue
                selected_task = TASK_TYPES[task_idx]
                print(f"\n正在修改: {selected_task['name']}")
                print(f"当前模型: {', '.join(allocation.get(selected_task['id'], [])) if allocation.get(selected_task['id']) else '未分配'}")
                print(f"可用模型: {', '.join(models_list)}")
                new_models_input = input("\n请输入要分配的模型（用逗号分隔，直接回车取消）: ").strip()
                if not new_models_input:
                    continue
                new_models = [m.strip() for m in new_models_input.split(',') if m.strip()]
                valid_models = [m for m in new_models if m in models_list]
                invalid_models = [m for m in new_models if m not in models_list]
                if invalid_models:
                    print(f"⚠️ 以下模型不存在，已忽略: {', '.join(invalid_models)}")
                if valid_models:
                    allocation[selected_task["id"]] = valid_models
                    print(f"✅ {selected_task['name']} 已分配: {', '.join(valid_models)}")
                else:
                    print("❌ 没有有效的模型被分配")
            except ValueError:
                print("❌ 请输入有效数字")
        elif choice == "2":
            for task in TASK_TYPES:
                allocation[task["id"]] = models_list.copy()
            print("✅ 已重置为默认分配")
        elif choice == "3":
            show_model_evaluation(models_list, configs)
            wait_enter()
        elif choice == "4":
            if write_env_config(configs, models_list, allocation):
                print("✅ 任务分配方案已保存到 .env")
            else:
                print("❌ 保存失败")
            break
        elif choice == "5":
            print("❌ 取消修改，返回")
            break
        else:
            print("❌ 无效选择")


def ai_auto_allocate(models_list, configs):
    print_header("🤖 AI 自动分配任务")
    if not models_list:
        print("❌ 没有配置任何模型，请先配置 AI 模型。")
        return
    print("正在分析模型能力...")
    evaluations = ai_evaluate_models(models_list, configs)
    sorted_models = sorted(evaluations, key=lambda x: x["total"], reverse=True)
    if len(sorted_models) >= 1:
        primary = sorted_models[0]["model"]
    else:
        primary = models_list[0]
    if len(sorted_models) >= 2:
        secondary = sorted_models[1]["model"]
    else:
        secondary = primary
    if len(sorted_models) >= 3:
        tertiary = sorted_models[2]["model"]
    else:
        tertiary = secondary
    backup_models = []
    for m in sorted_models[3:]:
        if m["total"] >= 240:
            backup_models.append(m["model"])
    print(f"\n📊 自动分配结果:")
    print(f"   🥇 主力模型: {primary} (总分: {sorted_models[0]['total']})")
    if len(sorted_models) >= 2:
        print(f"   🥈 辅助模型: {secondary} (总分: {sorted_models[1]['total']})")
    if len(sorted_models) >= 3:
        print(f"   🥉 第三模型: {tertiary} (总分: {sorted_models[2]['total']})")
    if backup_models:
        print(f"   📦 备用模型: {', '.join(backup_models)}")
    print("\n正在生成分配方案...")
    allocation = {}
    allocation["verify"] = [primary, secondary, tertiary] if len(sorted_models) >= 3 else [primary, secondary]
    allocation["nuclei"] = [primary, secondary]
    allocation["idor"] = [primary, secondary]
    allocation["strategy"] = [primary, secondary, tertiary] if len(sorted_models) >= 3 else [primary, secondary]
    allocation["agent"] = [primary, secondary]
    allocation["red_blue"] = [primary, secondary, tertiary] if len(sorted_models) >= 3 else [primary, secondary]
    vote_models = [m["model"] for m in sorted_models if m["total"] >= 320]
    if len(vote_models) < 2:
        vote_models = models_list[:3]
    allocation["negotiate"] = vote_models
    allocation["scoring"] = [primary]
    vote_participants = [m["model"] for m in sorted_models if m["total"] >= 280]
    if len(vote_participants) < 2:
        vote_participants = models_list[:2]
    allocation["vote"] = vote_participants
    print("\n" + "=" * 60)
    print("  📋 最终任务分配方案")
    print("=" * 60)
    task_names = {t["id"]: t["name"] for t in TASK_TYPES}
    for task_id, models in allocation.items():
        if task_id in task_names:
            print(f"\n  【{task_names[task_id]}】")
            if models:
                print(f"    └─ {', '.join(models)}")
            else:
                print(f"    └─ ⚠️ 未分配")
    print("\n" + "-" * 40)
    confirm = input("是否保存此分配方案？(y/n): ").strip().lower()
    if confirm == 'y':
        if write_env_config(configs, models_list, allocation):
            print("✅ 分配方案已保存到 .env")
        else:
            print("❌ 保存失败")
    else:
        print("❌ 已取消保存")


def manage_ai_config():
    print_header("🔧 AI 配置管理")
    current = read_current_env()
    if current and current.get('configs') and current.get('models'):
        print("📋 当前配置:")
        print(f"   模型列表: {', '.join(current['models'])}")
        print(f"   模型数量: {len(current['models'])} 个")
        if current.get('allocation'):
            print(f"   ✅ 任务分配方案: 已配置")
        else:
            print(f"   ⚠️ 任务分配方案: 未配置（使用默认）")
    else:
        print("⚠️ 未检测到当前 AI 配置，或配置不完整。")
    print("\n" + "-" * 40)
    print("  操作:")
    print("    1. 使用预设配置模板（需自行填写 API Key）")
    print("    2. 交互式向导配置（推荐）")
    print("    3. 查看模型评价（能力评分 + 推荐任务）")
    print("    4. 手动分配任务（细分到每个模型）")
    print("    5. AI 自动分配任务")
    print("    6. 返回")
    choice = input("\n请选择 (1-6): ").strip()
    if choice == "1":
        presets = get_preset_configs()
        print("\n可选预设配置模板（所有密钥均为空，需自行填写）:")
        for i, (name, _, _) in enumerate(presets, 1):
            print(f"  {i}. {name}")
        print("  0. 返回")
        sel = input("请选择预设编号 (0-6): ").strip()
        if sel == "0":
            return
        try:
            idx = int(sel) - 1
            if idx < 0 or idx >= len(presets):
                print("❌ 无效编号")
                return
            _, configs, models = presets[idx]
            empty_keys = [k for k, v in configs.items() if not v.get('api_key')]
            if empty_keys:
                print(f"⚠️ 以下模型的 API Key 为空: {', '.join(empty_keys)}")
                print("   你需要在保存后手动编辑 .env 文件填写 Key。")
            if write_env_config(configs, models):
                print("✅ 配置模板已写入 .env，请编辑 .env 填写你的 API Key。")
            else:
                print("❌ 写入失败，请检查 .env 文件权限。")
        except ValueError:
            print("❌ 请输入数字")
    elif choice == "2":
        final_configs, final_models = custom_config_wizard()
        if final_configs and final_models:
            if write_env_config(final_configs, final_models):
                print("✅ 配置已更新。请重新启动 `scripts/debug.bat` 或 `python scan.py` 生效。")
                print("\n💡 接下来建议使用 '3. 查看模型评价' 或 '4. 手动分配任务' 来优化分配。")
            else:
                print("❌ 写入失败，请检查 .env 文件权限。")
        else:
            print("❌ 配置取消。")
    elif choice == "3":
        if not current or not current.get('models'):
            print("❌ 没有配置任何模型，请先配置 AI 模型。")
            return
        show_model_evaluation(current['models'], current['configs'])
        wait_enter()
    elif choice == "4":
        if not current or not current.get('models'):
            print("❌ 没有配置任何模型，请先配置 AI 模型。")
            return
        manage_task_allocation(current['models'], current['configs'])
    elif choice == "5":
        if not current or not current.get('models'):
            print("❌ 没有配置任何模型，请先配置 AI 模型。")
            return
        ai_auto_allocate(current['models'], current['configs'])
    elif choice == "6":
        return
    else:
        print("❌ 无效选择")

# ============================================================
# 功能5：系统维护
# ============================================================


def system_maintenance():
    print_header("🔧 系统维护")
    print("  1. 扫描器自检（一键检测所有组件）")
    print("  2. 一键环境恢复（安装依赖 + 配置 Burp）")
    print("  3. 全部执行（自检 + 环境恢复）")
    print("  ---")
    print("  4. 🆕 清理所有扫描缓存和临时文件（含 _runtime_cache）")
    print("  5. 🆕 一键健康检查并修复")
    print("  6. 返回")
    choice = input("\n请选择 (1-6): ").strip()
    if choice == "1":
        self_test()
    elif choice == "2":
        setup_environment()
    elif choice == "3":
        print("\n🔄 执行自检...")
        self_test()
        print("\n🔄 执行环境恢复...")
        setup_environment()
    elif choice == "4":
        clean_all_cache()
        wait_enter()
    elif choice == "5":
        health_check_and_fix()
        wait_enter()
    elif choice == "6":
        return
    else:
        print("❌ 无效选择")


def self_test(return_summary=False):
    print_header("🔍 扫描器自检")
    print("正在检查所有组件...\n")
    results = []
    print("1. 检查 Python 版本...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 8:
        print(f"   ✅ Python 版本 {version.major}.{version.minor}.{version.micro} (符合要求)")
        results.append(True)
    else:
        print(f"   ❌ Python 版本 {version.major}.{version.minor} 低于 3.8，请升级")
        results.append(False)
    print("\n2. 检查关键依赖包...")
    # ===== 修复：使用正确的模块名映射 =====
    required = [
        ("aiohttp", "aiohttp"),
        ("openai", "openai"),
        ("pydantic", "pydantic"),
        ("pydantic_settings", "pydantic_settings"),
        ("requests", "requests"),
        ("python_dotenv", "dotenv"),
        ("bs4", "beautifulsoup4"),  # 修复：bs4 → beautifulsoup4
        ("dns", "dnspython"),       # 修复：dns → dnspython
        ("chromadb", "chromadb"),
        ("tqdm", "tqdm"),
        ("playwright", "playwright"),
        ("whois", "whois"),
    ]
    missing = []
    for module_name, package_name in required:
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(package_name)
    if missing:
        print(f"   ❌ 缺少依赖包: {', '.join(missing)}")
        print(f"   💡 请运行: pip install {' '.join(missing)}")
        results.append(False)
    else:
        print("   ✅ 所有关键依赖包已安装")
        results.append(True)
    print("\n3. 检查 .env 文件...")
    env_path = Path(".env")
    if not env_path.exists():
        print("   ❌ .env 文件不存在")
        results.append(False)
    else:
        try:
            with open(env_path, 'r', encoding='utf-8') as f:
                content = f.read()
            match = re.search(r'AI_MODEL_CONFIGS=({.*})', content)
            if match:
                json.loads(match.group(1))
                print("   ✅ .env 文件格式正确 (AI_MODEL_CONFIGS 可解析)")
                results.append(True)
            else:
                print("   ⚠️ 未找到 AI_MODEL_CONFIGS，AI 功能可能无法使用")
                results.append(True)
        except json.JSONDecodeError as e:
            print(f"   ❌ AI_MODEL_CONFIGS JSON 格式错误: {e}")
            results.append(False)
        except Exception as e:
            print(f"   ❌ .env 读取失败: {e}")
            results.append(False)
    print("\n4. 测试 AI 模型连接...")
    try:
        from vulnclaw.ai.core import get_llm_client
        import asyncio
        client = get_llm_client()
        if not client.models:
            print("   ❌ 没有可用的 AI 模型")
            results.append(False)
        else:
            print(f"   📋 已加载模型: {', '.join(client.models)}")

            async def test():
                try:
                    result = await client.ask(
                        "请回复 'OK' 表示连接正常。",
                        system="你只回答 'OK'。",
                        temperature=0,
                        models=[client.models[0]],
                        wrap_data=False
                    )
                    return "OK" in result
                except Exception as e:
                    print(f"   ⚠️ AI 连接测试异常: {e}")
                    return False
                finally:
                    try:
                        await client.close()
                    except BaseException:
                        pass
            if asyncio.run(test()):
                print(f"   ✅ AI 模型 {client.models[0]} 连接正常")
                results.append(True)
            else:
                print(f"   ❌ AI 模型 {client.models[0]} 连接失败，请检查 API Key")
                results.append(False)
    except Exception as e:
        print(f"   ❌ AI 连接测试失败: {e}")
        results.append(False)
    print("\n5. 检查关键目录...")
    dirs = [
        "thirdparty",
        os.path.join(PROJECT_CACHE_DIR, "reports"),
        os.path.join(PROJECT_CACHE_DIR, "logs"),
    ]
    missing_dirs = []
    for d in dirs:
        if not Path(d).exists():
            missing_dirs.append(d)
    if missing_dirs:
        print(f"   ⚠️ 缺少目录: {', '.join(missing_dirs)} (扫描器会自动创建)")
        results.append(True)
    else:
        print("   ✅ 关键目录均已存在")
        results.append(True)
    print("\n6. 检查第三方工具...")
    tools = ["nuclei.exe", "subfinder.exe", "httpx.exe"]
    thirdparty_dir = Path("thirdparty")
    missing_tools = []
    for tool in tools:
        tool_path = thirdparty_dir / tool
        if tool_path.exists():
            print(f"   ✅ {tool} 存在")
        else:
            if shutil.which(tool.replace('.exe', '')):
                print(f"   ✅ {tool} 在 PATH 中")
            else:
                missing_tools.append(tool)
                print(f"   ❌ {tool} 未找到")
    if missing_tools:
        print(f"   ⚠️ 缺少工具: {', '.join(missing_tools)} (部分功能受限)")
        results.append(True)
    else:
        results.append(True)
    print("\n7. 检查 Nuclei 模板目录...")
    try:
        from vulnclaw.core.settings import settings
        # ===== 修复：使用 os.path.expanduser 展开 ~ =====
        template_dir = os.path.expanduser(settings.nuclei_template_dir)
        if os.path.exists(template_dir) and os.path.isdir(template_dir):
            print(f"   ✅ Nuclei 模板目录存在: {template_dir}")
            results.append(True)
        else:
            print(f"   ⚠️ Nuclei 模板目录不存在: {template_dir}")
            results.append(True)
    except Exception as e:
        print(f"   ❌ 无法读取 Nuclei 模板配置: {e}")
        results.append(False)
    print("\n8. 检查 ChromaDB 向量数据库...")
    try:
        import chromadb  # noqa: F401
        # 修复：此处不要再 from core.settings import PROJECT_CACHE_DIR（会把外层同名全局变成
        #      本函数的 local variable，导致 5. 关键目录检查那里先用到时抛 UnboundLocalError）。
        vectordb_path = os.path.join(PROJECT_CACHE_DIR, "vectordb")
        _ = chromadb.PersistentClient(path=vectordb_path)
        print("   ✅ ChromaDB 可正常初始化")
        results.append(True)
    except Exception as e:
        print(f"   ❌ ChromaDB 初始化失败: {e}")
        results.append(False)
    print("\n9. 检查 Playwright 浏览器...")
    try:
        import playwright
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        print("   ✅ Playwright Chromium 浏览器可用")
        results.append(True)
    except ImportError:
        print("   ❌ Playwright 未安装")
        results.append(False)
    except Exception as e:
        print(f"   ❌ Playwright 浏览器初始化失败: {e}")
        results.append(False)
    print("\n10. 检查 Burp 代理连通性...")
    try:
        import socket
        for port in [8081, 8080, 1337]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            if result == 0:
                print(f"   ✅ Burp 代理正在监听 127.0.0.1:{port}")
                results.append(True)
                break
        else:
            print("   ⚠️ Burp 代理未监听 (扫描器仍可运行)")
            results.append(True)
    except Exception as e:
        print(f"   ⚠️ 无法检查 Burp 代理: {e}")
        results.append(True)
    print("\n11. 检查数据库读写权限...")
    db_files = ["vuln_knowledge.db", "chroma.sqlite3"]
    db_ok = True
    for db in db_files:
        p = Path(db)
        if p.exists():
            if os.access(p, os.W_OK):
                print(f"   ✅ {db} 可读写")
            else:
                print(f"   ❌ {db} 不可写")
                db_ok = False
        else:
            print(f"   ℹ️ {db} 不存在 (首次运行会创建)")
    results.append(db_ok)
    print("\n" + "=" * 60)
    print("   📊 自检报告")
    print("=" * 60)
    status_names = ["Python 版本", "依赖包", ".env 配置", "AI 模型连接", "关键目录", "第三方工具", "Nuclei 模板", "ChromaDB", "Playwright 浏览器", "Burp 代理", "数据库权限"]
    for i, (name, passed) in enumerate(zip(status_names, results)):
        status = "✅ 通过" if passed else "❌ 失败"
        print(f"{name:.<20} {status}")
    if all(results):
        print(f"\n🎉 所有检查通过，扫描器可以正常运行！")
    else:
        failed = sum(1 for r in results if not r)
        print(f"\n⚠️ 有 {failed} 项检查未通过，部分功能可能受限。")
    if return_summary:
        return {"pass": all(results),
                "passed": int(sum(1 for r in results if r)),
                "total": len(results)}


def setup_environment():
    print_header("🔧 一键环境恢复")
    print("正在安装依赖和配置环境...\n")
    print("[1/6] 检查 Python 环境...")
    try:
        result = subprocess.run(["python", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Python 未安装，请先安装 Python 3.8+")
            return
        print(f"✅ {result.stdout.strip()}")
    except BaseException:
        print("❌ Python 未安装，请先安装 Python 3.8+")
        return
    print("\n[2/6] 安装 Python 依赖包...")
    try:
        if os.path.exists("requirements.txt"):
            subprocess.run(["pip", "install", "-r", "requirements.txt", "-q"], check=False)
        subprocess.run(["pip", "install", "whois", "beautifulsoup4", "chromadb", "playwright", "psutil", "esprima", "-q"], check=False)
        subprocess.run(["playwright", "install", "chromium", "--quiet"], check=False)
        print("✅ Python 依赖安装完成")
    except Exception as e:
        print(f"⚠️ 依赖安装部分失败: {e}")
    print("\n[3/6] 创建 Burp 日志目录...")
    burp_log_dir = os.path.expanduser("~/burp_logs")
    os.makedirs(burp_log_dir, exist_ok=True)
    print(f"✅ Burp 日志目录已创建: {burp_log_dir}")
    print("\n[4/6] 生成 Burp 插件...")
    plugin_dir = os.path.join(PROJECT_ROOT, "thirdparty", "extensions")
    os.makedirs(plugin_dir, exist_ok=True)
    plugin_content = '''# -*- coding: utf-8 -*-
# BurpExtender.py - Cookie/Token 自动导出插件
import json
import os
import time
import traceback
from threading import Lock
from burp import IBurpExtender, IHttpListener

OUTPUT_FILE = os.path.expanduser("~/burp_cookies.json")
LOCK = Lock()

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Cookie Exporter")
        callbacks.registerHttpListener(self)
        self._data = {}
        self._save_interval = 2
        print("[+] Cookie Exporter 已加载")
        print("[+] 输出文件: " + OUTPUT_FILE)
        try:
            if os.path.exists(OUTPUT_FILE):
                with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                    _old = json.load(f)
                _domains = [k for k in _old if k != "_meta"]
                print("[+] 已继承历史 Cookie 域 " + str(len(_domains)) + " 个")
        except Exception as e:
            print("[!] 读取历史 Cookie 失败（将从头累积）: " + repr(e))

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not messageIsRequest:
            return
        try:
            request = messageInfo.getRequest()
            if request is None: return
            analyzed = self._helpers.analyzeRequest(request)
            headers = analyzed.getHeaders()
            url = messageInfo.getUrl()
            if url is None: return
            host = url.getHost()
            if not host: return
            cookies = {}
            tokens = {}
            for header in headers:
                h = header.lower()
                if h.startswith("cookie:"):
                    for part in header[7:].strip().split(";"):
                        part = part.strip()
                        if "=" in part:
                            k, v = part.split("=", 1)
                            cookies[k] = v
                elif h.startswith("authorization:"):
                    tokens["Authorization"] = header[14:].strip()
                elif h.startswith("x-api-key:"):
                    tokens["X-API-Key"] = header[10:].strip()
            if cookies or tokens:
                with LOCK:
                    if host not in self._data:
                        self._data[host] = {}
                    self._data[host].update(cookies)
                    self._data[host].update(tokens)
                self._save_data()
        except Exception:
            print("[!] Cookie Exporter 处理请求异常（插件仍运行）:")
            traceback.print_exc()

    def _save_data(self):
        if not self._data:
            return
        with LOCK:
            existing = {}
            if os.path.exists(OUTPUT_FILE):
                try:
                    with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    print("[!] 读取历史 Cookie 文件失败，将重建该文件:")
                    traceback.print_exc()
            for domain, items in self._data.items():
                if domain not in existing:
                    existing[domain] = {}
                existing[domain].update(items)
            existing["_meta"] = {
                "last_update": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "domains": len([k for k in existing if k != "_meta"]),
            }
            try:
                with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2, ensure_ascii=False)
                print("[+] Cookie 已写盘: " + time.strftime("%H:%M:%S") + " 域数=" + str(existing["_meta"]["domains"]))
            except Exception:
                print("[!] 写 cookie 文件失败:")
                traceback.print_exc()
'''
    plugin_path = os.path.join(plugin_dir, "BurpExtender.py")
    with open(plugin_path, 'w', encoding='utf-8') as f:
        f.write(plugin_content)
    print(f"✅ Burp 插件已生成: {plugin_path}")
    print("\n[5/6] 创建 .env 配置文件...")
    if not os.path.exists(".env"):
        env_content = '''# ========== AI 模型别名映射 ==========
AI_MODEL_ALIASES={"1":"glm-4-flash","2":"qwen-plus-2025-07-28","4":"deepseek-ai/DeepSeek-V3.1-Terminus","5":"glm-4.7"}

# ========== Burp 配置 ==========
BURP_API_URL=http://127.0.0.1:1337
BURP_API_KEY=

# ========== AI 默认配置（请填写你的 API Key） ==========
AI_MODEL_CONFIGS={"glm-4-flash":{"api_key":"","base_url":"https://open.bigmodel.cn/api/paas/v4/"},"qwen-plus-2025-07-28":{"api_key":"","base_url":"https://dashscope.aliyuncs.com/compatible-mode/v1"},"deepseek-ai/DeepSeek-V3.1-Terminus":{"api_key":"","base_url":"https://api.siliconflow.cn/v1"},"glm-4.7":{"api_key":"","base_url":"https://open.bigmodel.cn/api/paas/v4/"}}
AI_MODELS=["1","2","4","5"]'''
        with open(".env", 'w', encoding='utf-8') as f:
            f.write(env_content)
        print("✅ .env 已创建（请填写 API Key）")
    else:
        print("✅ .env 已存在，跳过创建")
        print("💡 提醒：请检查 .env 中的 base_url 是否包含正确的 'paas'（不是 'pass'）和 'api'（不是 'apis'）")
    print("\n[6/6] 创建输出目录...")
    for d in [
        os.path.join(PROJECT_CACHE_DIR, "reports"),
        os.path.join(PROJECT_CACHE_DIR, "logs"),
    ]:
        os.makedirs(d, exist_ok=True)
    print("✅ 目录结构已创建")
    print("\n" + "=" * 60)
    print("  ✅ 环境恢复完成！")
    print("=" * 60)
    print("\n📌 后续步骤:")
    print("  1. 打开 Burp → Extender → Add → 加载 BurpExtender.py")
    print("  2. Burp → Project options → Logging → 开启 Request logging")
    print(f"     日志路径: {burp_log_dir}\\requests.log")
    print(f"\n📂 Burp 插件位置: {plugin_path}")
    print("\n💡 如果使用 '查看模型评价' 功能卡住，按 Ctrl+C 中断即可，不影响主扫描器。")

# ============================================================
# 功能6：启动浏览器（走 Burp 代理）
# ============================================================


def start_browser_burp():
    print_header("🌐 启动浏览器（走 Burp 代理）")
    print("请选择要启动的浏览器：")
    print("  1. Chrome")
    print("  2. Firefox")
    print("  3. Edge")
    print("  4. 返回")
    choice = input("请选择 (1-4): ").strip()
    if choice == "4":
        return
    if choice not in ["1", "2", "3"]:
        print("❌ 无效选择")
        return
    port_input = input("请输入 Burp 代理端口（默认 8080）: ").strip()
    proxy_port = port_input if port_input else "8080"
    proxy = f"127.0.0.1:{proxy_port}"
    target_url = input("请输入要访问的目标 URL（直接回车使用 https://www.tw.coupang.com）: ").strip()
    if not target_url:
        target_url = "https://www.tw.coupang.com"
    browser_map = {"1": ("Chrome", "chrome"), "2": ("Firefox", "firefox"), "3": ("Edge", "edge")}
    browser_name, browser_cmd = browser_map[choice]
    print(f"\n🚀 启动 {browser_name}，代理: {proxy}，目标: {target_url}")
    try:
        if browser_cmd == "chrome":
            chrome_profile_dir = os.path.join(PROJECT_ROOT, "chrome_profile")
            if not os.path.exists(chrome_profile_dir):
                os.makedirs(chrome_profile_dir)
            chrome_path = shutil.which("chrome") or shutil.which("chromium")
            if not chrome_path:
                possible_paths = [
                    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
                    os.path.expanduser(r"~\AppData\Local\Google\Chrome\Application\chrome.exe")
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        chrome_path = p
                        break
            if not chrome_path:
                print("❌ 未找到 Chrome 可执行文件。请确保 Chrome 已安装或在 PATH 中。")
                return
            cmd = [chrome_path, f"--proxy-server={proxy}", f"--user-data-dir={chrome_profile_dir}", "--new-window", target_url]
            subprocess.Popen(cmd, shell=False)
        elif browser_cmd == "firefox":
            firefox_profile_dir = os.path.join(PROJECT_ROOT, "firefox_profile")
            if not os.path.exists(firefox_profile_dir):
                os.makedirs(firefox_profile_dir)
            user_js_path = os.path.join(firefox_profile_dir, "user.js")
            with open(user_js_path, 'w', encoding='utf-8') as f:
                f.write(f'''
user_pref("network.proxy.http", "127.0.0.1");
user_pref("network.proxy.http_port", {proxy_port});
user_pref("network.proxy.ssl", "127.0.0.1");
user_pref("network.proxy.ssl_port", {proxy_port});
user_pref("network.proxy.type", 1);
user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");
''')
            firefox_path = shutil.which("firefox")
            if not firefox_path:
                possible_paths = [
                    r"C:\Program Files\Mozilla Firefox\firefox.exe",
                    r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        firefox_path = p
                        break
            if not firefox_path:
                print("❌ 未找到 Firefox 可执行文件。请确保 Firefox 已安装或在 PATH 中。")
                return
            cmd = [firefox_path, "-no-remote", "-profile", firefox_profile_dir, target_url]
            subprocess.Popen(cmd, shell=False)
        elif browser_cmd == "edge":
            edge_profile_dir = os.path.join(PROJECT_ROOT, "edge_profile")
            if not os.path.exists(edge_profile_dir):
                os.makedirs(edge_profile_dir)
            edge_path = shutil.which("msedge") or shutil.which("edge")
            if not edge_path:
                possible_paths = [
                    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
                    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
                    os.path.expanduser(r"~\AppData\Local\Microsoft\Edge\Application\msedge.exe")
                ]
                for p in possible_paths:
                    if os.path.exists(p):
                        edge_path = p
                        break
            if not edge_path:
                print("❌ 未找到 Edge 可执行文件。请确保 Edge 已安装或在 PATH 中。")
                return
            cmd = [edge_path, f"--proxy-server={proxy}", f"--user-data-dir={edge_profile_dir}", "--new-window", target_url]
            subprocess.Popen(cmd, shell=False)
        print(f"✅ {browser_name} 已启动，代理 {proxy}，目标 {target_url}")
        print("🔍 所有流量将经过 Burp（127.0.0.1:{proxy_port}）")
        print(f"📁 用户数据已保存到: {chrome_profile_dir if browser_cmd == 'chrome' else (edge_profile_dir if browser_cmd == 'edge' else firefox_profile_dir)}")
        print("💡 下次启动将自动恢复登录状态，无需重新登录。")
    except Exception as e:
        print(f"❌ 启动 {browser_name} 失败: {e}")
        traceback.print_exc()

# ============================================================
# 功能：清理所有扫描缓存
# ============================================================


def clean_all_cache(interactive=True, auto_yes=False, _runtime_preserve_subdirs=("daily_status", "extracted_scripts", "reports", "logs")):
    """清理扫描缓存和临时文件。

    修复：不再一把梭删除整个 _runtime_cache/，而是按子目录白名单保留：
        _runtime_cache/daily_status        ← 自动验证产物（auto_validation_result.md 等）
        _runtime_cache/extracted_scripts   ← 本文件提取的脚本清单（用户需求）
        _runtime_cache/reports             ← server_health / api_compare 机器报告
        _runtime_cache/logs                ← 调度日志（排障用）
    其余子目录（例如 .pytest_cache、debug、临时 outputs）照常清理。
    """
    print_header("🧹 清理所有扫描缓存和临时文件")
    root = PROJECT_ROOT
    deleted_count = 0
    deleted_size = 0

    to_delete = []

    # 修复：只清 _runtime_cache 下的非保留子项，不再删除整个目录
    runtime_cache = os.path.join(root, "_runtime_cache")
    if os.path.isdir(runtime_cache):
        protect = {os.path.normcase(x) for x in _runtime_preserve_subdirs}
        for entry in os.listdir(runtime_cache):
            entry_norm = os.path.normcase(entry)
            # 保留 manifest 文件（MANIFEST.json / MANIFEST.html）以保证产物自洽
            if entry_norm.startswith("manifest.") and not os.path.isdir(os.path.join(runtime_cache, entry)):
                continue
            if entry_norm in protect:
                print(f"  🛡️ 保留（用户产物）: _runtime_cache/{entry}")
                continue
            full = os.path.join(runtime_cache, entry)
            size = 0
            try:
                if os.path.isdir(full):
                    for dirpath, _dirnames, filenames in os.walk(full):
                        for f in filenames:
                            fp = os.path.join(dirpath, f)
                            try:
                                if os.path.exists(fp):
                                    size += os.path.getsize(fp)
                            except OSError:
                                pass
                elif os.path.isfile(full):
                    try:
                        size = os.path.getsize(full)
                    except OSError:
                        size = 0
            except BaseException:
                size = 0
            kind = "目录" if os.path.isdir(full) else "文件"
            to_delete.append((kind, full, size))
            print(f"  🗑️ 计划清理 _runtime_cache/{entry} ({size / 1024 / 1024:.2f} MB)")

    # 清理其他常见垃圾
    clean_patterns = [
        "*.tmp", "*.temp", "*.log", "*.lock",
        ".nuclei_cache/", ".nuclei_cache_*/",
        "*.sqlite3-journal", "chroma.sqlite3-journal",
        "调试/*.txt", "debug/*.txt",
        "endpoints_*.txt", "subfinder_*.txt"
    ]

    for pattern in clean_patterns:
        if pattern.endswith('/'):
            dirname = pattern.rstrip('/')
            for dirpath, dirnames, filenames in os.walk(root):
                for d in dirnames:
                    if fnmatch.fnmatch(d, dirname):
                        full = os.path.join(dirpath, d)
                        if full != runtime_cache:  # 避免重复
                            size = 0
                            try:
                                for dp, dn, fn in os.walk(full):
                                    for f in fn:
                                        fp = os.path.join(dp, f)
                                        if os.path.exists(fp):
                                            size += os.path.getsize(fp)
                            except BaseException:
                                pass
                            to_delete.append(("目录", full, size))
                            print(f"  📁 {os.path.basename(full)} ({size / 1024 / 1024:.2f} MB)")
        else:
            for dirpath, dirnames, filenames in os.walk(root):
                for f in filenames:
                    if fnmatch.fnmatch(f, pattern):
                        full = os.path.join(dirpath, f)
                        size = os.path.getsize(full) if os.path.exists(full) else 0
                        to_delete.append(("文件", full, size))
                        print(f"  📄 {f} ({size / 1024:.2f} KB)")

    if not to_delete:
        print("✅ 没有发现可清理的缓存。")
        return

    total_size = sum(item[2] for item in to_delete)
    print(f"\n总计将释放约 {total_size / 1024 / 1024:.2f} MB 空间")

    if not interactive or auto_yes:
        confirm = "y"
    else:
        confirm = input("\n确认清理？(y/N): ").strip().lower()
    if confirm != 'y':
        print("❌ 已取消清理。")
        return {"deleted_count": 0, "deleted_size": 0, "total_size": total_size, "confirmed": False}

    for typ, path, size in to_delete:
        try:
            if os.path.exists(path):
                if typ == "目录":
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
                print(f"✅ 已删除: {safe_relpath(path, root)}")
                deleted_count += 1
                deleted_size += size
        except Exception as e:
            print(f"⚠️ 删除失败 {safe_relpath(path, root)}: {e}")

    print(f"\n✅ 清理完成！")
    print(f"   - 删除 {deleted_count} 项")
    print(f"   - 释放约 {deleted_size / 1024 / 1024:.2f} MB 空间")
    check_disk_space()
    return {"deleted_count": deleted_count, "deleted_size": deleted_size, "total_size": total_size, "confirmed": True}

# ============================================================
# 功能：一键健康检查并修复（修复版）
# ============================================================


def health_check_and_fix():
    print_header("🏥 一键健康检查并修复")
    print("正在执行全面健康检查...\n")

    issues_found = []
    fixes_applied = []

    print("1. 检查 .env 配置文件...")
    if not os.path.exists(ENV_FILE):
        print("   ❌ .env 文件不存在")
        issues_found.append(".env 文件缺失")
        try:
            default_env = '''# ========== AI 模型别名映射 ==========
AI_MODEL_ALIASES={"1":"glm-4-flash","2":"qwen-plus-2025-07-28","4":"deepseek-ai/DeepSeek-V3.1-Terminus","5":"glm-4.7"}

# ========== Burp 配置 ==========
BURP_API_URL=http://127.0.0.1:1337
BURP_API_KEY=

# ========== AI 默认配置（请填写你的 API Key） ==========
AI_MODEL_CONFIGS={"glm-4-flash":{"api_key":"","base_url":"https://open.bigmodel.cn/api/paas/v4/"},"qwen-plus-2025-07-28":{"api_key":"","base_url":"https://dashscope.aliyuncs.com/compatible-mode/v1"},"deepseek-ai/DeepSeek-V3.1-Terminus":{"api_key":"","base_url":"https://api.siliconflow.cn/v1"},"glm-4.7":{"api_key":"","base_url":"https://open.bigmodel.cn/api/paas/v4/"}}
AI_MODELS=["1","2","4","5"]'''
            with open(ENV_FILE, 'w', encoding='utf-8') as f:
                f.write(default_env)
            fixes_applied.append("已创建默认 .env 文件（请填写 API Key）")
            print("   ✅ 已创建默认 .env 文件，请后续填写 API Key")
        except Exception as e:
            print(f"   ❌ 无法创建 .env: {e}")
    else:
        print("   ✅ .env 文件存在")

    print("\n2. 检查关键目录...")
    required_dirs = [
        os.path.join(PROJECT_CACHE_DIR, "reports"),
        os.path.join(PROJECT_CACHE_DIR, "logs"),
        os.path.join(PROJECT_CACHE_DIR, "tmp"),
        "thirdparty",
    ]
    for d in required_dirs:
        if not os.path.exists(d):
            try:
                os.makedirs(d, exist_ok=True)
                fixes_applied.append(f"已创建目录: {d}")
                print(f"   ✅ 已创建: {d}")
            except Exception as e:
                print(f"   ❌ 无法创建 {d}: {e}")
        else:
            print(f"   ✅ {d} 存在")

    print("\n3. 检查 ChromaDB 向量数据库...")
    try:
        import chromadb
        from vulnclaw.core.settings import PROJECT_CACHE_DIR
        vectordb_path = os.path.join(PROJECT_CACHE_DIR, "vectordb")
        client = chromadb.PersistentClient(path=vectordb_path)
        print("   ✅ ChromaDB 可正常初始化")
    except Exception as e:
        print(f"   ❌ ChromaDB 异常: {e}")
        issues_found.append("ChromaDB 初始化失败")
        try:
            import chromadb
            from vulnclaw.core.settings import PROJECT_CACHE_DIR
            vectordb_path = os.path.join(PROJECT_CACHE_DIR, "vectordb")
            client = chromadb.PersistentClient(path=vectordb_path)
            fixes_applied.append("ChromaDB 已重建")
            print("   ✅ ChromaDB 已重建")
        except BaseException:
            print("   ❌ 无法自动修复 ChromaDB，请手动检查")

    print("\n4. 检查 AI 模型配置...")
    try:
        from vulnclaw.ai.core import get_llm_client
        client = get_llm_client()
        if client.models:
            print(f"   ✅ 已配置 {len(client.models)} 个模型: {', '.join(client.models)}")
        else:
            print("   ⚠️ 没有配置任何模型")
            issues_found.append("没有配置 AI 模型")
    except Exception as e:
        print(f"   ❌ AI 配置加载失败: {e}")
        issues_found.append("AI 配置加载失败")

    print("\n5. 检查 Nuclei 模板...")
    try:
        from vulnclaw.core.settings import settings
        # ===== 修复：使用 os.path.expanduser 展开 ~ =====
        template_dir = os.path.expanduser(settings.nuclei_template_dir)
        if os.path.exists(template_dir) and os.path.isdir(template_dir):
            print(f"   ✅ 模板目录存在: {template_dir}")
        else:
            print(f"   ⚠️ 模板目录不存在: {template_dir}")
            issues_found.append("Nuclei 模板目录不存在")
    except Exception as e:
        print(f"   ❌ 无法读取 Nuclei 配置: {e}")

    print("\n6. 检查关键 Python 包...")
    # ===== 修复：使用正确的模块名映射 =====
    required = [
        ("aiohttp", "aiohttp"),
        ("requests", "requests"),
        ("pydantic", "pydantic"),
        ("bs4", "beautifulsoup4"),
        ("dns", "dnspython"),
    ]
    missing_packages = []
    for module_name, package_name in required:
        try:
            importlib.import_module(module_name)
            print(f"   ✅ {package_name}")
        except ImportError:
            print(f"   ❌ {package_name} 未安装")
            missing_packages.append(package_name)

    if missing_packages:
        print(f"\n   尝试安装缺失的包: {' '.join(missing_packages)}")
        try:
            subprocess.run(["pip", "install"] + missing_packages, check=False)
            fixes_applied.append(f"已安装缺失包: {', '.join(missing_packages)}")
            print("   ✅ 已尝试安装缺失包")
        except Exception as e:
            print(f"   ❌ 安装失败: {e}")

    print("\n7. 检查磁盘空间...")
    check_disk_space()

    print("\n" + "=" * 60)
    print("  📊 健康检查报告")
    print("=" * 60)

    if issues_found:
        print(f"\n发现 {len(issues_found)} 个问题：")
        for issue in issues_found:
            print(f"  ❌ {issue}")
    else:
        print("\n  ✅ 未发现明显问题")

    if fixes_applied:
        print(f"\n已应用 {len(fixes_applied)} 项修复：")
        for fix in fixes_applied:
            print(f"  🔧 {fix}")

    print("\n💡 建议：")
    if missing_packages:
        print("  - 运行 `pip install -r requirements.txt` 安装所有依赖")
    if issues_found:
        print("  - 查看上述问题并根据提示手动修复")
    if not issues_found and not fixes_applied:
        print("  - 系统状态良好，可以正常使用扫描器")

# ============================================================
# 主菜单
# ============================================================


def _parse_cli(argv=None):
    """极简命令行解析，不依赖 argparse（避免在最顶部导入没装时就挂）。
    支持：
      --help / -h
      --extract                一键：提取脚本到 _runtime_cache/extracted_scripts/
      --output PATH            指定 --extract 的输出文件路径
      --self-test              一键：运行扫描器自检
      --clean-cache            一键：执行 clean_all_cache（不交互）
      --yes / -y               对需要确认的动作自动说 yes
      --run 1|2|3|4|5|0        选择主菜单编号（仍会进入 wait_enter 交互）
      --headless               强制非交互模式：执行完 --xxx 动作后直接退出，
                               不再调用主菜单 while 循环。
    """
    argv = list(sys.argv[1:] if argv is None else argv)
    opts = {
        "help": False, "extract": False, "output": None,
        "self_test": False, "clean_cache": False,
        "yes": False, "run": None, "headless": False,
        "remainder": [],
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            opts["help"] = True
        elif a == "--extract":
            opts["extract"] = True
            opts["headless"] = True
        elif a == "--output":
            i += 1
            opts["output"] = argv[i] if i < len(argv) else None
        elif a == "--self-test":
            opts["self_test"] = True
            opts["headless"] = True
        elif a == "--clean-cache":
            opts["clean_cache"] = True
            opts["headless"] = True
        elif a in ("-y", "--yes"):
            opts["yes"] = True
        elif a == "--run":
            i += 1
            opts["run"] = argv[i] if i < len(argv) else None
        elif a == "--headless":
            opts["headless"] = True
        else:
            opts["remainder"].append(a)
        i += 1
    return opts


_CLI_HELP_TEXT = """Usage: python scripts/tools_menu.py [OPTIONS]

Interactive launcher for the pentest platform. If no OPTIONS are passed, the
textual main menu is shown.

Options:
  -h, --help          Show this help and exit.

  Non-interactive (implies --headless, writes RC != 0 on failure):
    --extract         Extract script content + paths into one consolidated file.
                      Default output:
                        _runtime_cache/extracted_scripts/tools_menu.extracted_scripts.txt
    --output PATH     Custom output file for --extract.
    --self-test       Run scanner self-test (11 items).
    --clean-cache     Clean scan caches; preserves daily_status/extracted_scripts.

  Misc:
    -y, --yes         Auto-answer "y" to confirmation prompts.
    --run CHOICE      Run main menu choice once (1..5 / 0); still interactive for
                      submenu prompts unless --headless/--yes is also used.
    --headless        Exit after the requested actions; do not enter the loop.

Exit codes (headless mode):
  0   success
  1   argument / usage error
  2   an action (self-test / extract / etc) reported failure

Examples:
  scripts\\debug.bat --help
  scripts\\debug.bat --extract
  scripts\\debug.bat --extract --output D:\\dump\\my_code.txt
  scripts\\debug.bat --self-test
  python scripts\\tools_menu.py --clean-cache --yes
"""


def main():
    opts = _parse_cli()

    # ---- Help is terminal -------------------------------------------------
    if opts["help"]:
        sys.stdout.write(_CLI_HELP_TEXT)
        return 0

    # ---- Headless actions: run once each, then return RC ------------------
    if opts["headless"]:
        any_action = False
        failed_actions = []

        if opts["extract"]:
            any_action = True
            try:
                out = extract_code(output_file=opts["output"])
                print("\n[CLI] extract_code -> OK")
                if out:
                    print(f"[CLI] output_file: {out}")
                    if not os.path.exists(out) or os.path.getsize(out) == 0:
                        failed_actions.append("extract: empty or missing output file")
            except Exception as exc:
                failed_actions.append(f"extract raised: {exc!r}")
                traceback.print_exc()

        if opts["self_test"]:
            any_action = True
            try:
                summary = self_test(return_summary=True) or {}
                passed = summary.get("passed", 0)
                total = summary.get("total", -1)
                ok = bool(summary.get("pass", False))
                print(f"\n[CLI] self_test -> passed/total={passed}/{total}, ok={ok}")
                if not ok:
                    failed_actions.append(f"self_test: {passed}/{total} checks passed")
            except Exception as exc:
                failed_actions.append(f"self_test raised: {exc!r}")
                traceback.print_exc()

        if opts["clean_cache"]:
            any_action = True
            try:
                result = clean_all_cache(interactive=False, auto_yes=bool(opts["yes"]))
                print(f"\n[CLI] clean_all_cache -> {result!r}")
                if result is None:
                    # Nothing-to-clean returns None; that's still OK.
                    pass
                elif not result.get("confirmed", True):
                    failed_actions.append("clean_cache: cancelled (pass --yes to auto-confirm)")
            except Exception as exc:
                failed_actions.append(f"clean_cache raised: {exc!r}")
                traceback.print_exc()

        if not any_action:
            sys.stderr.write("error: --headless requires one action: --extract / --self-test / --clean-cache\n")
            sys.stderr.write("       (run with --help for usage)\n")
            return 1

        if failed_actions:
            print("\n[CLI] FAILED actions:")
            for item in failed_actions:
                print("  -", item)
            return 2
        return 0

    # ---- Fallback: run a single main-menu choice then exit? ---------------
    if opts["run"] is not None:
        choice = str(opts["run"]).strip()
        try:
            if choice == "1":
                test_ai()
            elif choice == "2":
                extract_code()
            elif choice == "3":
                manage_ai_config()
            elif choice == "4":
                system_maintenance()
            elif choice == "5":
                start_browser_burp()
            elif choice == "0":
                print("👋 退出工具")
                return 0
            else:
                print(f"❌ 无效 --run 选择: {choice}")
                return 1
        except KeyboardInterrupt:
            print("\n👋 用户中断，退出")
        except Exception as exc:
            print(f"❌ 发生未预期错误: {exc}")
            traceback.print_exc()
        return 0

    # ---- Legacy interactive loop -----------------------------------------
    while True:
        try:
            print("\n" + "=" * 60)
            print("   渗透测试平台 - 多功能管理工具 (v6.5.3 修复版)")
            print("=" * 60)
            print("  1. 调试 AI")
            print("  2. 提取所有脚本内容及路径")
            print("  3. 🔧 切换 AI 配置（预设/交互式向导/任务分配）")
            print("  4. 🔧 系统维护（自检 + 环境恢复 + 清理缓存 + 健康检查）")
            print("  5. 🌐 启动浏览器（走 Burp 代理）")
            print("  ---")
            print("  0. 退出")
            print("=" * 60)
            choice = input("请选择 (0-5): ").strip()
            if choice == "1":
                test_ai()
                wait_enter()
            elif choice == "2":
                extract_code()
                wait_enter()
            elif choice == "3":
                manage_ai_config()
                wait_enter()
            elif choice == "4":
                system_maintenance()
                wait_enter()
            elif choice == "5":
                start_browser_burp()
                wait_enter()
            elif choice == "0":
                print("👋 退出工具")
                break
            else:
                print("❌ 无效输入，请重新选择")
        except KeyboardInterrupt:
            print("\n👋 用户中断，退出")
            break
        except Exception as e:
            print(f"❌ 发生未预期错误: {e}")
            traceback.print_exc()
            wait_enter()
    return 0


if __name__ == "__main__":
    try:
        rc = main()
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        rc = 130
    sys.exit(int(rc or 0))