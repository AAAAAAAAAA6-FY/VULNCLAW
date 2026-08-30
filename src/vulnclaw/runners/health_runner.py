# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""健康检查 runner（R2 拆分自 scan_main.py）。"""

import os
import sys
from pathlib import Path

from vulnclaw.config import PROJECT_CACHE_DIR, settings
from vulnclaw.paths import PROJECT_ROOT as _PROJECT_ROOT_DIR

def run_health_check() -> int:



    """健康检查：Python/工具二进AI Provider/配置/缓存目录，输出汇总并返回退出码







    退出码 = 全部关键项正常（可选项缺失不扣分） = 存在关键项异常



    """



    from vulnclaw.core.utils import get_tool_path







    print("=" * 70)



    print("🏥 pentest_platform 健康检")



    print("=" * 70)







    issues = []  # 关键异常项（影响退出码



    optional_missing = []  # 可选缺失项（仅提示







    # ---------- 1. 运行环境 ----------



    print("\n[1/5] 运行环境")



    print(f"   Python: {sys.version.split()[0]} ({sys.platform})")



    print(f"   项目 {_PROJECT_ROOT_DIR}")







    # ---------- 2. 第三方工具二进制 ----------



    print("\n[2/5] 第三方工具（缺失自动降级，非阻断")



    tools = [



        ("nuclei", "CVE 模板扫描"),



        ("ffuf", "目录爆破"),



        ("subfinder", "子域名收"),



        ("interactsh-client", "OOB 带外检"),



        ("arjun", "隐藏参数发现"),



        ("sqlmap", "SQL 注入深度验证"),



    ]



    for tool, usage in tools:



        path = get_tool_path(tool)



        if path:



            print(f"   {tool:<18s} {usage:<14s} -> {path}")



        else:



            optional_missing.append(f"{tool}（{usage}")



            print(f"   ⚠️ {tool:<18s} {usage:<14s} -> 未找到（该能力将跳过/降级")








    # ---------- 3. AI Provider 配置 ----------



    print("\n[3/5] AI Provider（关键项")



    try:



        from vulnclaw.ai.core import get_llm_client



        client = get_llm_client()



        models = getattr(client, "models", []) or []



        if models:



            print(f"   AI 模型已配 {len(models)} -> {', '.join(str(m) for m in models[:5])}")



            # provider 检api_key 是否为空



            configs = getattr(settings, "ai_model_configs", {}) or {}



            empty_keys = [name for name, cfg in configs.items()



                          if isinstance(cfg, dict) and not (cfg.get("api_key") or "").strip()]



            if empty_keys:



                for name in empty_keys:



                    issues.append(f"AI 模型 {name} api_key 为空")



                    print(f"   ⚠️ {name}: api_key 为空，调用将失败")



            else:



                print(f"   各模api_key 均已配置（{len(configs)} provider")




        else:



            from vulnclaw.ai.core import get_configured_ai_models
            if not get_configured_ai_models():
                print("   纯引擎模式（AI_MODE=0）：AI 未启用，扫描将跳过 AI 增强")
            else:
                issues.append("未配置任AI 模型（检.env AI_MODELS")
                print("   未配AI 模型：请.env 配置 AI_MODELS / AI_MODEL_CONFIGS，或运行 tools_menu.py 导向")







    except Exception as e:



        issues.append(f"AI 配置加载失败: {e}")



        print(f"   AI 配置加载失败: {e}")







    # ---------- 4. Nuclei 模板 ----------



    print("\n[4/5] Nuclei 模板（缺失时 CVE 扫描降级")



    try:



        template_dir = getattr(settings, "nuclei_template_dir", "")



        if template_dir and os.path.isdir(template_dir):



            print(f"   模板目录: {template_dir}")



        else:



            optional_missing.append("nuclei 模板目录")



            print(f"   ⚠️ 模板目录不存 {template_dir or '(未配'}")



    except Exception as e:



        optional_missing.append("nuclei 模板目录")



        print(f"   ⚠️ 模板目录检查异 {e}")







    # ---------- 5. 缓存目录 ----------



    print("\n[5/5] 运行时缓存目")



    try:



        for sub in ["logs", "reports", "cookies"]:



            d = Path(PROJECT_CACHE_DIR) / sub



            d.mkdir(parents=True, exist_ok=True)



        print(f"   {PROJECT_CACHE_DIR}{{logs,reports,cookies}} 就绪")



    except Exception as e:



        issues.append(f"缓存目录创建失败: {e}")



        print(f"   缓存目录创建失败: {e}")







    # ---------- 汇----------



    print("\n" + "=" * 70)



    if issues:



        print(f"健康检查未通过：{len(issues)} 个关键问")




        for msg in issues:



            print(f"   - {msg}")



    else:



        print("健康检查通过（关键项全部正常")



    if optional_missing:


        print(f"ℹ️  可选能力缺失（{len(optional_missing)} 项）：对应步骤会自动降级或跳过。")
        print(f"   一键补齐：  python scan.py setup --download-thirdparty")
        print(f"   详情: {', '.join(optional_missing)}")



    print("=" * 70)



    return 1 if issues else 0
