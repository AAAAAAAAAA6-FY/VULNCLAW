# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

"""代码审计 runner（R2 拆分自 scan_main.py）。

run_code_audit 函数体内部自带延迟 import（time/Path/PROJECT_CACHE_DIR/
generate_html_report/traceback），模块头仅保留函数体全局引用。
"""

import datetime
import json
import os

async def run_code_audit(args):



    """Sprint 2: 代码安全审计工作流（Semgrep + CodeQL + 依赖扫描 + AI 审计 + 报告）"""



    import time



    from pathlib import Path



    from vulnclaw.config import PROJECT_CACHE_DIR



    from vulnclaw.core.report_generator import generate_html_report







    start_time = time.time()



    report_dir = Path(PROJECT_CACHE_DIR) / "reports"



    report_dir.mkdir(parents=True, exist_ok=True)



    deep_dev_dir = Path(PROJECT_CACHE_DIR) / "deep_dev"



    deep_dev_dir.mkdir(parents=True, exist_ok=True)



    patches_dir = report_dir / "patches"



    patches_dir.mkdir(parents=True, exist_ok=True)







    code_arg = getattr(args, 'code', False)



    repo_url = getattr(args, 'repo', None) or (code_arg if isinstance(code_arg, str) else None) or "https://github.com/Anon-Artist/vulnpy.git"



    lang = getattr(args, 'lang', 'python')



    # 兼容 Windows 绝对路径（如 c:\path\to\repo）与 Git URL



    target_name = repo_url.rstrip('/').rstrip('\\').split('/')[-1].split('\\')[-1].replace('.git', '')



    if not target_name or target_name in ('.', '..'):



        target_name = 'repo'







    print("=" * 70)



    print("🔍 Sprint 2 代码安全审计启动")



    print("=" * 70)



    print(f"目标仓库: {repo_url}")



    print(f"语言: {lang}")



    print("")







    findings = []



    codeql_findings = []



    dep_findings = []



    diffs = []



    filtered = []



    errors = []



    repo_path = None



    semgrep_findings_count = 0







    # Step 1: 克隆仓库



    try:



        from vulnclaw.code.repo_manager import get_repo_manager



        mgr = get_repo_manager()



        repo_path = await mgr.clone_repo(repo_url)



        print(f"仓库克隆完成: {repo_path}")



    except Exception as e:



        errors.append(f"仓库克隆失败: {e}")



        print(f"仓库克隆失败: {e}")



        import traceback



        traceback.print_exc()







    # Step 2: Semgrep 扫描



    if repo_path:



        try:



            from vulnclaw.code.engines.semgrep_adapter import SemgrepAdapter



            adapter = SemgrepAdapter(config="auto", timeout=300)



            rulesets = ['p/python', 'p/flask', 'p/secrets', 'p/command-injection']



            for ruleset in rulesets:



                print(f"🔍 Semgrep 扫描规则 {ruleset} ...")



                batch = await adapter.scan(repo_path, rules=ruleset)



                findings.extend(batch)



            semgrep_findings_count = len(findings)



            print(f"Semgrep 扫描完成: {len(findings)} 个发")




        except Exception as e:



            errors.append(f"Semgrep 扫描失败: {e}")



            print(f"Semgrep 扫描失败: {e}")



            import traceback



            traceback.print_exc()







    # Step 2.5: CodeQL 扫描（二进制缺失时警告并跳过，结果与 Semgrep 合并后统一AI 审计



    if repo_path:



        try:



            from vulnclaw.core.utils import get_tool_path



            codeql_bin = get_tool_path("codeql")



            if codeql_bin is None:



                print("⚠️ CodeQL 未安装（未找codeql 二进制），跳CodeQL 扫描")



                errors.append("CodeQL 未安装（未找codeql 二进制），已跳过")



            else:



                from vulnclaw.code.engines.codeql_adapter import CodeQLAdapter



                codeql = CodeQLAdapter(language=lang)



                codeql_results = await codeql.scan(repo_path)



                findings.extend(codeql_results)



                codeql_findings = codeql_results



                print(f"CodeQL 扫描完成: {len(codeql_results)} 个发现（累计 {len(findings)} 个）")



        except Exception as e:



            errors.append(f"CodeQL 扫描跳过: {e}")



            print(f"⚠️ CodeQL 扫描跳过: {e}")



            import traceback



            traceback.print_exc()







    # Step 3: 依赖扫描



    dep_findings = []



    if repo_path:



        try:



            from vulnclaw.code.dependency_scanner import DependencyScanner



            ds = DependencyScanner(timeout=120)



            dep_findings = await ds.audit_dependencies(repo_path)



            print(f"依赖扫描完成: {len(dep_findings)} CVE")



        except Exception as e:



            errors.append(f"依赖扫描失败: {e}")



            print(f"依赖扫描失败: {e}")



            import traceback



            traceback.print_exc()







    # Step 4: AI 审计



    if findings:



        try:



            from vulnclaw.code.ai_auditor import AIAuditor



            auditor = AIAuditor(batch_size=5)



            source_map = {}



            if repo_path:



                for root, _, files in os.walk(repo_path):



                    for fname in files:



                        if fname.endswith('.py'):



                            fpath = os.path.join(root, fname)



                            try:



                                with open(fpath, 'r', encoding='utf-8', errors='ignore') as f:



                                    source_map[os.path.relpath(fpath, repo_path)] = f.read()



                            except Exception:



                                pass



            filtered, diffs = await auditor.audit_findings(findings, source_code_map=source_map)



            print(f"AI 审计完成: 有效={len(filtered)} 误报={len(findings)-len(filtered)} 修复建议={len(diffs)}")



        except Exception as e:



            errors.append(f"AI 审计失败: {e}")



            print(f"AI 审计失败: {e}")



            import traceback



            traceback.print_exc()



            filtered = findings



            diffs = []







    # Step 5: 保存 patch



    patch_files = []



    for i, d in enumerate(diffs[:20], 1):



        patch_name = f"{i:03d}_{d.get('rule_id', 'fix').replace('.', '_')}.patch"



        patch_path = patches_dir / patch_name



        try:



            original = d.get('original', '')



            suggested = d.get('suggested_fix', '')



            file_path = d.get('file', '')



            diff_content = f"--- a/{file_path}\n+++ b/{file_path}\n@@ -1 +1 @@\n-{original}\n+{suggested}\n"



            with open(patch_path, 'w', encoding='utf-8') as f:



                f.write(diff_content)



            patch_files.append(str(patch_path))



        except Exception as e:



            errors.append(f"Patch 保存失败: {e}")







    # Step 6: 生成报告



    elapsed = round(time.time() - start_time, 2)



    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')



    report_data = {



        "target": repo_url,



        "repo_path": repo_path,



        "scan_time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),



        "elapsed_seconds": elapsed,



        "language": lang,



        "semgrep_findings_count": semgrep_findings_count,



        "codeql_findings_count": len(codeql_findings),



        "dependency_findings_count": len(dep_findings),



        "ai_filtered_count": len(filtered),



        "ai_diffs_count": len(diffs),



        "patch_files": patch_files,



        "errors": errors,



        "vulnerabilities": filtered + dep_findings,



        "summary": {



            "critical": len([v for v in filtered if v.get('severity') == 'ERROR']),



            "high": len([v for v in filtered if v.get('severity') == 'WARNING']),



            "medium": len([v for v in filtered if v.get('severity') == 'INFO']),



            "low": 0,



            "info": 0,



        }



    }







    json_path = report_dir / f"code_audit_{target_name}_{timestamp}.json"



    with open(json_path, 'w', encoding='utf-8') as f:



        json.dump(report_data, f, indent=2, ensure_ascii=False, default=str)



    print(f"📄 JSON 报告: {json_path}")







    try:



        html_path = json_path.with_suffix('.html')



        generate_html_report(report_data, str(html_path))



        print(f"📄 HTML 报告: {html_path}")



    except Exception as e:



        print(f"⚠️ HTML 报告生成失败: {e}")







    # Step 7: 执行报告



    exec_report_path = deep_dev_dir / "code_audit_execution_report.md"



    with open(exec_report_path, 'w', encoding='utf-8') as f:



        f.write("# 代码审计实战验证执行报告\n\n")



        f.write(f"- **扫描目标**: {repo_url}\n")



        f.write(f"- **扫描时间**: {report_data['scan_time']}\n")



        f.write(f"- **耗时**: {elapsed} 秒\n")



        f.write(f"- **Semgrep 发现*: {semgrep_findings_count}\n")



        f.write(f"- **CodeQL 发现*: {len(codeql_findings)}\n")



        f.write(f"- **依赖 CVE *: {len(dep_findings)}\n")



        f.write(f"- **AI 过滤后有效漏*: {len(filtered)}\n")



        f.write(f"- **生成修复 diff *: {len(diffs)}\n")



        f.write(f"- **Patch 文件**: {len(patch_files)} 个\n")



        f.write(f"- **错误**: {len(errors)} 个\n")



        if errors:



            f.write("\n## 错误明细\n")



            for err in errors:



                f.write(f"- {err}\n")



        f.write("\n## 验收结论\n")



        if len(filtered) >= 3 and len(diffs) >= 3:



            f.write("**通过**: 有效漏洞  且修diff \n")



        else:



            f.write("**未通过**: 有效漏洞或修diff 不足\n")



    print(f"📄 执行报告: {exec_report_path}")







    # 保存完整日志



    full_log_path = deep_dev_dir / "code_audit_full_log.txt"



    with open(full_log_path, 'w', encoding='utf-8') as f:



        f.write(f"代码审计完整日志\n目标: {repo_url}\n耗时: {elapsed}s\n")



        f.write(f"Semgrep: {semgrep_findings_count}\nCodeQL: {len(codeql_findings)}\n")



        f.write(f"CVE: {len(dep_findings)}\n有效: {len(filtered)}\nDiff: {len(diffs)}\n")







    print("\n" + "=" * 70)



    print("📊 代码审计结果")



    print("=" * 70)



    print(f"   ⏱️ 耗时: {elapsed} ")




    print(f"   🔍 Semgrep 发现: {semgrep_findings_count} ")




    print(f"   🔬 CodeQL 发现: {len(codeql_findings)} ")




    print(f"   📦 依赖 CVE: {len(dep_findings)} ")




    print(f"   🤖 AI 有效漏洞: {len(filtered)} ")




    print(f"   🔧 修复 diff: {len(diffs)} ")




    print(f"   📝 Patch 文件: {len(patch_files)} ")




    if errors:



        print(f"   ⚠️ 错误: {len(errors)} ")




    print("=" * 70)



    print("代码审计完成")

    # 结构化摘要落盘：供 MCP / 外部程序读取（CLI 仍返回 exit code，不受影响）
    try:
        summary_path = report_dir / "code_audit_summary.json"
        with open(summary_path, "w", encoding="utf-8") as _sf:
            json.dump({
                "repo": repo_url,
                "lang": lang,
                "elapsed_seconds": elapsed,
                "semgrep": semgrep_findings_count,
                "codeql": len(codeql_findings),
                "dependency_cve": len(dep_findings),
                "ai_validated": len(filtered),
                "fix_diffs": len(diffs),
                "patch_files": [str(p) for p in patch_files] if patch_files else [],
                "errors": errors,
            }, _sf, ensure_ascii=False, indent=2, default=str)
        print(f"   📄 摘要文件: {summary_path}")
    except Exception as _e:  # noqa: BLE001
        print(f"   ⚠️ 摘要写入失败: {_e}")



    print("=" * 70)







    if repo_path:



        try:



            from vulnclaw.code.repo_manager import get_repo_manager



            get_repo_manager().cleanup()



        except Exception:



            pass







    return 0
