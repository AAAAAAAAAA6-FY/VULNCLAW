# VULNCLAW 工作交接（2026-09-11）

> 给另一边 AI 的交接：本会话已做 / 剩余 / 坑位。状态：4/5 任务完成。

## 状态
声明驱动漏洞引擎 + local_lab 靶场 + e2e/单测全绿；公开仓备份已推送。仅 Web 前端未做。

## 已完成

### #1 测试框架 + local_lab 靶场（方案 C，无 Docker）
- `scripts/local_lab.py`：监听 127.0.0.1:8090，端点 xss/sqli/ssti/lfi/cmdi/nosql/ldap/deser/.env/redirect/cors/upload，内置 `EXPECTED_FINDINGS` 基准（含 negatives 用于误报校验）。
- `tests/test_vulnspec.py`：声明引擎单测，当前 **15 例全 PASS**。

### #5 声明驱动漏洞引擎
- `src/vulnclaw/core/vulnspec/builtin.py`：新增/完善声明（xss_reflect / sql_error / ssti / nosql_injection / ldap_injection / open_redirect / cors_misconfig / java_deserialization …），含 payloads / detect / param_hints / severity / cvss / remediation。
- 接入 `SpecRunner`：`SpecRunner.run(spec_from_url(url))` 对 URL 跑声明；e2e + 单测均 PASS。

### #4 local_lab 检出率复测
- 完整 scan 对本地靶机过重（卡在信息收集/目录爆破），改用轻量声明线代理复测（`SpecRunner.run` 直对端点，绕过 AI 编排）。
- 结果 **8/8 命中**（xss / sqli / ssti / nosql / ldap / redirect / cors / deser）；`/.env` + `/upload` 无对应声明（NA，属覆盖度非回归）。
- **关键修复**：`builtin.py` 的 `ldap_injection.detect` 漏认 `invalid search filter syntax`（local_lab 实际返回 `LDAPException: invalid search filter syntax`），已补 `r"search filter syntax"` 模式，消灭单点 FN（复测 7/8 → 8/8）。
- 声明单测 15 PASS 确认修复无回归；bench（`scripts/benchmark.py`）用户要求跳过，此前轮次 `BENCH=0` 无回归。

### #2 公开仓备份
- 已推送分支 `opt/deepseek-review-v2` 到 GitHub（thirdparty 为子模块，不入主仓）。

## 改动文件
- `src/vulnclaw/core/vulnspec/builtin.py`（声明 + LDAP oracle 修复）
- `scripts/local_lab.py`（靶场）
- `tests/test_vulnspec.py`（单测）
- 其余 #5 引擎接入改动见 `git diff` vs main

## 剩余

### #3 Web 前端（pending）
- 用户明确暂不做（"除前端外都推进"）。UI 路线见 `MEMORY.md`：状态总线 → TUI → 开源清洗 → Web 仪表盘 → Tauri 桌宠；官方不做任何设计，只做皮肤平台层（加载器 + manifest + 热插拔 + 无角色纯色占位块）。

### 待提交
- `builtin.py` 的 LDAP 修复尚未 commit/push（在 #2 推送之后产生），需确认是否并入 `opt/deepseek-review-v2`。

## 给另一边 AI 的坑（避免重蹈）
- PowerShell `-c` 传中文/引号会吞字节 → 用 `[System.IO.File]::WriteAllText(.., [System.Text.Encoding]::UTF8)` 写临时 UTF-8 文件再跑，跑完即删。
- 没有 `get_all_specs`，用 `get_spec(sid)`。
- 完整 scan 对本地靶机过重，复测用声明线代理（直 `SpecRunner.run`），别硬跑全量。
- bench 慢，可后置；声明单测快且够用。
- 控制台 GBK 勿用 emoji；git 含 `${}` 的提交用 `--file=`。
- 扫描器入口 `scan.py → src/vulnclaw`；测试用 `venv/Scripts/python.exe`；import 须指向当前 `src`（防 .pth 影子副本劫持）。

## 验证（接手用）
```powershell
venv\Scripts\python -m pytest tests/test_vulnspec.py -q          # 期望 15 passed
# 起靶机：python scripts/local_lab.py   （监听 8090）
# 声明线复测：SpecRunner.run 对
#   /xss?q=  /sqli?id=1  /ssti?name=  /nosql?q=1
#   /ldap?user=admin  /redirect?next=home  /cors  /deser?data=x
# → 期望 8/8 全命中
```
