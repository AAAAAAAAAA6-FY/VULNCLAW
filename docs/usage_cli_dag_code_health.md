# VULNCLAW CLI 速查：scan / code / health + DAG / 多 Agent / 多目标 / 守卫开关

> 最后更新：2026-08-30（v103 src-layout + P2 代码审计入口三合一 + pyproject CLI 打包）。
>
> 两份等价入口：
> - 推荐子命令形式：`vulnclaw scan|code|health ...`（已实测可用：`pip install -e .` 后 console_scripts 注册成功，`vulnclaw --help` / `health` / `scan --help` / `code --help` 均正常）
> - 稳定兼容形式：`python scan.py [scan|code|health] ...`（不带子命令前缀也可：`python scan.py -t URL --dag --agents 6` 与 `python scan.py scan -t URL --dag --agents 6` 等价）
> - 代码审计独立入口：`python scan.py code --repo PATH --lang python`（**唯一入口**；旧 `src/vulnclaw/code_audit*.py` 已删除，不应再被调用）

---

## 1. 总览：3 个子命令 + 2 个兼容入口

| 子命令 | 作用 | 最少需要的参数 | 退出码（0=成功） |
| --- | --- | --- | --- |
| `scan` | 启动 URL 扫描（侦察 → 任务生成 → 攻击 → 验证 → 报告） | `-t/--target URL` | `0` |
| `code` | 代码审计（Python/Go/JS/Java…），产出 JSON + HTML 报告 | `--repo REPO_OR_DIR` + `--lang LANG` | `0`（工具未安装会降级，非致命） |
| `health` | 配置/依赖/三方工具/目录结构 健康检查 | （无） | `0`（见 §6 列表） |

兼容模式：当 `argv[0]` 不是 `scan/code/health` 时，`vulnclaw.cli.main()` 会把参数**原样**转发给旧的 `scan_main.main()`，所以以下命令**100% 等价**：

```powershell
# 写法 A：子命令（推荐，显式）
python scan.py scan -t http://testphp.vulnweb.com --dag --agents 6

# 写法 B：兼容（与 v100 时代的扫描脚本行为一致）
python scan.py -t http://testphp.vulnweb.com --dag --agents 6
```

---

## 2. `scan`：完整参数表

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-t / --target` | `str` | **必填** | 目标 URL；允许 `http://` / `https://`，尾斜杠可选，最终都会被统一为 `scheme://netloc` 的 target_key。 |
| `-l / --target-list` | `str` | 未设置 | **多目标批量扫描**（`multi_target_context.py` 的上下文隔离）：指向一个 txt 文件，每行一个 URL；若同时指定 `-t`，`-t` 与 `-l` 中的 URL 会合并去重。 |
| `--initial-qps` | `int` | `3`（DAG 模式内部会提升到 `6`，见下方） | 起始最大每秒请求数；adaptive_concurrency 在侦察/攻击中会按 429/503 退避与回升。 |
| `--max-tasks` | `int` | `200` | 单目标 `V100Orchestrator` 最大生成任务数，防止超大目标的无限任务爆炸。 |
| `--dag` | `store_true` | `False` | ✅ **启用 DAG 调度**：扫描阶段按 DAG 节点（recon_sub/recon_alive/recon_nuclei/recon_js/recon_port/recon_ffuf → static → attack → verify → report）并行执行；**不开启则沿用 V100 内部串行步骤**。 |
| `--agents` | `int` | `3`（若 `--dag` 开启才生效） | ✅ **DAG 并行度（AgentPool 大小）**：实测 `--agents 6` 时，recon 5 子节点可在 1s 内同时进入 RUNNING；并发峰值受 `ResourceGovernor(llm≤7, nuclei≤2, ffuf≤4)` 二次保护。 |
| `--deep` | `store_true` | `False` | 深度模式（Sprint3 引入，对应 `test_sprint3.py::test_deep_arg_in_help`）：额外启用 collectors 静态端点迭代 / 更细的 ffuf 字典 / 更多 AI 任务分配轮次。 |
| `--dangerous` | `store_true` | `False` | ⚠️ **危险模式开关（Sprint4）**：默认 **严格关闭**。需同时满足 (1) `.env:DANGEROUS_MODE=true` 或命令行 `--dangerous`，(2) 确认「对目标有合法授权」后才会解锁：高破坏性引擎、交互式 payload、长耗时字典爆破、Broken Access Control 的垂直权限提升、Spring Actuator 上传利用等。**未授权目标请永远不要启用**。 |
| `--proxy` | `str` | 未设置 | HTTP/HTTPS 代理（`http://127.0.0.1:8080`）；会同步写入全局 requests Session + aiohttp trace_configs + 子进程 env。 |
| `--no-cookie` | `store_true` | `False` | 跳过「本机浏览器 Cookie → CookieManager 注入」「Burp 插件载入」步骤；目标需要登录态时不要加此参数。 |

### 2.1 DAG Dashboard 观察方法（`--dag --agents N` 必看）
- 每 5 秒打印一次 `[DAG Dashboard] [TICK]` 日志行。
- 关键字段：`nodes_done / nodes_running / nodes_failed / agents_active / agents_peak / resources{llm,nuclei,ffuf}`。
- 最终报告 JSON 中新增 `dag_profile[]`：每个节点 `id / duration_seconds / status / submitted_at / finished_at`；`scan.py` 额外打印 `slowest_3_nodes`（用于定位优化点，如之前 attack 节点 311s→已通过 parallel engine bundle + QPS 提升降到 ~150s 区间）。

### 2.2 DAG 模式下 `--initial-qps` 的特殊说明
DAG `attack` 节点装配 `V100Orchestrator` 时，将 `ai/v100/phases/phases_executor.py` 的 bundle 并行打开，并把 `initial_qps` 从 3 拉到 `6`（提升 AI 阶段吞吐）。**这是有意为之的差异化**：DAG 已经把"侦察期高 I/O、攻击期高 LLM"拆开了，所以攻击期放开不会造成侦察被饿死。若你希望保持保守，手动 `--initial-qps 3` 显式写即可覆盖。

---

## 3. `code`：代码审计参数表（入口三合一，唯一入口）

> P2（2026-08-30 完成）：删除了 3 处重复入口（`code_audit_runner.py`、`src/vulnclaw/code_audit.py`、`src/vulnclaw/code_audit_standalone.py`）；真正实现只剩 `vulnclaw.scan_main.run_code_audit(args)`，守卫测试 `tests/test_layout_guard.py::test_no_standalone_code_audit_runner` 会强制校验 `src/vulnclaw/code_audit*.py` 数量必须为 0。

| 参数 | 类型 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--repo` | `str` | **必填** | 支持两类：① **远程 git URL**（`https://github.com/.../... .git`，未带 `.git` 也会尝试 clone）；② **本地绝对/相对目录**（`code/repo_manager.py:clone_repo` 会优先识别 `Path(args.repo).is_dir`，走 symlink 或降级复制，避免不必要的 clone）。 |
| `--lang` | `str` | `python` | `python / go / js / java / dotnet / php / ruby` 之一（非以上值会被扫描器默认兜底，但规则集可能不匹配）。 |

### 3.1 常用命令（可直接复制）

```powershell
# 1) 本地项目做 Python 代码审计（避免外网拉，最快回归）
python scan.py code --repo .\src\vulnclaw\code --lang python

# 2) 远程 Git URL 审计（需要外网 + 目标服务可用）
python scan.py code --repo https://github.com/Anon-Artist/vulnpy.git --lang python
```

### 3.2 典型输出解读（before/after diff 时用来过滤非差异行）
- 报告 3 份：`_runtime_cache/reports/code_audit_<repo>_<YYYYMMDD_HHMMSS>.json` + 同名 `.html` + `_runtime_cache/deep_dev/code_audit_execution_report.md`。
- 汇总 8 项：`耗时 / Semgrep findings / CodeQL findings / CVE / AI findings / 修复建议 diffs / Patch files / 错误数`。
- 常见**可预期降级**（不属于 P2 失败）：
  - `Semgrep 未安装（OSError WinError 2）` → `RuntimeError: semgrep 未安装...`，进入 `errors[]`。
  - `CodeQL 未安装（未找到 codeql 二进制）` → 跳过，进入 `errors[]`。

---

## 4. `health`：健康检查（零参数，运行时不会发起任何真实扫描）

输出分 5 段：`环境/AI/第三方工具/目录/降级说明`，末尾打印 `=== HEALTH OK ===` 或 `=== HEALTH FAIL ===` + 统计 `OK/FAIL/DEGRADED/SKIP`。

```powershell
python scan.py health
# 或
python scan.py --health
```

### 4.1 常见 DEGRADED（不会退出非 0，但建议修复）
- `arjun 未安装`（PATH 中未解析到路径，缺失仅影响部分 HTTP 参数发现，不阻塞）。
- `nuclei templates 目录缺失`（health 在若干常见位置查找 nuclei-templates，建议设置 `NUCLEI_TEMPLATE_DIR=thirdparty/nuclei-templates`，本仓库已有该子目录，只需在 `.env` 取消注释即可生效）。

---

## 5. 子命令矩阵（速查）

| 场景 | 命令（推荐复制行） |
| --- | --- |
| 常规扫描（单目标，串行 V100） | `python scan.py -t https://target.example` |
| DAG + 6 并发（推荐生产） | `python scan.py -t http://testphp.vulnweb.com --dag --agents 6` |
| DAG + 6 并发 + 深度模式 | `python scan.py -t <URL> --dag --agents 6 --deep` |
| 批量多目标（每行一个 URL，上下文隔离） | `python scan.py -l .\targets.txt --dag --agents 6` |
| 代码审计（本地 Python 项目） | `python scan.py code --repo .\src\vulnclaw\code --lang python` |
| 健康检查 | `python scan.py health` |
| 带代理 + 跳过 Cookie 注入（无痕测试） | `python scan.py -t <URL> --proxy http://127.0.0.1:8080 --no-cookie` |
| ⚠️ **授权前提下**打开危险模式（破坏性 payload 解锁） | `python scan.py -t <AUTHORIZED_TARGET> --dangerous` |

---

## 6. 与「测试守卫」的联动（避免你手工跑半天发现是守卫规则问题）

- 跑测试前确保 `PYTHONDONTWRITEBYTECODE=1`（`tests/test_layout_guard.py` 已经顶部 + autouse 双保险）。
- 若 `test_layout_guard.py::test_no_runtime_cache_or_pycache_in_src` 偶发红：先跑一次 `Remove-Item -Recurse -Force src\vulnclaw\__pycache__`（layout guard 已经自动 purge 1 次，py3.14+pytest9 的启动顺序竞争仍可能触发）。
- 若 `test_code_arg_default_false / test_deep_arg_in_help / test_dangerous_arg_in_help` 在你本机 Python 3.14+pytest 9 上出现 `OSError: [WinError 6] 句柄无效`：这是 `subprocess.run([...], ...)` 的句柄继承问题，不影响子命令实际工作。用命令行 `python scan.py --help` 直接核对 `{scan,code,health}` 和对应参数是否出现在 help 里即可；P2 / Sprint2/3/4 的实际行为不依赖这 3 条测试。
