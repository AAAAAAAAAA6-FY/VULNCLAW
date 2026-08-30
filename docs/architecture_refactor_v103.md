# VULNCLAW v103 架构调整与开源化实施方案

> 生成时间：2026-08-30（基于当日实测文件系统）
> 目标：根目录简洁、分类清晰、去重合并、可打包安装、开发/维护/使用体验最优、为开源铺路。
> 核心原则：**底层逻辑先行** —— 先固化"包命名空间 / 导入路径 / 配置中心 / 入口"，再动上层文件，防止改完又回退。

> **执行状态（2026-08-30 更新）**：
> - 阶段 0 已完成：src-layout 迁移完成（`src/vulnclaw/`），`cli.py` 统一入口就位（`vulnclaw scan / code / health`，兼容旧参数转发），`scan.py` 降级为薄壳，导入路径已批量迁移为 `vulnclaw.*`。
> - 阶段 1 进行中：代码审计入口已收敛；`archive/`、`pocs_test/` 已删除；认证模块收敛（R5）待执行。
> - 阶段 2/3 待执行：scripts 清理、venv 移出、thirdparty 瘦身、LICENSE/SECURITY/CI。
> - 本文档第 1 节"现状诊断"为迁移前快照，仅作历史参考。

---

## 1. 现状诊断（2026-08-30 实测快照，src-layout 迁移后）

> 本节覆盖「src-layout 迁移 + P2 代码审计入口三合一」落地后的**实际文件系统**。
> 迁移前的旧根目录快照（`scan.py` 巨无霸、`code_audit_runner.py`、`archive/`、`pocs_test/`、顶级 `ai/code/core/...` 等）请以 git 历史（提交 P2 合并前的 tag）为准，不再在本文档中维护。

### 1.1 根目录全景（6 个一级目录 + 14 个文件，src-layout）

| 条目 | 内容 | 判定 |
| --- | --- | --- |
| `scan.py` | **薄壳**：UTF-8 / bytecode / HOME 三级守卫 + 转发到 `vulnclaw.cli.main()`；兼容旧参数风格（直接传 `-t/--dag/--health/--code` 仍可用）。 | ✅ 保留（唯一兼容入口） |
| `start_vulnclaw.ps1/.sh` | 一键启动脚本（3 层守卫 + 入口选择） | ✅ 保留 |
| `pyproject.toml` | 依赖声明；**packages=src + console_scripts 仍待补齐（阶段 0.4）**，当前仍以「在项目根运行 python scan.py」为主。 | ⚠️ v103 阶段 0 剩余项 |
| `README.md / CONTRIBUTING.md / CHANGELOG.md / LICENSE / SECURITY.md` | 文档 + 开源发布材料 | ✅ 保留（SECURITY 邮箱占位见 §7 备注） |
| `.gitignore / .env.example / .pre-commit-config.yaml` | 配置骨架 | ✅ 保留 |
| `docs/` | `architecture_refactor_v103.md` + `code_structure_report.md` + `design/*` + **`usage_cli_dag_code_health.md`（命令速查，2026-08-30 新增）** | ✅ 保留 |
| `scripts/` | 工具脚本（api_compare、auto_validation、entry_*、server_health、tools_menu 等）；先前的"垃圾目录"需按阶段 2.1 再做一次巡检。 | ⚠️ 阶段 2 再清理 |
| `src/vulnclaw/` | **唯一主包（src-layout）**：内含 `ai/`、`code/`、`config/`、`core/`、`dag/`、`dashboard/`、`deepsec/`、`distributed/`、`engines/`、`modules/`；`cli.py / scan_main.py / health.py / paths.py / exceptions.py / bootstrap.py / __init__.py` 位于包根。 | ✅ 唯一事实源 |
| `tests/` | 14 个 pytest 文件（layout_guard / integration_smoke / sprint1~4 / unit_* / optimization / plugin_market / core_imports / core_registry 等） | ✅ 保留 |
| `thirdparty/` | 第三方工具二进制/源码/vendor：nuclei/ffuf/interactsh-client/amass/katana/gau/afrog/fscan/rustscan/assetfinder/rad.exe / BurpExtender.py / `BurpSuite V2026.7.3/` / `Ehole/` / `OneForAll/` / `PentestGPT/` / `dirsearch/` / `nuclei-templates/` / `nyxstrike/` / `sqlmap/`。**exe 已就位；nuclei-templates 需要显式设置 `NUCLEI_TEMPLATE_DIR=thirdparty/nuclei-templates` 才不降级**。 | ⚠️ 开源需瘦身（阶段 2.4） |
| `_runtime_cache/` | 运行时产物（reports / logs / deep_dev / cookies / code_workspace 等）；若仍有嵌套 `_runtime_cache/_runtime_cache/`，按阶段 2.2 清理。 | ⚠️ 按需巡检 |
| `venv/` | 本机虚拟环境（已被 `.gitignore` 忽略），建议按阶段 2.3 移出根。 | ⚠️ 阶段 2 |
| `(已删除)` `code_audit_runner.py` / `archive/` / `pocs_test/` / `src/vulnclaw/code_audit.py` / `src/vulnclaw/code_audit_standalone.py` | **P2 + v103 阶段 1 已删除**。 | 🔴 历史项，不复存在 |

### 1.2 重复 / 冗余清单（src-layout 迁移后，重按"实际文件"刷新）

| # | 项目 | 状态 | 说明 |
| --- | --- | --- | --- |
| R1 | **3 处代码审计入口 → 已收敛为 1** | ✅ 完成（P2） | 唯一实现：`src/vulnclaw/scan_main.py:run_code_audit`；入口：`vulnclaw code` 或 `python scan.py --code`。`code_audit_runner.py`、`src/vulnclaw/code_audit*.py` 已删除，残留引用=0。 |
| R2 | **`archive/` 与 `thirdparty/` 重复** | ✅ 完成（v103 阶段 1） | `archive/` 整目录已删除。 |
| R3 | **`scripts/` 垃圾目录** | ⚠️ 待阶段 2 复查 | 先前列出的 `(the/`、`default/`、`non-65001/`、`old/`、`page/`、`runs/`、`under/`、`code/`、`_merge_backup/` 需重新 `Get-ChildItem scripts` 巡检。 |
| R4 | **`_runtime_cache/` 嵌套** | ⚠️ 待阶段 2 复查 | 2026-08-30 时 `scan.py --health` 已稳定通过，但运行过程中偶发嵌套；阶段 2.2 一次性清理 + 修 `resolve_project_path` 中仍存在的重复拼接。 |
| R5 | **认证模块交叠** | 🟡 收敛方案已定（v103 阶段 1.4） | `core/auth_helper.py`（CLI 交互 + requests 版 auto_login）/ `core/auto_login.py`（Playwright 自动登录，含 unreachable 死代码段 L69-L109）/ `core/browser_cookie.py`（Chrome/Edge sqlite 读取，2 处重复 cookie_paths 样板）/ `core/session_manager.py`（CookieManager + SessionManager，真实被 9 处 import 的状态模块）。收敛方案：`session_manager` 为状态唯一入口；`auth_helper` 统一"4 类 Cookie 来源工厂"；其余两文件降级为 re-export shim。**本项暂未动代码**，等确认后按 §7 执行。 |
| R6 | **`config/` 目录 / 字典路径描述** | ✅ 已解决（src-layout） | 字典/Payload 统一在 `src/vulnclaw/core/data/`（subdomains / payload_pool.yaml 等）。README 中的旧 `config/` 描述需在阶段 3.4 文档对齐时同步修正。 |
| R7 | **空 `__init__.py` / 导出缺失** | 🟡 半完成 | `src/vulnclaw/config/__init__.py` 已补 `PROJECT_CACHE_DIR`、`TMP_DIR` re-export（P2 验收阻断修复）；`engines/__init__.py` 仍未导出具体引擎类，阶段 1.5 未做。 |
| R8 | **`pocs_test/` 散落 POC** | ✅ 完成（v103 阶段 1） | 整目录已删除。 |

### 1.3 打包现状（关键缺陷，src-layout 后）

- `pyproject.toml` 仍未补 `[tool.setuptools.package-dir]={"":"src"}` + `packages=find_namespace:where=src` + `[project.scripts] vulnclaw = "vulnclaw.cli:main"` → **vulnclaw 命令仍不可通过 `pip install -e .` 直接获得**。
- 由于已统一为 `src/vulnclaw/*`，`pip install -e .` 的改动仅在 pyproject.toml（A→B 实际已经是 B），风险很低；缺的只是**真正写 pyproject.toml 并实测一次 `vulnclaw --help`**。

### 1.4 底层逻辑现状（src-layout 后）

- 已具备的稳定底座：`vulnclaw.core.tool_registry`（工具统一入口 + `get_tool_path` 三级兜底）、`vulnclaw.core.settings / vulnclaw.config.settings`（双份 settings 并存，后续收敛为一）、`vulnclaw.core.utils`（共享会话 + 原子写 + 自适应限速）、`BaseEngine` 插件体系（自动装配）、`vulnclaw.ai.tools.EngineTool`。
- P1/P2 实际落地的能力（文档需要同步描述）：
  - **DAG 调度 + 多 Agent 并行**：`vulnclaw/dag/{graph,scheduler,executor,context,resources,multi_target_context}.py`，`scan.py -t <url> --dag --agents 6` 实测通过（5 个侦察节点 1s 内并行启动，ResourceGovernor：llm≤7 / nuclei≤2 / ffuf≤4）。
  - **多目标并行 `-l`**：`multi_target_context.py` 的上下文隔离链已实现。
  - **流式 pipeline 验证**：`ai/v100/orchestrator.py` 的 stream-verify 后台协程 + `phases/phases_verify.py` 去重。
  - **代码审计入口三合一**：唯一入口 `scan_main.run_code_audit`，守卫测试 `test_no_standalone_code_audit_runner` 通过。
- 仍缺失的底座：**统一入口验证**（`pip install -e . && vulnclaw --help`）、**导入路径彻底一致**（目前仍有 `from vulnclaw.core.settings import settings` 与 `from vulnclaw.config.settings import settings` 双路径并存，R5/R7 后续统一）、**文档对齐**（README 目录结构 + CLI 参数速查）。

---

## 2. 目标架构

### 2.1 设计原则

1. **唯一命名空间 `vulnclaw.*`**：所有包收敛到 `vulnclaw/` 下，内部用相对/前缀导入，外部只暴露 `vulnclaw` 一个顶级包 —— 开源不撞名。
2. **入口唯一**：`vulnclaw` 命令（`pip install -e .` 后）与 `python -m vulnclaw` 等价；`python scan.py` 降级为兼容薄壳。
3. **配置/路径/工具三中心**：一切可配置项进 `core/settings.py`，一切外部工具进 `core/tool_registry.py`，一切路径解析进 `core/utils.py`。
4. **数据静态化**：字典/Payload 集中在 `vulnclaw/data/`，运行时产物只进 `_runtime_cache/`。
5. **先立后破**：先落地阶段 0 的底座，再执行阶段 1/2 的文件级改动；每阶段跑 `tests/` + 冒烟扫描验收。

### 2.2 目标目录树

```
pentest_platform/
├── pyproject.toml            # 打包 + console_scripts + 依赖（唯一）
├── README.md  LICENSE  SECURITY.md  CONTRIBUTING.md  CHANGELOG.md
├── .gitignore  .env.example  .github/            # CI（可选）
├── start_vulnclaw.ps1  start_vulnclaw.sh
├── scan.py                   # 薄壳：from vulnclaw.cli import main; main()
├── vulnclaw/                 # ★ 唯一主包（src-layout 目标）
│   ├── __init__.py           # __version__
│   ├── cli.py                # 统一 CLI（scan/code-audit/master/worker/health/plugins）
│   ├── core/                 # settings/logger/scanner/utils/tool_registry/payload_pool/...
│   ├── engines/              # 29 检测引擎（BaseEngine 自动装配）
│   ├── ai/                   # v100 编排 + provider + tools（legacy 移入 archive 或删除）
│   ├── modules/              # recon/collectors/vuln_scanner
│   ├── dag/  distributed/  deepsec/
│   ├── code/                 # 代码审计
│   ├── dashboard/            # Web Dashboard（保留预留）
│   └── data/                 # subdomains_top5000.txt / payload_pool.yaml / ...
├── scripts/                  # 仅保留开发辅助（tools_menu 等），垃圾目录全清
├── tests/
├── docs/
└── thirdparty/               # 工具二进制（gitignore / 子模块，按需下载脚本）
```

> 注：src-layout 有两条路线，见 §3.1 的 A/B 决策。若选 A（保留顶级包），则省略 `vulnclaw/` 外层，仅补 pyproject 打包配置。

---

## 3. 分阶段实施计划

### 阶段 0：底层逻辑先行（防回退地基）★ 必须先做

目标：让"包结构 / 导入路径 / 入口 / 配置"变成不可回退的约定，之后移动任何文件都不破坏运行。

**0.1 命名空间决策（二选一，建议 A）**

| 方案 | 做法 | 成本 | 收益 |
| --- | --- | --- | --- |
| **A. 保留顶级包 + 补全打包**（推荐） | `pyproject.toml` 增加 `[tool.setuptools] packages={find={include=["core*","ai*","engines*","modules*","dag*","distributed*","code*","deepsec*","dashboard*"]}}` + `[project.scripts] vulnclaw="scan:main"` | 低 | 立即 `pip install -e .`，`import core` 可用；但顶级包名开源不友好 |
| **B. 收敛到 `vulnclaw/` 命名空间** | 物理移动 9 个顶级包进 `vulnclaw/`，批量改写 79 处 `from core.` → `from vulnclaw.core.`（可用脚本 `sed`/`ruff` 批量替换） | 中高 | 开源规范、永不撞名、`import vulnclaw.core` 清晰 |

> 决策建议：**先做 A 立即可用，再以自动化脚本在稳定后升级到 B**（B 的批量替换脚本可先在小范围 pilot：`engines/` 一个子包验证后推广）。A→B 唯一成本是一次性机械替换，风险可控。

**0.2 配置/路径中心化（消除散落硬编码）**

- 全库扫描 `Path(__file__).parent.parent / "thirdparty"`、`"../thirdparty"`、`"config/"` 等散落路径，统一改为 `core/settings.py` 的 `THIRDPARTY_DIR` / `DATA_DIR`，或 `core/utils.py` 的 `resolve_project_path()`。
- 删除 R6：README 中 `config/` 描述改为 `core/data/`（若走 B 方案则改 `vulnclaw/data/`），并加 FAQ 提示。

**0.3 统一 CLI 入口**

- 新建 `cli.py`：把 `scan.py` 的 argparse 保持原样，函数拆分为模块：
  - `cli/scan.py`（`run_scan`，原 `main_async` 去掉 Cookie 细节）
  - `cli/code_audit.py`（合并 R1 三份逻辑，收敛为一份 `run_code_audit`）
  - `cli/distributed.py`（master/worker 入口）
  - `cli/health.py`（健康检查）
  - `cli/plugins.py`（插件市场 CLI）
- `scan.py` 变为薄壳：环境引导（UTF-8/bytecode 禁止/HOME 重定向）+ `from vulnclaw.cli import main; main()`。
- 新增 `vulnclaw/__main__.py`：`python -m vulnclaw` 等价 `vulnclaw`。

**0.4 打包完整化**

- `pyproject.toml`：补 `[project.scripts] vulnclaw = "scan:main"`（薄壳），声明 `packages`（A 方案）或 `[tool.setuptools.package-dir]`（B 方案）。
- 版本号从 `0.1.0` 提为 `0.10.0`（对齐 v101/v102 里程碑）并读 `vulnclaw/__init__.py.__version__`。
- 验收：`pip install -e .` → `vulnclaw --help` 可用；`python scan.py -t <url>` 行为不变。

### 阶段 1：去重与合并（文件级）

| # | 动作 | 详述 |
| --- | --- | --- |
| 1.1 | **合并代码审计入口** | 以 `scan.py` 的 `run_code_audit` 为唯一实现（迁入 `cli/code_audit.py`）；删除 `code_audit_runner.py`、`scripts/run_code_audit.py`；`scripts/start_*` bat 指向新入口 |
| 1.2 | **删除 `archive/`** | 与 `thirdparty/` 子模块重复，确认无独立内容后整目录删除（或先 git 归档 tag） |
| 1.3 | **删除 `pocs_test/`** | 测试产物，确认无被引用后删除（`search_content "pocs_test"` 先行） |
| 1.4 | **认证模块收敛（R5）** | 评估 `auth_helper/auto_login/browser_cookie/session_manager`，将 Cookie 提取统一为 `core/auth/`（`session.py` 会话+`cookies.py` 提取+`login.py` 自动登录），旧文件降级为 re-export 兼容层 |
| 1.5 | **`engines/__init__.py` 导出** | 聚合导出全部引擎类 + `__all__`，作为稳定的引擎 API 门面（供开源文档化） |
| 1.6 | **`core/__init__.py` 补内容或删除** | 若 A 方案改为空包说明 docstring；若 B 方案作为 `vulnclaw.core` 一部分正常导出 |

### 阶段 2：清理与目录收敛

| # | 动作 | 详述 |
| --- | --- | --- |
| 2.1 | **清理 `scripts/` 垃圾目录** | 删除 `(the/`、`default/`、`non-65001/`、`old/`、`page/`、`runs/`、`under/`、`code/`、`_merge_backup/`（先确认 `merge_tool.py` 不再写 `_merge_backup`） |
| 2.2 | **治理 `_runtime_cache/`** | 删除嵌套 `_runtime_cache/_runtime_cache/`、`scripts/`、`extracted_scripts.zip`；检查并修复产生嵌套的代码（搜索 `_runtime_cache/_runtime_cache`） |
| 2.3 | **`venv/` 移出项目根** | 移至 `<USER_HOME>\venv_pentest\` 或删除重建为 `.venv`（README 同步"环境要求"章节） |
| 2.4 | **`thirdparty/` 开源瘦身** | nuclei-templates / PentestGPT / nyxstrike 子模块化或 gitignore + 下载脚本（`scripts/fetch_tools.py` 按需拉取）；exe 二进制从仓库移除，改由脚本下载或文档指引 |
| 2.5 | **`legacy/` 处置** | `ai/legacy/orchestrator_v5.py`、`fusion_agent.py` 若无人引用（`search_content "legacy"` 验证）移入 `archive/legacy/` 或删除，根目录不再保留历史代码 |

### 阶段 3：开源化

| # | 动作 | 详述 |
| --- | --- | --- |
| 3.1 | **LICENSE** | ✅ **已就位（MIT）**：`LICENSE` 已存在，Copyright (c) 2026 VULNCLAW / pentest_platform contributors。 |
| 3.2 | **SECURITY.md** | ✅ **已就位**（2026-08-30 修复邮箱占位：example.com 已替换为项目级填写指引，避免发布后裸 `example.com` 邮箱出现在 SECURITY 文件）。 |
| 3.3 | **CI（可选）** | `.github/workflows/ci.yml`：ruff + pytest + `vulnclaw --health` 冒烟。pyproject 未完成打包前可先用 `python scan.py --health` 代替。 |
| 3.4 | **文档对齐** | README 目录结构重写为 src-layout 实际树 + 子命令矩阵；新增 `docs/usage_cli_dag_code_health.md`（命令速查，**2026-08-30 已新增**）；`CONTRIBUTING.md` 更新入口说明（统一 `vulnclaw scan / code / health` + 兼容薄壳）。 |
| 3.5 | **敏感信息审计** | 全库 grep `api_key`/`password`/`token=` 硬编码，确认仅 `.env` 持有；检查 `thirdparty/` 是否残留私钥（如 `rad_ca.key` 需评估是否入库）。另外 `src/vulnclaw/config/settings.py` 与 `src/vulnclaw/core/settings.py` 的默认 API Key 占位必须保持为空。 |

---

## 7. 认证模块收敛（R5）执行方案（v103 阶段 1.4 增补）

> 对应 §1.2 R5。本方案**先于重构写代码**前固化边界与回退点；等你批准后再落地代码。

### 7.1 目标与边界

**目标**：把"Cookie 的 4 类来源（本机浏览器 DB / Playwright 自动登录 / CLI 粘贴 / 文件或 Burp 持久化）→ 统一收纳 → 注入会话"这条链路变成**单一入口**，消除多份 Cookie 提取样板与重复的 Cookie 合法性校验。

**保持不变**：
- `session_manager.py` 作为**状态唯一入口**：对外暴露 `CookieManager.add_cookies / add_cookies_sync`（双轨锁模型）、`SessionManager`（按角色隔离的 ClientSession + 请求注入）。**不拆分这个文件**，避免 9 处 import 一起迁移。
- 现有对外调用契约：`from vulnclaw.core.browser_cookie import get_browser_cookies` 与 `from vulnclaw.core.session_manager import get_session_manager, CookieManager` **继续可用**（re-export 兼容层保留一版本周期）。

**变更**：
- `auth_helper.py` 升级为 **CookieSource 工厂**：统一导出 `from_browser()`、`from_playwright()`、`from_cookie_string()`、`from_cli_interactive()`、`verify_cookies()`。
- `browser_cookie.py`、`auto_login.py` 降级为 **re-export shim**：文件内容只剩 `from vulnclaw.core.auth_helper import ...`（保留 L123 `__all__` 原签名）。
- 删除 `auto_login.py` L69-L109 **不可达死代码**（前面 try/except 已 return，这段永远不执行）。
- 消除 `browser_cookie.py` 中 2 处重复的 `cookie_paths` 枚举+复制+sqlite open 样板：内部抽成 `_open_cookie_db_copy(domain)` 返回 `(temp_path, conn)`，`get_browser_cookies` 与 `get_all_browser_cookies` 共用。
- `auth_helper.py` 当前缺少 `from typing import Dict, List, Optional`（`NameError: Dict` 风险，目前未被 import 所以没炸），收敛时一并补齐。

### 7.2 推荐合并映射表

| 函数现在的位置 | 合并后所在 | 对外稳定名 | 备注 |
| --- | --- | --- | --- |
| `auth_helper.parse_cookie_string` | `auth_helper.py` | `parse_cookie_string`（纯函数） | 保留；供 from_cookie_string 复用 |
| `auth_helper.verify_cookie_sync` | `auth_helper.py` | `verify_cookies(domain, cookies)` 改名 | 改名体现"同步网络校验"，与 session_manager 内"纯域名校验"区分 |
| `auth_helper.get_accounts_interactive` | `auth_helper.py` | `from_cli_interactive(default_domain)` | 返回 `CookieBag(role)` |
| `auth_helper.auto_login(target,u,p,login_url=None)` | `auth_helper.py` | `from_requests_login(target,u,p,login_url)` | 与 from_playwright 命名对称，避免与 playwright 重名歧义 |
| `auto_login.auto_login_and_get_cookie` | `auth_helper.py` | `from_playwright(login_ctx)` | 内部函数本体迁移；shim 导出旧名 |
| `auto_login.auto_login_multiple_accounts` | `auth_helper.py` | `from_playwright_batch(accounts)` | 同上 |
| `browser_cookie.get_browser_cookies` | `auth_helper.py` | `from_browser(domain)` | 重命名；shim 保留旧名 |
| `browser_cookie.get_all_browser_cookies` | `auth_helper.py` | `from_browser_multihost(domain)` | 同上 |
| `session_manager._is_valid_cookie_domain` | 留在 `session_manager.py` | 不导出到 auth_helper | 保持状态模块内部使用 |
| `session_manager.CookieManager.add_cookies(_sync)` | 留在 `session_manager.py` | 状态唯一 sink | auth_helper 仅返回 CookieBag，不直接写状态 |

### 7.3 统一数据结构 CookieBag（NamedTuple，建议写在 session_manager 顶部 import 区或 auth_helper 顶部）

```python
CookieBag = NamedTuple("CookieBag", [
    ("domain", str),
    ("cookies", Dict[str, str]),
    ("source", Literal["browser", "playwright", "cli", "requests_login", "burp", "file"]),
    ("role", str),            # session_manager 的 role 键，默认 "default"
    ("expires", Optional[int]) # None 时由 CookieManager 填默认 7 天
])
```

所有 `from_*()` 工厂返回 `list[CookieBag]`；调用方统一 `for bag in bags: await cm.add_cookies(bag.domain, bag.cookies, expires=bag.expires)`，避免裸 dict 丢 meta。

### 7.4 回退策略（R5 必须保证安全）

- **阶段 A（小修）回退**：若仅删死代码/抽 cookie_paths 样板就出问题，`git checkout -- src/vulnclaw/core/auto_login.py src/vulnclaw/core/browser_cookie.py` 即可。
- **阶段 B（shim + 迁移）回退**：若 re-export shim 某处 import 循环，**先恢复旧文件**（从 git 取），再下一轮用 `if TYPE_CHECKING` 的懒导入排查循环根源，不强行推进。
- 验收（R5 落地时执行）：`tests/test_integration_smoke.py` 中 `TestSessionManager`（若有）与 `pytest tests/test_layout_guard.py tests/test_integration_smoke.py -q` 必绿；手工跑 `python scan.py --health` 不应出现认证相关新增告警。

---

## 8. 测试补强计划（2026-08-30 新增，依据 §3 覆盖率 15% 报告）

> 目标：把 **15% → 25%**（第一阶段），补强 3 组最高 ROI 的测试。每组均不触及正在运行的长任务文件（scan_main 实际逻辑 / ai 编排内部 / engines），只在外围"入口 + 数据结构 + 小图"打桩。

### 8.0 覆盖率事实基线（2026-08-30 采集）

- 160 passed / 4 skipped（稳定子集，不含 sprint2/3 的 WinError 6）。
- `--cov=src` 总 stmt=21162，覆盖率=15%。
- Top 低覆盖群：`scan_main.py`（0%）、`dag/*`（近乎 0%）、`session_manager + 认证 4 件套`（0~10%）、`code/repo_manager + 适配器`（0%）。

### 8.1 P0：高 ROI，改完直接提升 5~8%（建议新建 4 个测试文件，等你确认文件名后落地）

| 目标模块 | 测试文件（建议） | 测什么（**不依赖真实 AI / 真实外网**） | 预期覆盖提升 | 风险点 |
| --- | --- | --- | --- | --- |
| `code/repo_manager.py` + `code/engines/semgrep_adapter.py`（本地目录分支 + 工具缺失兜底） | `tests/test_code_repo_manager.py` | ① 用 `tempfile.TemporaryDirectory` 建 3 个 `.py` 样例（包含明显的 os.system/eval 让 semgrep 规则命中的 pattern），传 `--repo <local>`，验证 `clone_repo` 走 symlink/复制分支且 `repo_name` 正确；② 临时 patch `PATH` 移除 semgrep，验证 adapter.scan 抛出「semgrep 未安装」的 RuntimeError（匹配 before/after diff 的行为）；③ 验证 DependencyScanner 在无 requirements.txt 时返回空（不报错）。 | ~140 stmt 可覆盖（repo_manager 70 + semgrep_adapter 63 + dependency_scanner 部分）。 | Windows 符号链接可能失败 → 已覆盖降级复制分支，正好命中。 |
| `core/session_manager.py`（CookieManager 的域名校验 + 双轨锁 + 持久化） | `tests/test_session_manager_unit.py` | ① `_is_valid_cookie_domain`：纯 TLD / 带点前缀 / 常规二级域 / co.uk 形式的参数化；② `CookieManager`：先 `add_cookies_sync` 写 com（应被拒绝）→ 写 `a.example.com` → `get_cookies_for_url("https://a.example.com/x")` 精确命中；③ 并发 `asyncio.gather(*[cm.add_cookies(...) for _ in range(20)])` 后统计 cookie_map 数量==20（异步锁保护有效）；④ 损坏 cookie 文件修复流程（构造损坏 JSON，调用 reload 验证备份恢复与日志）。 | ~250 stmt（session_manager 从 10%→50%+）。 | 不碰 `SessionManager` 里的真实 aiohttp 请求，只测 CookieManager。 |
| `dag/graph.py` + `dag/scheduler.py`（最小 DAG 图 + 资源上限） | `tests/test_dag_minigraph.py` | ① 手工建 3 节点链：A → B → C，调用 add_edge 检查 `graph.topological_order()` A→B→C，反向 B→A 被拒绝；② 构造含循环的图应在 `add_edge`/`topo` 处抛异常；③ ResourceGovernor：3 个并发 acquire(llm) 后第 8 个应阻塞或被限流（mock 时间），验证 `llm ≤ 7`。 | ~180 stmt。 | scheduler 的时间推进可用 mock `asyncio.sleep`，不跑真实 executor。 |
| `scan_main.run_code_audit` 的入口签名 + 报告输出（不跑 AI 链） | `tests/test_scan_main_code_smoke.py` | ① 用 `argparse.Namespace(repo=tmp_local, lang="python", code=True)` 直接 `asyncio.run(run_code_audit(args))`，验证：退出无异常、报告 JSON 文件存在且能 load、包含 findings/errors 两键、errors 列表中包含"未安装"/"跳过"两项中至少一项（Windows 环境无 semgrep/codeql 正是当前可重现行为）。 | ~200 stmt（scan_main 从 0%→约 22%）。 | 可能有 LLM 初始化路径 → 建议用 monkeypatch 把 AI 调用替换为 `[]`，把 semgrep/codeql 的 subprocess 捕获为可控 mock。 |

### 8.2 P1：DAG 执行 + 认证 4 件套（建议在 R5 收敛之后做，避免一边合文件一边写测试来回返工）

| 目标模块 | 测试文件（建议） | 预期覆盖提升 |
| --- | --- | --- |
| `dag/executor.py` 的 recon 子节点（recon_alive / recon_port） | `tests/test_dag_executor_nodes.py` | 用 `monkeypatch` 把 `modules.recon.get_subdomains_async` 换为返回 3 个假域名，只验证 executor 的"节点状态机"（PENDING→RUNNING→OK/FAIL），不做真实网络。提升 ~100 stmt。 |
| `auth_helper + browser_cookie + auto_login`（R5 之后） | `tests/test_auth_cookie_sources.py` | 对 4 类 CookieSource 的**纯函数/本地文件**部分做参数化测试：`parse_cookie_string("a=1; b=2")`、`from_browser_multihost`（构造一个假 sqlite cookies db 在 tmp 下，填两行 host_key/name/value，验证解析正确）、`from_playwright`（mock `async_playwright` 返回固定 cookies）。提升 ~200 stmt。 |
| `core/auth_helper.py` 当前 typing 缺陷 | 同上文件里顺手加 1 条冒烟 | `from vulnclaw.core.auth_helper import parse_cookie_string; parse_cookie_string("a=1")` 必不抛出 `NameError: Dict`（现在可能直接炸）。 |

### 8.3 P2：引擎级 / 大规模（长期项，预计 15%→30% 还需要这些）

- `engines/base.py` 的 `BaseEngine._parse_response` + 兼容 tuple 分支统一助手：`tests/test_engines_base_parse.py`（覆盖 25 次 `isinstance(normal_resp, tuple)` 高频样板的统一助手）。
- `modules/collectors.py` 本地缓存路径 / 去重逻辑：`tests/test_collectors_dedup.py`。
- 分布式模式 `distributed/master + worker + redis_backend`：需要一个本地单节点 redis 或 fakeredis 才能稳定，暂不推荐在 CI 前加。

### 8.4 执行顺序建议（风险最低）

```
Week 1（P0，4 个文件）：
  T1. test_code_repo_manager.py → 验证 code 审计入口三合一回归基线
  T2. test_session_manager_unit.py → 验证 R5 落地前的状态模块稳定性
  T3. test_dag_minigraph.py → DAG 调度正确性的外围守护
  T4. test_scan_main_code_smoke.py → 以入口签名 + 报告 JSON 存在作为 P2 的验收标准

Week 2（R5 落地 + P1）：
  T5. 合并认证模块（按 §7 方案）→ 同步提交 test_auth_cookie_sources.py
  T6. test_dag_executor_nodes.py

Week 3+（P2）：选择性推进。
```

### 8.5 统一的环境约束（写测试前必须遵守）

- 必须设置 `PYTHONDONTWRITEBYTECODE=1`，不写 `__pycache__` 到 `src/vulnclaw/`（layout 守卫已开启 autouse 级 purge，避免与测试启动顺序竞态）。
- 禁用真实网络：默认 `pytest` 跑时不连任何真实 API；需连的测试显式 mark 为 `@pytest.mark.live` 并在 CI 默认跳过。
- 不改 ai/ / engines/ / scan_main 内部函数签名；只在外部打桩 monkeypatch（与 user 要求"不要影响正在运行的任务依赖文件"一致）。

---

## 9. 验收标准

| 阶段 | 验收命令 / 行为 |
| --- | --- |
| 0 | `pip install -e .` 成功；`vulnclaw --help` 与 `python scan.py --help` 输出一致；`python -c "import core; import engines; import ai"` 成功 |
| 0 | `python scan.py --health` 退出码 0；`python scan.py -t https://httpbin.org` 冒烟扫描正常产出报告 |
| 1 | `tests/` 全绿；`grep -r "run_code_audit" --include="*.py"` 仅 1 处实现；`archive/`、`pocs_test/` 已删除 |
| 2 | 根目录 `ls` 仅剩目标树条目；`scripts/` 无异常目录；`_runtime_cache/` 无嵌套 |
| 3 | LICENSE/SECURITY 就位；`ruff check .` 通过；README 目录树与实际一致 |

---

## 10. 风险与回退策略

| 风险 | 缓解 |
| --- | --- |
| 阶段 0 打包破坏现有 `python scan.py` 运行 | 薄壳 `scan.py` 保留全部环境引导逻辑（UTF-8/bytecode/HOME 重定向），只在最后一行改调用；A 方案不移动任何文件，风险最小 |
| 批量改写 79 处 import 出错 | 先 A 后 B；B 用脚本替换 + `tests/` + 冒烟双保险；每批小步提交，出错可 `git revert` |
| `merge_tool.py` 依赖 `_merge_backup` | 清理前先读 `merge_tool.py`，将其备份路径改为 `_runtime_cache/backups/` |
| 认证模块合并引入行为回归 | 旧模块保留 re-export 兼容层，逐步迁移调用方；`tests/test_integration_smoke.py` 守护 Cookie 流程 |
| 开源后第三方工具缺失导致降级 | 现有 `get_tool_path` 兜底链（PATH→系统→thirdparty/）已具备，README 明确"缺失自动降级" |

---

## 11. 建议执行顺序

```
第 1 天：阶段 0（0.1-A + 0.2 + 0.3 + 0.4）→ 全量测试 + 冒烟 → 提交
第 2 天：阶段 1（1.1–1.6）→ 测试 → 提交
第 3 天：阶段 2（2.1–2.5）→ 测试 → 提交
第 4 天：阶段 3（3.1–3.5）→ 开源前最后审计
可选：稳定 1 周后执行 0.1-B（收敛 vulnclaw.* 命名空间）
```

> 每一阶段都是独立可交付、可回滚的提交；**阶段 0 先行**是防止"改完又变回去"的关键 —— 一旦包结构/入口/路径被约定并测试覆盖，后续文件重组只是搬家而非重构。
