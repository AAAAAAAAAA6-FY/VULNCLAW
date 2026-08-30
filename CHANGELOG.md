# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，版本语义化（SemVer）。

## [Unreleased] - 2026-08-30

### 新增
- **v105 四轨并行**：
  - 新增工具集成：naabu v2.1.9、dalfox v2.9.0（thirdparty/ 自动发现）
  - 新增 `engines/mobile_engines.py`：移动端 API 安全检测（弱认证/明文传输/越权）
  - 新增 `engines/container_engines.py`：容器/K8s 配置风险检测
  - 新增 `engines/api_security_engines.py`：API 深度安全检测（GraphQL DoS/速率限制绕过/JWT 重放）
  - MCP Server 新增 `scan.api_audit` 工具
  - 新增 `rules/mobile_weak_auth.yaml` 规则库
- **MCP Server 适配器**：`core/mcp_server.py` 提供扫描任务与结果查询的 MCP 工具入口。
- **Agent 交叉验证**：多 Agent 结果交叉核对，降低误报。
- **BusinessLogic 业务流程检测**：`engines/input_engines.py` 基于 API 序列构建流程图的 AI 业务逻辑漏洞分析。
- **引擎统一导出门面**：`engines/__init__.py` 汇总全部 30 个引擎类，支持 `from vulnclaw.engines import SQLiEngine, XSSEngine` 简洁导入。

### 修复
- `core/mcp_server.py`：scan 结果优先读取 `vulnerabilities` 字段并兼容旧 `findings` key，修复 MCP 返回空列表的问题。
- `dag/graph.py`：`NodeType` 新增 `DESERIALIZATION` 反序列化节点类型。
- `distributed/worker.py`：默认 capabilities 补齐 `deserialization`，支持反序列化任务分发。

### 变更
- 认证模块收敛至 `core/auth/`，清理 `code_audit.py` / `code_audit_standalone.py` 等旧文件。
- 配置项同步至 `.env.example` 与 `core/config`。

### 基础设施
- `tests/test_layout_guard.py`：根目录布局守卫测试。
- `docs/architecture_refactor_v103.md`：v103 架构重构说明。
- `.vscode/launch.json`：VS Code F5 调试入口（`scan.py` / `vulnclaw.cli`）。
- `pyproject.toml`：打包配置就绪（`pip install -e .` 后 `vulnclaw` CLI 可用）；修正 `python-whois` 依赖约束为 `>=0.9.0`（官方从未发布 1.0）。
- 测试补强：`tests/test_scan_main.py`、`tests/test_session_manager.py`。

## [v101] - 2026-08-30

### 新增
- **分布式多节点模式（Sprint 4）**
  - `scan.py` 新增 `--distributed / --master / --worker / --redis-url` 参数，支持 Redis 任务队列 + Master 心跳监控 + Worker 分布式执行。
  - `distributed/master.py`：Worker 注册监控、心跳检测与离线故障转移。
  - `distributed/worker.py`：补齐 `_execute_node`，按 `task.type` 解析 NodeType 并调度 `dag.executor.NODE_EXECUTORS` 真实执行（原为 TODO 空壳）。
  - `pyproject.toml` 声明 `redis>=5.0` 依赖。
- **CodeQL 代码安全扫描接入主链路**
  - `scan.py` / `code_audit_runner.py` 新增 CodeQL 步骤：二进制可用时运行 SARIF 分析，结果与 Semgrep 合并后统一送 AI 审计；缺失时友好降级。
  - 报告新增 `codeql_findings_count` 字段。
- **反序列化漏洞检测引擎**（CWE-502）
  - 新增 `engines/deserialization.py`，覆盖 Java（Jackson/原生序列化）、PHP、Python（pickle）技术栈。
  - 被动检测：响应/请求特征指纹（`@type`、`rO0AB`、`O:8:"`、`gASV` 等）。
  - 主动检测：8 类 payload 注入 + 错误回显信号确认。
  - 已注册进 v100 全局扫描引擎列表（`ai/v100/phases/phases_taskgen.py`）。

### 修复
- `code/repo_manager.py`：Windows 下本地目录符号链接失败（无管理员权限）时回退为目录复制。
- Windows 本地路径兼容：`target_name` 提取与 `_extract_repo_name` 支持 `\` 分隔符。
- `scan.py --code` 无需再提供 `-t/--target`。
- 补齐 `distributed/master.py`、`distributed/worker.py` 缺失的 typing 导入。

### 变更
- `core/settings.py` 全部配置项沉淀到 `.env.example`（AI 模型、QPS、超时、代理、日志、Burp、端口扫描、缓存、告警等）。
- `README.md` 更新：分布式部署说明由"预留"改为"可用"，补充 CodeQL 与反序列化引擎说明。
- 一键启动脚本 `start_vulnclaw.sh` 增强：Python 版本校验、`.env` 存在性与 AI Key 检查、关键依赖导入校验。
- 根目录清理：删除 `scan.py.bak`、`_tmp_cachepoison_repro.py` 等临时文件。

## [v100-stable] - 2026-08-29

基线稳定版（v100 限流感知版）：

- 28 个漏洞检测引擎（BaseEngine 插件体系，自动装配）。
- v100 编排器：自适应 QPS 限流（429 指数退避 + 冷却 + 成功爬升）、N-worker 并发、任务队列。
- DAG 多 Agent 调度（`--dag --agents N`），侦察 6 节点并行 → 攻击 → 验证 → 利用 → 报告。
- AI 多模型交叉验证（智谱 / 通义 / DeepSeek，ProviderFailover 自动故障转移）。
- `safe_verify` HTTP 重放 + interactsh OOB 回调 + SafeExploit 自动利用链。
- 统一工具调用注册表 `core/tool_registry.py`（`run_tool`，支持 `stdin_text` 透传）。
- 第三方工具统一接入：nuclei / ffuf / subfinder / sqlmap / interactsh 等经 `get_tool_path` 兜底解析。
- 完整报告输出：JSON + HTML 双格式，DAG 模式含性能复盘 `dag_profile`。
