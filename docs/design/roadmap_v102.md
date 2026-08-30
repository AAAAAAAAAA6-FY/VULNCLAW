# VULNCLAW v102 规划

> ⚠️ **历史归档（2026-08-30 更新）**：本文件为 v102 阶段的原始设计稿，记录当时的目标与排期，**不再作为当前版本的实施依据**。
> - v102 阶段的大部分项目已在 v103 期间以更细粒度的方式落地（MCP Server 适配器、思维链导出、业务逻辑引擎增强等）。
> - 当前（v103）实施计划请以 `docs/architecture_refactor_v103.md` 为准。
> - 用户侧命令/子命令速查请以 `docs/usage_cli_dag_code_health.md` 为准。
> - 如需追溯 v102 的设计取舍，可对照 `CHANGELOG.md` 与 git 提交记录。

---

## 已完成基础（v100/v101）
- 29 个检测引擎
- 分布式模式（--master/--worker）
- 代码审计模式（--code）
- 统一注册中心（Registry）
- 反序列化引擎
- CodeQL 接入

## v102 目标

### 1. MCP Server 适配器
- 路径：`core/mcp_server.py`
- 功能：将 tool_registry 暴露为 MCP 服务，外部 AI 可调用
- 验收：Claude Desktop 能连接并调用扫描引擎

### 2. Agent 思维链导出
- 路径：`core/chain_of_thought.py`
- 功能：ReAct Agent 的 Thought/Action/Observation 导出为 Markdown/JSON
- 验收：扫描后生成 `_runtime_cache/reports/chain_of_thought_xxx.md`

### 3. 业务逻辑引擎 AI 增强
- 文件：`engines/input_engines.py` 的 `BusinessLogicEngine`
- 功能：让 LLM 理解业务流程状态机，检测复杂逻辑漏洞
- 验收：能检测到多步骤业务逻辑绕过

## 排期
- MCP Server：2 小时
- 思维链导出：1.5 小时
- 业务逻辑增强：3 小时