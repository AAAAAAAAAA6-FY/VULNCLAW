# MCP Server 适配器设计草案

## 目标
将 VULNCLAW 的 tool_registry 暴露为 MCP 服务。

## 架构
Claude Desktop / Cursor → MCP Server (core/mcp_server.py) → tool_registry (core/registry.py) → 引擎

## 技术选型
- 协议：MCP（Model Context Protocol）
- 实现：mcp Python SDK
- 传输：stdio（本地）/ SSE（远程）

## 接口设计
- 遍历 Registry 所有引擎自动注册为 MCP Tools
- 每个引擎对应一个 MCP Tool

## 实施步骤
1. 安装 mcp SDK
2. 实现 core/mcp_server.py
3. 注册所有引擎为 MCP Tools
4. 测试 Claude Desktop 连接
