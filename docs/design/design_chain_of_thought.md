# 思维链导出模块设计草案

## 目标
将 ReAct Agent 的 Thought/Action/Observation 导出为可审计报告。

## 数据来源
- `ai/dispatcher.py` 的 `ReActAgent.history`

## 输出格式
- Markdown（人类可读）
- JSON（机器可读）

## 输出位置
`_runtime_cache/reports/chain_of_thought_{target}_{timestamp}.md`

## 实施步骤
1. 在 `ReActAgent.run()` 结束时导出
2. 生成 Markdown + JSON 双格式
