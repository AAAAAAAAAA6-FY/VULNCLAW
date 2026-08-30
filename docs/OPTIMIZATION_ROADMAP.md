# VULNCLAW 优化任务可视化进度表

> 创建时间：2026-08-30
> 用途：跟踪 18+ 个优化任务的状态，避免迷失

---

## 任务总览

| 编号 | 任务 | 分支名 | 状态 | 开始时间 | 结束时间 | 验收命令 |
|------|------|--------|------|----------|----------|----------|
| P1-1 | FFUF 增量缓存 | opt/p1-1-ffuf-cache | 待开始 | - | - | pytest tests/test_ffuf_cache.py |
| P1-2 | LLM Prompt 压缩 + 语义缓存 | opt/p1-2-llm-cache | 待开始 | - | - | pytest tests/test_llm_cache.py |
| P1-3 | DAG 失败重试 + 死信队列 | opt/p1-3-dag-retry | 待开始 | - | - | pytest tests/test_dag_retry.py |
| P1-4 | BatchProcessor 接线 | opt/p1-4-batch-proc | 待开始 | - | - | pytest tests/test_batch_proc.py |
| P2-1 | httpbin 集成测试 | opt/p2-1-httpbin | 待开始 | - | - | pytest tests/test_httpbin_live.py |
| P2-2 | 扩充 payload_pool.yaml | opt/p2-2-payloads | 待开始 | - | - | python -c "import yaml; yaml.safe_load(open('core/data/payload_pool.yaml'))" |
| P2-3 | 扩充 common_dirs | opt/p2-3-dirs | 待开始 | - | - | python -c "from vulnclaw.core.settings import settings; print(len(settings.common_dirs))" |
| P2-4 | 优化进度表 | opt/p2-4-roadmap | 已完成 | 2026-08-30 | 2026-08-30 | Test-Path docs/OPTIMIZATION_ROADMAP.md |
| P2-5 | Dockerfile | opt/p2-5-docker | 待开始 | - | - | docker build -t vulnclaw:latest . |
| P2-6 | CLI 帮助文档 | opt/p2-6-cli-help | 待开始 | - | - | python scan.py --help |
