# 测试覆盖盘点与 gap 报告（I.3）

> 由 `scripts/test_coverage_audit.py` 生成，**只盘点不自动补测**。
> 统计口径：测试函数 = `tests/test_*.py` 中以 `test_` 开头的函数；
> 引擎覆盖 = 引擎注册名是否在任何测试文件中被提到（粗略但足以定位 gap）。

- 测试文件：**113** 个
- 测试函数：**1370** 个
- 引擎总数：**73** ｜ 有测试提及：**31** ｜ **未被提及：42**

## 关键模块覆盖

| 模块 | 是否有测试提及 |
|---|---|
| `danger_guard` | 是 |
| `verification_gateway` | 是 |
| `oob_channel` | 是 |
| `smart_queue` | 是 |
| `rate_limiter` | 是 |
| `tool_governance` | 是 |
| `report_generator` | 是 |
| `dedupe` | 是 |
| `finding_lifecycle` | 是 |
| `exploit_verify` | 是 |
| `cost_router` | 是 |
| `provider_failover` | 是 |
| `target_capacity_probe` | 是 |
| `adaptive_concurrency` | 是 |
| `audit_receipt` | 是 |

## 测试分布（按文件）

| 文件 | 测试函数数 |
|---|---|
| test_unit_recon.py | 44 |
| test_optimization_c1_c2_c3.py | 42 |
| test_sp20_redis_backend.py | 40 |
| test_mcp_server.py | 38 |
| test_tool_health.py | 33 |
| test_verification_gateway.py | 33 |
| test_target_capacity_probe.py | 29 |
| test_session_manager.py | 26 |
| test_oob_channel.py | 23 |
| test_plan_e.py | 23 |
| test_request_feed.py | 23 |
| test_instructions.py | 22 |
| test_target_lab.py | 22 |
| test_sp20_master.py | 21 |
| test_sprint3.py | 21 |
| test_remote_agents.py | 20 |
| test_sprint4.py | 20 |
| test_sp19_sqlmap_parse.py | 19 |
| test_burp_integration.py | 18 |
| test_engines_core.py | 18 |
| test_s1_deep_react.py | 18 |
| test_sarif_attack_graph.py | 18 |
| test_sprint2.py | 18 |
| test_tool_output_guard.py | 18 |
| test_live_intake.py | 17 |
| test_sp16_bandit.py | 17 |
| test_attack_graph.py | 16 |
| test_dedupe_core.py | 16 |
| test_asset_profile_incremental.py | 15 |
| test_benchmark_eval.py | 15 |
| test_scheduler_audit.py | 15 |
| test_static_audit.py | 15 |
| test_community_nuclei.py | 14 |
| test_sp29_verify_signal_ldap.py | 14 |
| test_sqlite_resume.py | 14 |
| test_tool_governance.py | 14 |
| test_cve_ingest.py | 13 |
| test_e33_pure_http_crawler.py | 13 |
| test_evidence_pack.py | 13 |
| test_feedback_ledger.py | 13 |
| test_sp17_callgraph_cross.py | 13 |
| test_unit_rate_limiter.py | 13 |
| test_biz_oracle.py | 12 |
| test_core_imports.py | 12 |
| test_oob_evidence.py | 12 |
| test_plugin_market.py | 12 |
| test_sp24_agent_race.py | 12 |
| test_sprint1.py | 12 |
| test_anti_scan_detector.py | 11 |
| test_finding_lifecycle.py | 11 |
| test_llm_cache.py | 11 |
| test_sandbox_runner.py | 11 |
| test_scope_guard.py | 11 |
| test_sp16_graph.py | 11 |
| test_distill_data.py | 10 |
| test_sp17_report.py | 10 |
| test_sp21_deadline_grace.py | 10 |
| test_sp23_tier_router.py | 10 |
| test_stage_tools.py | 10 |
| test_unit_bundle_parse.py | 10 |
| test_asset_profile.py | 9 |
| test_bandit_flywheel.py | 9 |
| test_coverage_ledger.py | 9 |
| test_detection_line1.py | 9 |
| test_z24_oob_evidence.py | 9 |
| test_budget_wiring.py | 8 |
| test_core_registry.py | 8 |
| test_instruction_auth.py | 8 |
| test_integration_smoke.py | 8 |
| test_layout_guard.py | 8 |
| test_memory_feedback.py | 8 |
| test_plan_d.py | 8 |
| test_rule_bazaar.py | 8 |
| test_sp17_impersonate_pool.py | 8 |
| test_autofix.py | 7 |
| test_danger_guard.py | 7 |
| test_param_mining_taskgen.py | 7 |
| test_phase_timeboxed.py | 7 |
| test_sp16_impersonate.py | 7 |
| test_sp18_archive.py | 7 |
| test_sp19_poc_verify.py | 7 |
| test_sp20_worker.py | 7 |
| test_usage_ledger.py | 7 |
| test_cost_router.py | 6 |
| test_e32_diff_cli.py | 6 |
| test_native_tools.py | 6 |
| test_poc_generator.py | 6 |
| test_recon_tools_fixes.py | 6 |
| test_sp17_export.py | 6 |
| test_parsing_shadow.py | 5 |
| test_skill_payload_bridge.py | 5 |
| test_sp15_param_mining_e2e.py | 5 |
| test_sp18_flywheel.py | 5 |
| test_sp18_orch_observability.py | 5 |
| test_sp26_report_diff.py | 5 |
| test_verdict_grading.py | 5 |
| test_cookie_path_fallback.py | 4 |
| test_engine_schema.py | 4 |
| test_human_in_the_loop.py | 4 |
| test_param_pool_backfill.py | 4 |
| test_priv_esc_planner.py | 4 |
| test_scan_main.py | 4 |
| test_sp19_rce_confirm.py | 4 |
| test_state_chain.py | 4 |
| test_stream_verify_window.py | 4 |
| test_target_anti_scan_baseline.py | 4 |
| test_ci_workflow.py | 3 |
| test_deep_chimera.py | 3 |
| test_lessons.py | 3 |
| test_sp21_export_real.py | 2 |
| test_utils_obfuscate.py | 2 |
| test_engine_fixtures.py | 1 |
| test_httpbin_live.py | 0 |

## 引擎测试 gap（42 个从未被测试提及）

| 引擎名 | 文件 | 类 |
|---|---|---|
| `api_security` | api_security_engines.py | APISecurityEngine |
| `mass_assignment` | api_security_engines.py | MassAssignmentEngine |
| `password_reset` | auth_engines.py | PasswordResetEngine |
| `api_version_diff` | auxiliary_engines.py | APIVersionDiffEngine |
| `http2_ws` | auxiliary_engines.py | HTTP2WebSocketEngine |
| `request_smuggling` | auxiliary_engines.py | RequestSmugglingEngine |
| `container_security` | container_engines.py | ContainerSecurityEngine |
| `exposure_fingerprint` | exposure_fingerprint_engine.py | ExposureFingerprintEngine |
| `fastjson_deserialization` | framework_zero_day_engines.py | FastjsonDeserializationEngine |
| `struts2_ognl` | framework_zero_day_engines.py | Struts2OGNLEngine |
| `spring4shell` | framework_zero_day_engines.py | Spring4ShellEngine |
| `view_state` | framework_zero_day_engines.py | ViewStateEngine |
| `shiro_rememberme` | framework_zero_day_engines_2.py | ShiroRememberMeEngine |
| `spring_cloud_gateway` | framework_zero_day_engines_2.py | SpringCloudGatewayEngine |
| `container_platform_exposure` | framework_zero_day_engines_2.py | ContainerPlatformExposureEngine |
| `admin_console_exposure` | framework_zero_day_engines_2.py | AdminConsoleExposureEngine |
| `cloud_container_exposure` | framework_zero_day_engines_2.py | CloudAndContainerExposureEngine |
| `web_cache_deception` | http_advanced_engines.py | WebCacheDeceptionEngine |
| `host_header` | http_engines.py | HostHeaderEngine |
| `race_condition` | http_engines.py | RaceConditionEngine |
| `el_injection` | input_engines.py | ELInjectionEngine |
| `crlf` | input_engines.py | CRLFEngine |
| `business_logic` | input_engines.py | BusinessLogicEngine |
| `hpp` | input_engines.py | HPPEngine |
| `source_code_leak` | leak_logic_engines.py | SourceCodeLeakEngine |
| `auth_enumeration` | leak_logic_engines.py | AuthEnumerationEngine |
| `backup_file_leak` | logic_leak_engines_2.py | BackupFileLeakEngine |
| `swagger_api_doc` | logic_leak_engines_2.py | SwaggerApiDocEngine |
| `verb_tampering` | logic_leak_engines_2.py | VerbTamperingEngine |
| `prometheus_metrics` | logic_leak_engines_2.py | PrometheusMetricsExposureEngine |
| `js_library_cve` | logic_leak_engines_2.py | JsLibraryCveEngine |
| `backend_component_cve` | logic_leak_engines_2.py | BackendComponentFingerprintEngine |
| `nacos_exposure` | middleware_exposure_engines.py | NacosExposureEngine |
| `solr_exposure` | middleware_exposure_engines.py | SolrExposureEngine |
| `confluence_exposure` | middleware_exposure_engines.py | ConfluenceExposureEngine |
| `mobile_api` | mobile_engines.py | MobileAPIEngine |
| `tls_security` | net_engines.py | TlsSecurityEngine |
| `dns_security` | net_engines.py | DnsSecurityEngine |
| `xpath_injection` | web_advanced_engines.py | XPathInjectionEngine |
| `ssi_injection` | web_advanced_engines.py | SSIInjectionEngine |
| `prototype_pollution` | web_advanced_engines.py | PrototypePollutionEngine |
| `jsonp_hijacking` | web_advanced_engines.py | JSONPHijackingEngine |

## 补齐计划（与 G.1 联动，不重复造轮子）

1. **引擎类 gap 优先用 G.1 的 fixture + benchmark 补**：`scripts/benchmark.py` 已支持注入式 mock，给一个引擎加正反例只需在 `tests/fixtures/engines/` 加一个 YAML，无需真实靶场，也无需写 pytest 样板。
2. **关键模块 gap 补单元测试**：上表标「否」的模块优先补（尤其 `danger_guard`、`verification_gateway`、`audit_receipt` 属安全与合规敏感路径）。
3. **不盲目堆测例**：先补「能证明正确性」的最小集合，再随 bug 回归逐步增厚。
