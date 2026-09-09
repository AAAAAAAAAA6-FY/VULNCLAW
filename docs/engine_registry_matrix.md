# 引擎注册一致性矩阵（G.3）

> 由 `scripts/engine_registry_check.py` 生成，**只核对不改注册**。
> 三方：A 引擎类定义（`engines/*.py`）｜ B 导出（`engines/__init__.py`）｜ C 任务池（`phases_taskgen.py`）。

引擎总数：**73**

| 状态 | 数量 | 含义 |
|---|---|---|
| OK（已接入注册/调度链路） | 72 | 已出现在 __init__ 导出或 taskgen 任务池（引擎实际为 glob 自动发现，未显式导出属正常） |
| 两处均缺（需确认是否跑得到） | 1 | 既未导出也未入池，需确认是遗漏注册还是已废弃 |

## 明细

| 引擎名 | 文件 | 类 | 在 __init__ | 在 __all__ | 在任务池 | 状态 |
|---|---|---|---|---|---|---|
| `admin_console_exposure` | framework_zero_day_engines_2.py | AdminConsoleExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `api_security` | api_security_engines.py | APISecurityEngine | 是 | 否 | 是 | OK（已接入注册/调度链路） |
| `api_version_diff` | auxiliary_engines.py | APIVersionDiffEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `auth_enumeration` | leak_logic_engines.py | AuthEnumerationEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `backend_component_cve` | logic_leak_engines_2.py | BackendComponentFingerprintEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `backup_file_leak` | logic_leak_engines_2.py | BackupFileLeakEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `business_logic` | input_engines.py | BusinessLogicEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `cache_poison` | http_engines.py | CachePoisonEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `cloud_container_exposure` | framework_zero_day_engines_2.py | CloudAndContainerExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `cmdi` | web_engines.py | CMDIEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `confluence_exposure` | middleware_exposure_engines.py | ConfluenceExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `container_platform_exposure` | framework_zero_day_engines_2.py | ContainerPlatformExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `container_security` | container_engines.py | ContainerSecurityEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `cors` | input_engines.py | CORSEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `crlf` | input_engines.py | CRLFEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `csrf` | http_advanced_engines.py | CSRFEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `deserialization` | deserialization.py | DeserializationEngine | 是 | 否 | 是 | OK（已接入注册/调度链路） |
| `dns_security` | net_engines.py | DnsSecurityEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `dotnet_deserialization` | dotnet_deserialization.py | DotNetDeserializationEngine | 是 | 否 | 是 | OK（已接入注册/调度链路） |
| `el_injection` | input_engines.py | ELInjectionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `exposure_fingerprint` | exposure_fingerprint_engine.py | ExposureFingerprintEngine | 否 | 否 | 否 | 两处均缺（需确认是否跑得到） |
| `fastjson_deserialization` | framework_zero_day_engines.py | FastjsonDeserializationEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `file_upload` | input_engines.py | FileUploadEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `graphql` | net_engines.py | GraphQLEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `graphql_introspection` | logic_leak_engines_2.py | GraphQLIntrospectionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `host_header` | http_engines.py | HostHeaderEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `hpp` | input_engines.py | HPPEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `http2_ws` | auxiliary_engines.py | HTTP2WebSocketEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `idor` | auth_engines.py | IDOREngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `idor_dual_session` | biz_oracle_engines.py | DualSessionOracleEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `info_leak` | input_engines.py | InfoLeakEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `js_library_cve` | logic_leak_engines_2.py | JsLibraryCveEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `jsonp_hijacking` | web_advanced_engines.py | JSONPHijackingEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `jwt` | auth_engines.py | JWTEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `ldap` | input_engines.py | LDAPEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `lfi` | web_engines.py | LFIEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `llm_injection` | llm_security_engines.py | LLMInjectionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `log4shell` | framework_zero_day_engines.py | Log4ShellEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `mass_assignment` | api_security_engines.py | MassAssignmentEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `mobile_api` | mobile_engines.py | MobileAPIEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `nacos_exposure` | middleware_exposure_engines.py | NacosExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `nosql` | web_engines.py | NoSQLEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `oauth` | auth_engines.py | OAuthEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `open_redirect` | http_engines.py | OpenRedirectEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `password_reset` | auth_engines.py | PasswordResetEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `prometheus_metrics` | logic_leak_engines_2.py | PrometheusMetricsExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `prototype_pollution` | web_advanced_engines.py | PrototypePollutionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `race_condition` | http_engines.py | RaceConditionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `rate_limit` | logic_leak_engines_2.py | RateLimitEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `request_smuggling` | auxiliary_engines.py | RequestSmugglingEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `rfi` | web_engines.py | RFIEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `security_headers` | http_engines.py | SecurityHeadersEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `session` | auth_engines.py | SessionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `shiro_rememberme` | framework_zero_day_engines_2.py | ShiroRememberMeEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `solr_exposure` | middleware_exposure_engines.py | SolrExposureEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `source_code_leak` | leak_logic_engines.py | SourceCodeLeakEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `spring4shell` | framework_zero_day_engines.py | Spring4ShellEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `spring_actuator` | leak_logic_engines.py | SpringActuatorEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `spring_cloud_gateway` | framework_zero_day_engines_2.py | SpringCloudGatewayEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `sqli` | web_engines.py | SQLiEngine | 是 | 是 | 是 | OK（已接入注册/调度链路） |
| `ssi_injection` | web_advanced_engines.py | SSIInjectionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `ssrf` | net_engines.py | SSRFEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `ssti` | web_engines.py | SSTIEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `struts2_ognl` | framework_zero_day_engines.py | Struts2OGNLEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `swagger_api_doc` | logic_leak_engines_2.py | SwaggerApiDocEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `tls_security` | net_engines.py | TlsSecurityEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `verb_tampering` | logic_leak_engines_2.py | VerbTamperingEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `view_state` | framework_zero_day_engines.py | ViewStateEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `weak_credential` | auth_engines.py | WeakCredentialEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `web_cache_deception` | http_advanced_engines.py | WebCacheDeceptionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `xpath_injection` | web_advanced_engines.py | XPathInjectionEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `xss` | web_engines.py | XSSEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |
| `xxe` | net_engines.py | XXEEngine | 否 | 否 | 是 | OK（已接入注册/调度链路） |

## 任务池中未匹配到引擎定义的名字（需人工确认）

- `access_key`
- `ai_reason`
- `ai_verdict`
- `alive_assets`
- `api_calls_saved`
- `api_check`
- `api_key`
- `api_version`
- `asset_profile_ttl_hours`
- `auth_token`
- `base_len`
- `burp_params`
- `business_flow_modeling`
- `client_secret`
- `crawl_noparam`
- `crawl_noparam_ssrf`
- `crawled_endpoints`
- `created_at`
- `csrf_token`
- `cve_id`
- `cve_ids`
- `cve_meta`
- `cve_scan`
- `deep_chimera`
- `enable_subdomain_taskgen`
- `engine`
- `engine_bundle`
- `engine_check`
- `engines`
- `global_scan`
- `idor_max_probes`
- `incremental_scan`
- `instruction_context`
- `js_endpoints`
- `line_target`
- `max_extra_engines_per_param`
- `max_param_mining`
- `max_paths`
- `max_subdomain_targets`
- `max_total_tasks`

## 处置原则

1. 「两处均缺」= 引擎定义了但既没导出也没入池 → **扫描时根本跑不到**，需确认是遗漏注册还是已废弃（废弃则由人决定下线，脚本不自动删）。
2. 「仅导出·未进任务池」= 可被单独调用但不参与自动撒网，需确认是否有意。
3. 任何补齐动作后需重跑 `pytest tests/test_engines_core.py` 与 `python scripts/benchmark.py`，确认不回归。
