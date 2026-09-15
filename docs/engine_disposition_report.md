# 边缘引擎处置建议（G.2 盘点报告）

生成时间：2026-09-15 22:12:19  
盘点引擎总数：**90** ｜ 靶场未覆盖·不可判死：**64** ｜ 需补样本/存疑：**15** ｜ 保留：**11**  
命中统计参考报告：report_http___127_0_0_1_8090_20260914_133428.json, report_http___127_0_0_1_8090_20260913_111702.json, report_http___rest_vulnweb_com_20260913_050815.json

> 本报告由 `scripts/engine_audit.py` 生成，**只出报告不改代码**。

> ## ⚠️ 方法局限（必读）
>
> 1. **零命中 ≠ 引擎无用**。当前唯一可用靶场是 local_lab，只覆盖 XSS/SQLi/SSTI/LFI/CMDI/NoSQL/LDAP/反序列化/.env/重定向/CORS/上传 等十余类；
>    Fastjson、Struts2、Shiro、Solr、Nacos、Confluence、JSONP、XPath 等引擎在该靶场上**永远不可能命中**，属靶场覆盖偏差。
> 2. **引用数少 ≠ 没人用**。引擎靠 glob 自动发现 + `ENGINE_REGISTRY` 按 name 注册，无需显式引用，引用数不再作为「无用」证据。
> 3. 因此**本报告不产出任何「可下线」结论**。判定去留必须先有对应场景的 fixture 与检出率基线（任务卡 G.1），在此之前一律保留。

## 汇总

| 分类 | 数量 | 说明 |
|---|---|---|
| 靶场未覆盖·不可判死 | 64 | 现有靶场无法评估，需先补场景 fixture（G.1） |
| 需补样本/存疑 | 15 | 类别被靶场覆盖但零命中，可能是引擎弱或样例不典型 |
| 保留 | 11 | 近期有命中，确认有效 |
| 可下线结论 | **0** | 无足够依据，**不建议下线任何引擎** |

## 明细

| 引擎名 | 类 | 文件 | 引用数 | 近扫描命中 | 代码行 | 复杂度 | 建议 |
|---|---|---|---|---|---|---|---|
| `playbook_gen` | PlaybookEngine | playbook_engine.py | 1 | 0 | 188 | 中 | 靶场未覆盖·不可判死 |
| `exposure_fingerprint` | ExposureFingerprintEngine | exposure_fingerprint_engine.py | 3 | 0 | 118 | 低 | 靶场未覆盖·不可判死 |
| `view_state` | ViewStateEngine | framework_zero_day_engines.py | 3 | 0 | 82 | 低 | 靶场未覆盖·不可判死 |
| `spring_cloud_gateway` | SpringCloudGatewayEngine | framework_zero_day_engines_2.py | 3 | 0 | 48 | 低 | 靶场未覆盖·不可判死 |
| `container_platform_exposure` | ContainerPlatformExposureEngine | framework_zero_day_engines_2.py | 3 | 0 | 66 | 低 | 靶场未覆盖·不可判死 |
| `web_cache_deception` | WebCacheDeceptionEngine | http_advanced_engines.py | 3 | 0 | 111 | 低 | 靶场未覆盖·不可判死 |
| `_ProbeEngine` | _ProbeEngine | leak_logic_engines.py | 3 | 0 | 18 | 低 | 靶场未覆盖·不可判死 |
| `verb_tampering` | VerbTamperingEngine | logic_leak_engines_2.py | 3 | 0 | 52 | 低 | 靶场未覆盖·不可判死 |
| `prometheus_metrics` | PrometheusMetricsExposureEngine | logic_leak_engines_2.py | 3 | 0 | 43 | 低 | 靶场未覆盖·不可判死 |
| `js_library_cve` | JsLibraryCveEngine | logic_leak_engines_2.py | 3 | 0 | 126 | 低 | 靶场未覆盖·不可判死 |
| `jsonp_hijacking` | JSONPHijackingEngine | web_advanced_engines.py | 3 | 0 | 149 | 低 | 靶场未覆盖·不可判死 |
| `struts2_ognl` | Struts2OGNLEngine | framework_zero_day_engines.py | 4 | 0 | 100 | 低 | 靶场未覆盖·不可判死 |
| `shiro_rememberme` | ShiroRememberMeEngine | framework_zero_day_engines_2.py | 4 | 0 | 67 | 低 | 靶场未覆盖·不可判死 |
| `admin_console_exposure` | AdminConsoleExposureEngine | framework_zero_day_engines_2.py | 4 | 0 | 49 | 低 | 靶场未覆盖·不可判死 |
| `swagger_api_doc` | SwaggerApiDocEngine | logic_leak_engines_2.py | 4 | 0 | 62 | 低 | 靶场未覆盖·不可判死 |
| `rate_limit` | RateLimitEngine | logic_leak_engines_2.py | 4 | 0 | 61 | 低 | 靶场未覆盖·不可判死 |
| `backend_component_cve` | BackendComponentFingerprintEngine | logic_leak_engines_2.py | 4 | 0 | 135 | 低 | 靶场未覆盖·不可判死 |
| `nacos_exposure` | NacosExposureEngine | middleware_exposure_engines.py | 4 | 0 | 88 | 低 | 靶场未覆盖·不可判死 |
| `solr_exposure` | SolrExposureEngine | middleware_exposure_engines.py | 4 | 0 | 76 | 低 | 靶场未覆盖·不可判死 |
| `confluence_exposure` | ConfluenceExposureEngine | middleware_exposure_engines.py | 4 | 0 | 76 | 低 | 靶场未覆盖·不可判死 |
| `mobile_api` | MobileAPIEngine | mobile_engines.py | 4 | 0 | 196 | 中 | 靶场未覆盖·不可判死 |
| `dns_security` | DnsSecurityEngine | net_engines.py | 4 | 0 | 364 | 中 | 靶场未覆盖·不可判死 |
| `PlaybookAction` | PlaybookAction | playbook_engine.py | 4 | 0 | 9 | 低 | 靶场未覆盖·不可判死 |
| `xpath_injection` | XPathInjectionEngine | web_advanced_engines.py | 4 | 0 | 103 | 低 | 需补样本/存疑 |
| `ssi_injection` | SSIInjectionEngine | web_advanced_engines.py | 4 | 0 | 115 | 低 | 需补样本/存疑 |
| `password_reset` | PasswordResetEngine | auth_engines.py | 5 | 0 | 142 | 低 | 靶场未覆盖·不可判死 |
| `fastjson_deserialization` | FastjsonDeserializationEngine | framework_zero_day_engines.py | 5 | 0 | 79 | 低 | 需补样本/存疑 |
| `source_code_leak` | SourceCodeLeakEngine | leak_logic_engines.py | 5 | 0 | 94 | 低 | 需补样本/存疑 |
| `backup_file_leak` | BackupFileLeakEngine | logic_leak_engines_2.py | 5 | 0 | 72 | 低 | 需补样本/存疑 |
| `tls_security` | TlsSecurityEngine | net_engines.py | 5 | 0 | 454 | 高 | 靶场未覆盖·不可判死 |
| `ParsingShadowEngine` | ParsingShadowEngine | parsing_shadow.py | 5 | 0 | 278 | 中 | 靶场未覆盖·不可判死 |
| `WebSocketSecurityEngine` | WebSocketSecurityEngine | websocket_security.py | 5 | 0 | 272 | 中 | 靶场未覆盖·不可判死 |
| `mass_assignment` | MassAssignmentEngine | api_security_engines.py | 6 | 0 | 186 | 中 | 靶场未覆盖·不可判死 |
| `APIVersionEngine` | APIVersionEngine | api_version.py | 6 | 0 | 119 | 低 | 靶场未覆盖·不可判死 |
| `container_security` | ContainerSecurityEngine | container_engines.py | 6 | 0 | 120 | 低 | 靶场未覆盖·不可判死 |
| `DeepChimeraEngine` | DeepChimeraEngine | deep_chimera.py | 6 | 0 | 326 | 中 | 靶场未覆盖·不可判死 |
| `cloud_container_exposure` | CloudAndContainerExposureEngine | framework_zero_day_engines_2.py | 6 | 0 | 120 | 低 | 靶场未覆盖·不可判死 |
| `spring_actuator` | SpringActuatorEngine | leak_logic_engines.py | 6 | 0 | 91 | 低 | 靶场未覆盖·不可判死 |
| `auth_enumeration` | AuthEnumerationEngine | leak_logic_engines.py | 6 | 0 | 95 | 低 | 靶场未覆盖·不可判死 |
| `metamorphic` | MetamorphicEngine | metamorphic_engines.py | 6 | 0 | 510 | 高 | 靶场未覆盖·不可判死 |
| `StateChainEngine` | StateChainEngine | state_chain.py | 6 | 0 | 248 | 中 | 靶场未覆盖·不可判死 |
| `weak_credential` | WeakCredentialEngine | auth_engines.py | 7 | 0 | 240 | 中 | 靶场未覆盖·不可判死 |
| `http2_ws` | HTTP2WebSocketEngine | auxiliary_engines.py | 7 | 0 | 147 | 低 | 靶场未覆盖·不可判死 |
| `prototype_pollution` | PrototypePollutionEngine | web_advanced_engines.py | 7 | 0 | 145 | 低 | 靶场未覆盖·不可判死 |
| `request_smuggling` | RequestSmugglingEngine | auxiliary_engines.py | 8 | 0 | 83 | 低 | 靶场未覆盖·不可判死 |
| `llm_injection` | LLMInjectionEngine | llm_security_engines.py | 8 | 0 | 71 | 低 | 需补样本/存疑 |
| `host_header` | HostHeaderEngine | http_engines.py | 9 | 0 | 393 | 中 | 靶场未覆盖·不可判死 |
| `api_security` | APISecurityEngine | api_security_engines.py | 10 | 0 | 289 | 中 | 靶场未覆盖·不可判死 |
| `WAFBypass` | WAFBypass | auxiliary_engines.py | 10 | 0 | 70 | 低 | 靶场未覆盖·不可判死 |
| `Playbook` | Playbook | playbook_engine.py | 10 | 0 | 22 | 低 | 靶场未覆盖·不可判死 |
| `sequence_chain` | SequenceChainEngine | sequence_engines.py | 10 | 0 | 324 | 中 | 靶场未覆盖·不可判死 |
| `api_version_diff` | APIVersionDiffEngine | auxiliary_engines.py | 11 | 0 | 72 | 低 | 靶场未覆盖·不可判死 |
| `security_headers` | SecurityHeadersEngine | http_engines.py | 11 | 0 | 419 | 高 | 靶场未覆盖·不可判死 |
| `cache_poison` | CachePoisonEngine | http_engines.py | 11 | 0 | 342 | 中 | 靶场未覆盖·不可判死 |
| `InvariantDiffEngine` | InvariantDiffEngine | invariant_diff_engine.py | 11 | 0 | 168 | 中 | 靶场未覆盖·不可判死 |
| `SymbolicLogicEngine` | SymbolicLogicEngine | symbolic_engine.py | 11 | 0 | 69 | 低 | 靶场未覆盖·不可判死 |
| `AntiScanDetector` | AntiScanDetector | auxiliary_engines.py | 12 | 0 | 182 | 中 | 靶场未覆盖·不可判死 |
| `graphql_introspection` | GraphQLIntrospectionEngine | logic_leak_engines_2.py | 13 | 0 | 45 | 低 | 靶场未覆盖·不可判死 |
| `CaseInsensitiveDict` | CaseInsensitiveDict | base.py | 14 | 0 | 22 | 低 | 靶场未覆盖·不可判死 |
| `idor_dual_session` | DualSessionOracleEngine | biz_oracle_engines.py | 14 | 0 | 112 | 低 | 靶场未覆盖·不可判死 |
| `race_condition` | RaceConditionEngine | http_engines.py | 15 | 0 | 184 | 中 | 靶场未覆盖·不可判死 |
| `log4shell` | Log4ShellEngine | framework_zero_day_engines.py | 16 | 0 | 91 | 低 | 靶场未覆盖·不可判死 |
| `dotnet_deserialization` | DotNetDeserializationEngine | dotnet_deserialization.py | 17 | 0 | 254 | 中 | 需补样本/存疑 |
| `file_upload` | FileUploadEngine | input_engines.py | 20 | 0 | 648 | 高 | 需补样本/存疑 |
| `business_logic` | BusinessLogicEngine | input_engines.py | 20 | 0 | 962 | 高 | 靶场未覆盖·不可判死 |
| `rfi` | RFIEngine | web_engines.py | 20 | 0 | 122 | 低 | 需补样本/存疑 |
| `el_injection` | ELInjectionEngine | input_engines.py | 21 | 0 | 315 | 中 | 需补样本/存疑 |
| `open_redirect` | OpenRedirectEngine | http_engines.py | 24 | 0 | 325 | 中 | 需补样本/存疑 |
| `info_leak` | InfoLeakEngine | input_engines.py | 24 | 0 | 389 | 中 | 需补样本/存疑 |
| `csrf` | CSRFEngine | http_advanced_engines.py | 29 | 0 | 98 | 低 | 靶场未覆盖·不可判死 |
| `oauth` | OAuthEngine | auth_engines.py | 39 | 0 | 407 | 高 | 靶场未覆盖·不可判死 |
| `deserialization` | DeserializationEngine | deserialization.py | 45 | 0 | 374 | 中 | 需补样本/存疑 |
| `cmdi` | CMDIEngine | web_engines.py | 45 | 0 | 416 | 高 | 需补样本/存疑 |
| `jwt` | JWTEngine | auth_engines.py | 47 | 0 | 585 | 高 | 靶场未覆盖·不可判死 |
| `sqli` | SQLiEngine | web_engines.py | 85 | 0 | 962 | 高 | 需补样本/存疑 |
| `graphql` | GraphQLEngine | net_engines.py | 92 | 0 | 727 | 高 | 靶场未覆盖·不可判死 |
| `xxe` | XXEEngine | net_engines.py | 101 | 0 | 355 | 中 | 靶场未覆盖·不可判死 |
| `BaseEngine` | BaseEngine | base.py | 123 | 0 | 1039 | 高 | 靶场未覆盖·不可判死 |
| `session` | SessionEngine | auth_engines.py | 1642 | 0 | 254 | 中 | 靶场未覆盖·不可判死 |
| `ssti` | SSTIEngine | web_engines.py | 43 | 1 | 457 | 高 | 保留 |
| `spring4shell` | Spring4ShellEngine | framework_zero_day_engines.py | 5 | 2 | 59 | 低 | 保留 |
| `cors` | CORSEngine | input_engines.py | 29 | 2 | 320 | 中 | 保留 |
| `ldap` | LDAPEngine | input_engines.py | 46 | 2 | 360 | 中 | 保留 |
| `lfi` | LFIEngine | web_engines.py | 68 | 2 | 412 | 高 | 保留 |
| `idor` | IDOREngine | auth_engines.py | 48 | 6 | 624 | 高 | 保留 |
| `ssrf` | SSRFEngine | net_engines.py | 72 | 9 | 625 | 高 | 保留 |
| `hpp` | HPPEngine | input_engines.py | 8 | 10 | 124 | 低 | 保留 |
| `crlf` | CRLFEngine | input_engines.py | 12 | 11 | 432 | 高 | 保留 |
| `nosql` | NoSQLEngine | web_engines.py | 24 | 11 | 202 | 中 | 保留 |
| `xss` | XSSEngine | web_engines.py | 90 | 13 | 584 | 高 | 保留 |

## 下一步

1. '需补样本' 项先由 G.1 补正反例 fixture，跑出真实检出率再决定去留。
2. 本报告**不产出任何「可下线」结论**：判定引擎去留必须先有对应场景的 fixture 与检出率基线（G.1），在此之前一律保留，脚本也不会自动删除。
3. 任何下线动作后需重跑 8090/8091 靶场，确认检出基线不回退。
