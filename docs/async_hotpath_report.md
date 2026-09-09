# 异步热路径体检报告（H.1）

分析方法：AST 静态扫描 `engines/*.py` 中引擎类的 `check/scan/_check/_scan/run`，统计循环、嵌套、正则、编解码、阻塞 sleep、同步 IO、哈希等 CPU 密集特征并打分。  
**本报告只体检、不修改任何引擎行为**（重构成果见 H.2）。

## Top 热路径

| # | 引擎 | 类.方法 | 文件 | 是否 async | 循环 | 最大嵌套 | 密集特征 | 分值 |
|---|---|---|---|---|---|---|---|---|
| 1 | `jwt` | JWTEngine.scan | auth_engines.py | 是 | 4 | 3 | regex×2 | 19.0 |
| 2 | `deserialization` | DeserializationEngine.scan | deserialization.py | 是 | 5 | 2 | - | 16.0 |
| 3 | `dotnet_deserialization` | DotNetDeserializationEngine.scan | dotnet_deserialization.py | 是 | 5 | 2 | - | 16.0 |
| 4 | `idor` | IDOREngine.scan | auth_engines.py | 是 | 3 | 3 | - | 15.0 |
| 5 | `weak_credential` | WeakCredentialEngine.scan | auth_engines.py | 是 | 4 | 2 | decode×1 | 15.0 |
| 6 | `info_leak` | InfoLeakEngine.scan | input_engines.py | 是 | 3 | 2 | regex×1 | 13.0 |
| 7 | `js_library_cve` | JsLibraryCveEngine.scan | logic_leak_engines_2.py | 是 | 3 | 2 | regex×1 | 13.0 |
| 8 | `xxe` | XXEEngine.check | net_engines.py | 是 | 3 | 2 | decode×1 | 13.0 |
| 9 | `mass_assignment` | MassAssignmentEngine.scan | api_security_engines.py | 是 | 3 | 2 | - | 12.0 |
| 10 | `struts2_ognl` | Struts2OGNLEngine.check | framework_zero_day_engines.py | 是 | 3 | 2 | - | 12.0 |

## 判读建议

- **async 但含阻塞 sleep / 同步 IO**：直接阻塞事件循环，优先改为 `asyncio.to_thread`。
- **async 且循环深 + 正则重扫**：CPU 段长，优先把纯计算段挪到线程池（H.2）。
- **非 async 的 check/scan**：本身在线程/子进程执行的可能性需结合调用点确认，若在主事件循环里同步调用同样有风险。
- 分值只用于**排序定位**，不代表绝对耗时；真实耗时以 H.2 修复前后的 DAG 看板 tick 间隔对照为准。

## 下一步（H.2）

对上表 top3 引擎的纯 CPU 段改用 `asyncio.to_thread` 执行，修复后对照 DAG 看板 tick 间隔，确认引擎密集阶段不再劣化。
