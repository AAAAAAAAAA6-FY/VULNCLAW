# 第三方依赖许可证清单（LICENSES）

> 本文件由 `python scripts/sbom.py --licenses-md docs/LICENSES.md` **离线生成**，请勿手改。
> 许可证信息全部取自本机已安装发行包的元数据（`importlib.metadata`），
> 取不到即记 `UNKNOWN`——如实呈现，不做推测。

- 组件总数（已安装 + pyproject 声明）：**328**
- 许可证未标注（UNKNOWN）：**8**
- 数据源：`pyproject.toml` + 本机 `importlib.metadata`
- 生成时间（UTC）：2026-09-13T04:29:30Z

## 许可证分布

| 许可证 | 组件数 |
| --- | ---: |
| MIT | 71 |
| MIT License | 58 |
| BSD License | 43 |
| Apache Software License | 39 |
| Apache-2.0 | 30 |
| BSD-3-Clause | 24 |
| UNKNOWN | 8 |
| Python Software Foundation License | 5 |
| BSD-2-Clause | 4 |
| ISC License (ISCL) | 4 |
| GNU General Public License v2 (GPLv2) | 3 |
| MIT OR Apache-2.0 | 3 |
| Apache License 2.0 | 2 |
| BSD | 2 |
| GNU | 2 |
| GNU Affero General Public License v3 | 2 |
| GNU General Public License (GPL) | 2 |
| LGPL-2.1-or-later | 2 |
| Mozilla Public License 2.0 (MPL 2.0) | 2 |
| 3-Clause BSD License | 1 |
| Apache License, Version 2.0 | 1 |
| Apache-2.0 AND BSD-2-Clause | 1 |
| Apache-2.0 AND CNRI-Python | 1 |
| Apache-2.0 AND MIT | 1 |
| Apache-2.0 OR BSD-2-Clause | 1 |
| Apache-2.0 OR BSD-3-Clause | 1 |
| BSD 3-Clause OR Apache-2.0 | 1 |
| GNU General Public License v2 or later (GPLv2+) | 1 |
| GNU Library or Lesser General Public License (LGPL) | 1 |
| GPL-2.0-or-later | 1 |
| http://www.opensource.org/licenses/mit-license.php | 1 |
| lgpl | 1 |
| MIT AND PSF-2.0 | 1 |
| MIT-0 | 1 |
| MIT-CMU | 1 |
| MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later | 1 |
| MPL-2.0 AND (Apache-2.0 OR MIT) | 1 |
| MPL-2.0 AND MIT | 1 |
| OSI Approved | 1 |
| Other/Proprietary License | 1 |
| PSF-2.0 | 1 |

## 组件明细

| 包名 | 版本 | 许可证 | 依赖范围 |
| --- | --- | --- | --- |
| protobuf | 5.29.6 | 3-Clause BSD License | transitive |
| apkleaks | 2.6.3 | Apache License 2.0 | environment |
| multidict | 6.7.1 | Apache License 2.0 | transitive |
| overrides | 7.7.0 | Apache License, Version 2.0 | transitive |
| aiofiles | 25.1.0 | Apache Software License | direct |
| aiosignal | 1.4.0 | Apache Software License | transitive |
| argcomplete | 3.7.2 | Apache Software License | environment |
| bcrypt | 5.0.0 | Apache Software License | transitive |
| chromadb | 1.5.9 | Apache Software License | direct |
| cyclonedx-python-lib | 11.12.0 | Apache Software License | environment |
| defusedcsv | 3.0.0 | Apache Software License | environment |
| distro | 1.9.0 | Apache Software License | environment |
| fire | 0.4.0 | Apache Software License | environment |
| flatbuffers | 25.12.19 | Apache Software License | transitive |
| google-ai-generativelanguage | 0.6.15 | Apache Software License | environment |
| google-api-core | 2.25.2 | Apache Software License | environment |
| google-api-python-client | 2.198.0 | Apache Software License | environment |
| google-auth | 2.56.2 | Apache Software License | environment |
| google-auth-httplib2 | 0.4.0 | Apache Software License | environment |
| google-generativeai | 0.8.6 | Apache Software License | environment |
| googleapis-common-protos | 1.75.0 | Apache Software License | transitive |
| grpcio-status | 1.71.2 | Apache Software License | environment |
| huggingface_hub | 1.28.0 | Apache Software License | transitive |
| kubernetes | 36.0.3 | Apache Software License | transitive |
| nltk | 3.10.3 | Apache Software License | environment |
| openai | 2.48.0 | Apache Software License | environment |
| pip-api | 0.0.34 | Apache Software License | environment |
| pip_audit | 2.10.1 | Apache Software License | environment |
| propcache | 0.5.2 | Apache Software License | transitive |
| proto-plus | 1.28.2 | Apache Software License | environment |
| py-serializable | 2.1.0 | Apache Software License | environment |
| pyaxmlparser | 0.3.31 | Apache Software License | environment |
| pyinstaller-hooks-contrib | 2026.6 | Apache Software License | environment |
| pyOpenSSL | 26.1.0 | Apache Software License | environment |
| PyPika | 0.51.1 | Apache Software License | transitive |
| requests | 2.34.2 | Apache Software License | direct |
| requests-toolbelt | 1.0.0 | Apache Software License | environment |
| sortedcontainers | 2.4.0 | Apache Software License | transitive |
| tenacity | 9.1.4 | Apache Software License | transitive |
| tokenizers | 0.23.1 | Apache Software License | transitive |
| treelib | 1.6.1 | Apache Software License | environment |
| websocket-client | 1.9.0 | Apache Software License | transitive |
| zopfli | 0.4.3 | Apache Software License | environment |
| bandit | 1.9.4 | Apache-2.0 | environment |
| CacheControl | 0.14.4 | Apache-2.0 | environment |
| coverage | 7.16.0 | Apache-2.0 | transitive |
| fake-useragent | 2.2.0 | Apache-2.0 | environment |
| frozenlist | 1.8.0 | Apache-2.0 | transitive |
| grpcio | 1.83.0 | Apache-2.0 | transitive |
| hf-xet | 1.6.0 | Apache-2.0 | transitive |
| importlib_metadata | 8.7.1 | Apache-2.0 | transitive |
| importlib_resources | 7.1.0 | Apache-2.0 | transitive |
| license-expression | 30.4.4 | Apache-2.0 | environment |
| msgpack | 1.2.2 | Apache-2.0 | environment |
| opentelemetry-api | 1.37.0 | Apache-2.0 | transitive |
| opentelemetry-exporter-otlp-proto-common | 1.37.0 | Apache-2.0 | transitive |
| opentelemetry-exporter-otlp-proto-grpc | 1.44.0 | Apache-2.0 | transitive |
| opentelemetry-exporter-otlp-proto-http | 1.37.0 | Apache-2.0 | environment |
| opentelemetry-instrumentation | 0.58b0 | Apache-2.0 | environment |
| opentelemetry-instrumentation-requests | 0.58b0 | Apache-2.0 | environment |
| opentelemetry-instrumentation-threading | 0.58b0 | Apache-2.0 | environment |
| opentelemetry-proto | 1.37.0 | Apache-2.0 | transitive |
| opentelemetry-sdk | 1.37.0 | Apache-2.0 | transitive |
| opentelemetry-semantic-conventions | 0.58b0 | Apache-2.0 | transitive |
| opentelemetry-util-http | 0.58b0 | Apache-2.0 | environment |
| playwright | 1.61.0 | Apache-2.0 | environment |
| pytest-asyncio | 1.4.0 | Apache-2.0 | direct |
| python-multipart | 0.0.32 | Apache-2.0 | environment |
| selenium | 4.46.0 | Apache-2.0 | environment |
| stevedore | 5.9.1 | Apache-2.0 | environment |
| tzdata | 2026.3 | Apache-2.0 | environment |
| webdriver-manager | 4.1.2 | Apache-2.0 | environment |
| yarl | 1.24.5 | Apache-2.0 | transitive |
| prometheus_client | 0.26.0 | Apache-2.0 AND BSD-2-Clause | environment |
| regex | 2026.7.19 | Apache-2.0 AND CNRI-Python | environment |
| aiohttp | 3.14.3 | Apache-2.0 AND MIT | direct |
| packaging | 26.2 | Apache-2.0 OR BSD-2-Clause | transitive |
| cryptography | 47.0.0 | Apache-2.0 OR BSD-3-Clause | environment |
| cement | 2.6.2 | BSD | environment |
| PySocks | 1.7.1 | BSD | environment |
| uritemplate | 4.2.0 | BSD 3-Clause OR Apache-2.0 | environment |
| amqp | 5.3.1 | BSD License | environment |
| Authlib | 1.7.2 | BSD License | environment |
| billiard | 4.2.4 | BSD License | environment |
| boltons | 21.0.0 | BSD License | environment |
| click-plugins | 1.1.1.2 | BSD License | environment |
| colorama | 0.4.6 | BSD License | transitive |
| contourpy | 1.3.3 | BSD License | environment |
| cssselect2 | 0.9.0 | BSD License | environment |
| cycler | 0.12.1 | BSD License | environment |
| dill | 0.4.1 | BSD License | environment |
| esprima | 4.0.1 | BSD License | environment |
| gitdb | 4.0.12 | BSD License | environment |
| GitPython | 3.0.6 | BSD License | environment |
| glom | 25.12.0 | BSD License | environment |
| httpx | 0.28.1 | BSD License | direct |
| idna | 3.3 | BSD License | transitive |
| itsdangerous | 2.2.0 | BSD License | environment |
| Jinja2 | 3.1.6 | BSD License | environment |
| joserfc | 1.7.4 | BSD License | environment |
| kiwisolver | 1.5.0 | BSD License | environment |
| lz4 | 4.4.5 | BSD License | environment |
| nodeenv | 1.10.0 | BSD License | transitive |
| numpy | 1.26.4 | BSD License | direct |
| pandas | 3.0.5 | BSD License | environment |
| prompt_toolkit | 3.0.53 | BSD License | environment |
| pyasn1_modules | 0.4.2 | BSD License | environment |
| pycryptodomex | 3.23.0 | BSD License | environment |
| pydyf | 0.12.1 | BSD License | environment |
| pyreadline3 | 3.5.6 | BSD License | environment |
| python-dateutil | 2.9.0.post0 | BSD License | transitive |
| qrcode | 8.2 | BSD License | environment |
| reportlab | 5.0.1 | BSD License | environment |
| requests-oauthlib | 2.0.0 | BSD License | transitive |
| scipy | 1.18.1 | BSD License | transitive |
| semantic-version | 2.10.0 | BSD License | environment |
| semver | 3.0.4 | BSD License | environment |
| smmap | 5.0.3 | BSD License | environment |
| threadpoolctl | 3.6.0 | BSD License | transitive |
| tinycss2 | 1.5.1 | BSD License | environment |
| vine | 5.1.0 | BSD License | environment |
| webencodings | 0.5.1 | BSD License | environment |
| websockets | 15.0.1 | BSD License | environment |
| wrapt | 1.17.3 | BSD License | environment |
| boolean.py | 5.0 | BSD-2-Clause | environment |
| pyasn1 | 0.6.4 | BSD-2-Clause | environment |
| pybase64 | 1.5.0 | BSD-2-Clause | transitive |
| Pygments | 2.20.0 | BSD-2-Clause | transitive |
| celery | 5.6.3 | BSD-3-Clause | environment |
| click | 8.4.2 | BSD-3-Clause | transitive |
| click-option-group | 0.5.9 | BSD-3-Clause | environment |
| fakeredis | 2.37.1 | BSD-3-Clause | direct |
| Flask | 3.1.3 | BSD-3-Clause | environment |
| fsspec | 2026.7.0 | BSD-3-Clause | transitive |
| httpcore | 1.0.9 | BSD-3-Clause | transitive |
| joblib | 1.5.3 | BSD-3-Clause | transitive |
| kombu | 5.6.2 | BSD-3-Clause | environment |
| lxml | 6.1.1 | BSD-3-Clause | environment |
| Markdown | 3.10.2 | BSD-3-Clause | environment |
| MarkupSafe | 3.0.3 | BSD-3-Clause | environment |
| networkx | 3.6.1 | BSD-3-Clause | direct |
| oauthlib | 3.3.1 | BSD-3-Clause | transitive |
| psutil | 7.2.2 | BSD-3-Clause | direct |
| pycparser | 3.0 | BSD-3-Clause | transitive |
| python-dotenv | 1.2.2 | BSD-3-Clause | direct |
| pywin32-ctypes | 0.2.3 | BSD-3-Clause | environment |
| scikit-learn | 1.9.0 | BSD-3-Clause | direct |
| sse-starlette | 3.4.8 | BSD-3-Clause | environment |
| starlette | 1.6.0 | BSD-3-Clause | transitive |
| uvicorn | 0.52.4 | BSD-3-Clause | direct |
| wafw00f | 2.4.2 | BSD-3-Clause | environment |
| Werkzeug | 3.1.8 | BSD-3-Clause | environment |
| truffleHog | 2.2.1 | GNU | environment |
| truffleHogRegexes | 0.0.7 | GNU | environment |
| arjun | 2.2.7 | GNU Affero General Public License v3 | environment |
| exrex | 0.10.5 | GNU Affero General Public License v3 | environment |
| droopescan | 1.45.1 | GNU General Public License (GPL) | environment |
| python-nmap | 0.7.1 | GNU General Public License (GPL) | environment |
| fuzzywuzzy | 0.18.0 | GNU General Public License v2 (GPLv2) | environment |
| pyinstaller | 6.22.2 | GNU General Public License v2 (GPLv2) | environment |
| sqlmap | 1.10.7 | GNU General Public License v2 (GPLv2) | environment |
| pyphen | 0.17.2 | GNU General Public License v2 or later (GPLv2+) | environment |
| chardet | 5.0.0 | GNU Library or Lesser General Public License (LGPL) | environment |
| pylint | 4.0.7 | GPL-2.0-or-later | environment |
| WMI | 1.5.1 | http://www.opensource.org/licenses/mit-license.php | environment |
| dnspython | 2.8.0 | ISC License (ISCL) | direct |
| httpx-ntlm | 1.4.0 | ISC License (ISCL) | environment |
| requests_ntlm | 1.3.0 | ISC License (ISCL) | environment |
| shellingham | 1.5.4 | ISC License (ISCL) | transitive |
| browser-cookie3 | 0.20.1 | lgpl | environment |
| astroid | 4.0.4 | LGPL-2.1-or-later | environment |
| semgrep | 1.175.0 | LGPL-2.1-or-later | environment |
| annotated-doc | 0.0.5 | MIT | transitive |
| annotated-types | 0.8.0 | MIT | transitive |
| anyio | 4.14.2 | MIT | transitive |
| ast_serialize | 0.8.0 | MIT | transitive |
| attrs | 26.1.0 | MIT | transitive |
| bracex | 3.0.1 | MIT | environment |
| brotli | 1.2.0 | MIT | environment |
| build | 1.5.0 | MIT | transitive |
| caido-sdk-client | 0.3.0 | MIT | environment |
| cfgv | 3.5.0 | MIT | transitive |
| click-repl | 0.3.0 | MIT | environment |
| cloakbrowser | 0.5.8 | MIT | environment |
| curl_cffi | 0.15.0 | MIT | direct |
| durationpy | 0.10 | MIT | transitive |
| fastapi | 0.141.1 | MIT | direct |
| filelock | 3.32.3 | MIT | transitive |
| flask-cors | 6.0.5 | MIT | environment |
| fonttools | 4.63.0 | MIT | environment |
| gql | 4.0.0 | MIT | environment |
| h2 | 4.4.1 | MIT | environment |
| hpack | 4.2.0 | MIT | environment |
| httptools | 0.8.0 | MIT | environment |
| httpx-sse | 0.4.3 | MIT | environment |
| identify | 2.6.19 | MIT | transitive |
| iniconfig | 2.3.0 | MIT | transitive |
| isort | 8.0.1 | MIT | environment |
| jiter | 0.16.0 | MIT | environment |
| jsonschema | 4.25.1 | MIT | transitive |
| jsonschema-specifications | 2025.9.1 | MIT | transitive |
| librt | 0.15.0 | MIT | transitive |
| marshmallow | 4.3.1 | MIT | environment |
| mypy | 2.3.1 | MIT | direct |
| mypy_extensions | 1.1.0 | MIT | transitive |
| narwhals | 2.24.0 | MIT | transitive |
| pefile | 2024.8.26 | MIT | environment |
| pip | 26.1.2 | MIT | environment |
| pip-requirements-parser | 32.0.1 | MIT | environment |
| pipx | 1.16.7 | MIT | environment |
| platformdirs | 4.11.3 | MIT | transitive |
| plotly | 6.9.0 | MIT | environment |
| pre_commit | 4.6.2 | MIT | direct |
| pycodestyle | 2.14.0 | MIT | environment |
| pydantic | 2.13.4 | MIT | direct |
| pydantic-settings | 2.15.0 | MIT | direct |
| pydantic_core | 2.46.4 | MIT | transitive |
| PyJWT | 2.13.0 | MIT | environment |
| pyparsing | 3.3.2 | MIT | environment |
| pyspnego | 0.12.1 | MIT | environment |
| pytest | 9.1.1 | MIT | direct |
| pytest-cov | 7.1.0 | MIT | direct |
| redis | 8.1.0 | MIT | direct |
| referencing | 0.37.0 | MIT | transitive |
| rpds-py | 2026.6.3 | MIT | transitive |
| ruff | 0.16.5 | MIT | direct |
| safety | 3.8.1 | MIT | environment |
| setuptools | 83.0.0 | MIT | environment |
| sspilib | 0.5.0 | MIT | environment |
| tomli | 2.4.1 | MIT | transitive |
| truststore | 0.10.4 | MIT | environment |
| typer | 0.25.1 | MIT | transitive |
| typing-inspection | 0.4.2 | MIT | transitive |
| tzlocal | 5.4.4 | MIT | environment |
| urllib3 | 2.7.0 | MIT | transitive |
| userpath | 1.9.2 | MIT | environment |
| virtualenv | 21.7.5 | MIT | transitive |
| wcmatch | 8.5.2 | MIT | environment |
| wcwidth | 0.8.2 | MIT | environment |
| wheel | 0.47.0 | MIT | environment |
| whois | 1.20240129.2 | MIT | environment |
| wsproto | 1.3.2 | MIT | environment |
| zipp | 4.1.0 | MIT | transitive |
| greenlet | 3.5.4 | MIT AND PSF-2.0 | environment |
| altgraph | 0.17.5 | MIT License | environment |
| anthropic | 0.120.2 | MIT License | environment |
| asn1crypto | 1.5.1 | MIT License | environment |
| autopep8 | 2.3.2 | MIT License | environment |
| backoff | 2.2.1 | MIT License | environment |
| beautifulsoup4 | 4.15.0 | MIT License | direct |
| blinker | 1.9.0 | MIT License | environment |
| bs4 | 0.0.1 | MIT License | environment |
| charset-normalizer | 2.1.1 | MIT License | transitive |
| click-didyoumean | 0.3.1 | MIT License | environment |
| coloredlogs | 15.0.1 | MIT License | environment |
| docstring_parser | 0.18.0 | MIT License | environment |
| dparse | 0.6.4 | MIT License | environment |
| exceptiongroup | 1.2.2 | MIT License | transitive |
| flake8 | 7.3.0 | MIT License | environment |
| Flask-Compress | 1.24 | MIT License | environment |
| git-filter-repo | 2.47.0 | MIT License | environment |
| graphql-core | 3.2.11 | MIT License | environment |
| h11 | 0.16.0 | MIT License | transitive |
| httplib2 | 0.32.0 | MIT License | environment |
| humanfriendly | 10.0 | MIT License | environment |
| hyperframe | 6.1.0 | MIT License | environment |
| loguru | 0.6.0 | MIT License | environment |
| markdown-it-py | 4.2.0 | MIT License | transitive |
| mccabe | 0.7.0 | MIT License | environment |
| mcp | 1.29.0 | MIT License | environment |
| mdurl | 0.1.2 | MIT License | transitive |
| mmh3 | 5.2.1 | MIT License | transitive |
| onnxruntime | 1.29.0 | MIT License | transitive |
| outcome | 1.3.0.post0 | MIT License | environment |
| packageurl-python | 0.17.6 | MIT License | environment |
| pluggy | 1.6.0 | MIT License | transitive |
| py-spy | 0.4.2 | MIT License | environment |
| pyee | 13.0.1 | MIT License | environment |
| pyflakes | 3.4.0 | MIT License | environment |
| pyproject_hooks | 1.2.0 | MIT License | transitive |
| pystache | 0.6.8 | MIT License | environment |
| python-discovery | 1.5.3 | MIT License | transitive |
| python-whois | 0.9.6 | MIT License | direct |
| PyYAML | 6.0.3 | MIT License | direct |
| ratelimit | 2.2.1 | MIT License | environment |
| rich | 15.0.0 | MIT License | transitive |
| ruamel.yaml | 0.19.1 | MIT License | environment |
| ruamel.yaml.clib | 0.2.15 | MIT License | environment |
| safety-schemas | 0.0.16 | MIT License | environment |
| shadowcopy | 0.0.4 | MIT License | environment |
| simhash | 2.1.2 | MIT License | environment |
| six | 1.16.0 | MIT License | transitive |
| sniffio | 1.3.1 | MIT License | environment |
| soupsieve | 2.3.2 | MIT License | transitive |
| SQLAlchemy | 1.3.22 | MIT License | environment |
| termcolor | 1.1.0 | MIT License | environment |
| tinyhtml5 | 2.1.0 | MIT License | environment |
| tomli_w | 1.2.0 | MIT License | environment |
| tomlkit | 0.15.1 | MIT License | environment |
| trio-websocket | 0.12.2 | MIT License | environment |
| watchfiles | 1.2.0 | MIT License | environment |
| win32-setctime | 1.1.0 | MIT License | environment |
| structlog | 26.1.0 | MIT OR Apache-2.0 | environment |
| trio | 0.33.0 | MIT OR Apache-2.0 | environment |
| uv | 0.12.5 | MIT OR Apache-2.0 | environment |
| cffi | 2.1.0 | MIT-0 | transitive |
| pillow | 12.3.0 | MIT-CMU | environment |
| certifi | 2026.7.22 | Mozilla Public License 2.0 (MPL 2.0) | transitive |
| pathspec | 1.1.1 | Mozilla Public License 2.0 (MPL 2.0) | transitive |
| tld | 0.13.2 | MPL-1.1 OR GPL-2.0-only OR LGPL-2.1-or-later | environment |
| orjson | 3.12.0 | MPL-2.0 AND (Apache-2.0 OR MIT) | transitive |
| tqdm | 4.70.0 | MPL-2.0 AND MIT | direct |
| future | 0.18.2 | OSI Approved | environment |
| xsstrike | 3.2.2 | Other/Proprietary License | environment |
| typing_extensions | 4.16.0 | PSF-2.0 | transitive |
| aiohappyeyeballs | 2.7.1 | Python Software Foundation License | transitive |
| defusedxml | 0.7.1 | Python Software Foundation License | environment |
| distlib | 0.4.3 | Python Software Foundation License | transitive |
| matplotlib | 3.11.1 | Python Software Foundation License | environment |
| pywin32 | 311 | Python Software Foundation License | environment |
| caido-server-auth | 0.1.2 | UNKNOWN | environment |
| dicttoxml | 1.7.16 | UNKNOWN | environment |
| face | 26.0.1 | UNKNOWN | environment |
| gitdb2 | 4.0.2 | UNKNOWN | environment |
| githacker | 1.1.10 | UNKNOWN | environment |
| peewee | 3.19.0 | UNKNOWN | environment |
| tree-sitter | - | UNKNOWN | declared-missing |
| tree-sitter-languages | - | UNKNOWN | declared-missing |

## 依赖范围说明

- `direct`：`pyproject.toml` 直接声明且本机已安装；
- `transitive`：由直接依赖的基础依赖（非 optional extra）传递引入；
- `environment`：本机已安装但不在依赖闭包内（多为开发/工具类包）；
- `declared-missing`：`pyproject.toml` 声明了但本机未安装（版本字段为空）。
