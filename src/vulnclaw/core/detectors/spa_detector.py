from typing import Optional
import asyncio
import aiohttp
import re
import random
import string

def _get_random_path_token(length: int) -> str:
    """生成随机路径片段（本地实现，避免跨模块导入依赖）"""
    return "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(length))

class SpaFingerprintDetector:
    """SPA假404检测器 - 通过随机路径探测识别SPA应用"""
    
    def __init__(self, session: requests.Session):
        self.session = session
        self.is_spa = False
        self.homepage_content = None
        self.fingerprint_patterns = [
            r'<html[^>]*>',
            r'<head[^>]*>',
            r'<body[^>]*>',
            r'<div[^>]*id=["\']root["\']',
            r'<script[^>]*src=["\'][^"\']*["\']',
            r'<meta[^>]*charset=["\']utf-8["\']'
        ]
    
    def _extract_fingerprint(self, content: str) -> str:
        """提取响应的指纹特征"""
        features = []
        for pattern in self.fingerprint_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                features.append(pattern)
        return '|'.join(features)
    
    async def detect(self, url: str) -> bool:
        """检测目标是否为SPA应用（基于传入的 aiohttp ClientSession，须 await）

        注意：构造时传入的 session 是 aiohttp ClientSession（orchestrator 与
        input_engines 均如此），因此这里必须用 await 发起异步请求。早期实现误用
        同步 requests 语义（session.get 返回协程却不 await，再访问 .status_code
        抛 AttributeError 被静默吞掉，且泄漏未 await 协程）——SPA 检测形同虚设。
        """
        try:
            # 获取首页内容作为基线
            async with self.session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status != 200:
                    return False
                self.homepage_content = await resp.text()
            homepage_fingerprint = self._extract_fingerprint(self.homepage_content)

            # 随机路径探测（3个不同路径）
            random_paths = [
                f"/{_get_random_path_token(8)}",
                f"/api/{_get_random_path_token(6)}",
                f"/_next/{_get_random_path_token(10)}",
            ]

            for path in random_paths:
                test_url = f"{url.rstrip('/')}{path}"
                try:
                    async with self.session.get(
                        test_url,
                        timeout=aiohttp.ClientTimeout(total=5),
                        allow_redirects=False,
                    ) as resp:
                        if resp.status == 200:
                            test_fingerprint = self._extract_fingerprint(await resp.text())
                            # 如果指纹与首页相同，判定为SPA
                            if test_fingerprint == homepage_fingerprint:
                                self.is_spa = True
                                return True
                except (aiohttp.ClientError, asyncio.TimeoutError):
                    continue

            return False

        except (aiohttp.ClientError, asyncio.TimeoutError):
            return False
    
    def get_spa_status(self) -> Optional[bool]:
        """获取SPA检测状态"""
        return self.is_spa if self.homepage_content else None
    
    def get_homepage_fingerprint(self) -> Optional[str]:
        """获取首页指纹"""
        return self._extract_fingerprint(self.homepage_content) if self.homepage_content else None