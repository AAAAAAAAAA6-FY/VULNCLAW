from typing import Optional
import requests
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
    
    def detect(self, url: str) -> bool:
        """检测目标是否为SPA应用"""
        try:
            # 获取首页内容作为基线
            resp = self.session.get(url, timeout=10)
            if resp.status_code != 200:
                return False
                
            self.homepage_content = resp.text
            homepage_fingerprint = self._extract_fingerprint(self.homepage_content)
            
            # 随机路径探测（3个不同路径）
            random_paths = [
                f"/{_get_random_path_token(8)}",
                f"/api/{_get_random_path_token(6)}",
                f"/_next/{_get_random_path_token(10)}"
            ]
            
            for path in random_paths:
                test_url = f"{url.rstrip('/')}{path}"
                try:
                    resp = self.session.get(test_url, timeout=5, allow_redirects=False)
                    if resp.status_code == 200:
                        test_fingerprint = self._extract_fingerprint(resp.text)
                        # 如果指纹与首页相同，判定为SPA
                        if test_fingerprint == homepage_fingerprint:
                            self.is_spa = True
                            return True
                except requests.RequestException:
                    continue
            
            return False
            
        except requests.RequestException:
            return False
    
    def get_spa_status(self) -> Optional[bool]:
        """获取SPA检测状态"""
        return self.is_spa if self.homepage_content else None
    
    def get_homepage_fingerprint(self) -> Optional[str]:
        """获取首页指纹"""
        return self._extract_fingerprint(self.homepage_content) if self.homepage_content else None