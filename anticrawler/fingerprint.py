"""
指纹识别模块 - 识别爬虫和自动化工具特征
"""
import re
import hashlib
from typing import Dict, Optional, Tuple
from dataclasses import dataclass


@dataclass
class FingerprintResult:
    """指纹识别结果"""
    is_bot: bool
    confidence: float  # 0-100
    bot_type: Optional[str] = None
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class FingerprintDetector:
    """指纹识别器"""
    
    # 已知爬虫User-Agent特征
    BOT_SIGNATURES = {
        'googlebot': ['googlebot', 'google-inc'],
        'bingbot': ['bingbot', 'msnbot'],
        'baiduspider': ['baiduspider', 'baidu'],
        'yandexbot': ['yandexbot', 'yandex'],
        'sogou': ['sogou'],
        'facebot': ['facebot', 'facebookexternalhit'],
        'ia_archiver': ['ia_archiver', 'alexa'],
        'semrushbot': ['semrushbot'],
        'ahrefsbot': ['ahrefsbot'],
        'mj12bot': ['mj12bot'],
    }
    
    # 自动化工具特征
    AUTOMATION_SIGNATURES = {
        'selenium': ['selenium', 'webdriver'],
        'phantomjs': ['phantomjs'],
        'puppeteer': ['puppeteer'],
        'playwright': ['playwright'],
        'scrapy': ['scrapy'],
        'python-requests': ['python-requests', 'python-urllib'],
        'curl': ['curl/'],
        'wget': ['wget/'],
        'httpclient': ['apache-httpclient', 'java/'],
        'go-http': ['go-http-client'],
        'libwww-perl': ['libwww-perl'],
        'perl': ['perl/'],
        'ruby': ['ruby/'],
        'node-fetch': ['node-fetch'],
        'axios': ['axios/'],
    }
    
    # 浏览器指纹特征
    BROWSER_HEADERS = [
        'accept', 'accept-language', 'accept-encoding',
        'connection', 'upgrade-insecure-requests',
        'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site'
    ]
    
    def __init__(self, config):
        self.config = config
    
    def analyze(self, request_info: Dict) -> FingerprintResult:
        """分析请求指纹"""
        score = 0
        details = {}
        bot_type = None
        
        # 1. User-Agent分析
        ua = request_info.get('user_agent', '').lower()
        
        # 检查已知爬虫
        if self.config.block_known_bots:
            for bot_name, signatures in self.BOT_SIGNATURES.items():
                if any(sig in ua for sig in signatures):
                    return FingerprintResult(
                        is_bot=True,
                        confidence=100.0,
                        bot_type=bot_name,
                        details={'source': 'known_bot', 'ua': ua}
                    )
        
        # 检查自动化工具
        for tool_name, signatures in self.AUTOMATION_SIGNATURES.items():
            if any(sig in ua for sig in signatures):
                score += 80
                bot_type = tool_name
                details['automation_tool'] = tool_name
                break
        
        # 检查UA黑名单
        if any(blacklisted in ua for blacklisted in self.config.ua_blacklist):
            score += 60
            details['ua_blacklist_match'] = True
        
        # 2. 请求头完整性检查
        headers = request_info.get('headers', {})
        header_names = [h.lower() for h in headers.keys()]
        
        missing_headers = [h for h in self.BROWSER_HEADERS if h not in header_names]
        if len(missing_headers) > 3:
            score += 30
            details['missing_headers'] = missing_headers
        
        # 3. 请求头顺序异常
        expected_order = ['host', 'connection', 'accept', 'user-agent']
        actual_order = [h.lower() for h in headers.keys() if h.lower() in expected_order]
        if actual_order and actual_order != sorted(actual_order, key=lambda x: expected_order.index(x) if x in expected_order else 999):
            score += 10
            details['header_order_anomaly'] = True
        
        # 4. TLS指纹(如果可用)
        tls_info = request_info.get('tls_info', {})
        if tls_info:
            # 检查JA3指纹
            ja3 = tls_info.get('ja3', '')
            if self._is_suspicious_ja3(ja3):
                score += 40
                details['suspicious_ja3'] = True
        
        # 5. HTTP/2指纹
        h2_settings = request_info.get('h2_settings', {})
        if h2_settings and self._is_suspicious_h2(h2_settings):
            score += 20
            details['suspicious_h2'] = True
        
        # 6. 空或异常Header值
        if not ua or ua == '-' or len(ua) < 10:
            score += 50
            details['invalid_ua'] = True
        
        # 判断是否为爬虫
        is_bot = score >= 60 or bot_type is not None
        confidence = min(100.0, score)
        
        return FingerprintResult(
            is_bot=is_bot,
            confidence=confidence,
            bot_type=bot_type,
            details=details
        )
    
    def _is_suspicious_ja3(self, ja3: str) -> bool:
        """检查JA3指纹是否可疑"""
        # 已知的可疑JA3指纹
        suspicious_ja3s = {
            'e7d705a3286e19ea42f587b344ee6865',  # curl
            '6734f37431670b3ab4292b8f60f29984',  # python-requests
        }
        return ja3 in suspicious_ja3s
    
    def _is_suspicious_h2(self, h2_settings: Dict) -> bool:
        """检查HTTP/2设置是否可疑"""
        # 检查WINDOW_UPDATE大小等异常
        window_size = h2_settings.get('initial_window_size', 0)
        if window_size > 10000000:  # 异常大的窗口
            return True
        return False
    
    def get_browser_fingerprint(self, request_info: Dict) -> str:
        """生成浏览器指纹哈希"""
        # 基于多个特征生成指纹
        features = []
        
        ua = request_info.get('user_agent', '')
        features.append(ua)
        
        headers = request_info.get('headers', {})
        features.append(','.join(sorted(headers.keys())))
        
        # 添加其他特征
        features.append(request_info.get('accept_language', ''))
        features.append(request_info.get('accept_encoding', ''))
        
        # 生成哈希
        fingerprint_str = '|'.join(features)
        return hashlib.md5(fingerprint_str.encode()).hexdigest()
