"""
配置管理模块
"""
from dataclasses import dataclass, field
from typing import Set, Dict, Optional
import json


@dataclass
class AntiCrawlerConfig:
    """防爬虫配置"""
    
    # 基础配置
    enabled: bool = True
    debug: bool = False
    
    # 速率限制
    rate_limit_requests: int = 100  # 时间窗口内最大请求数
    rate_limit_window: int = 60  # 时间窗口(秒)
    burst_limit: int = 20  # 突发请求限制
    
    # 行为分析
    min_request_interval: float = 0.1  # 最小请求间隔(秒)
    max_requests_per_minute: int = 60  # 每分钟最大请求数
    suspicious_patterns_threshold: int = 5  # 可疑模式阈值
    
    # 指纹识别
    block_known_bots: bool = True
    bot_signatures: Set[str] = field(default_factory=lambda: {
        'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
        'sogou', 'facebot', 'ia_archiver', 'alexabot'
    })
    
    # 挑战验证
    enable_challenge: bool = True
    challenge_threshold: int = 50  # 触发挑战的分数阈值
    challenge_duration: int = 300  # 挑战有效期(秒)
    
    # IP黑名单
    ip_blacklist: Set[str] = field(default_factory=set)
    ip_whitelist: Set[str] = field(default_factory=set)
    
    # User-Agent黑名单
    ua_blacklist: Set[str] = field(default_factory=lambda: {
        'python-requests', 'scrapy', 'curl', 'wget',
        'httpclient', 'java/', 'libwww-perl', 'go-http-client'
    })
    
    # 威胁情报
    enable_threat_intel: bool = False
    threat_intel_api_key: Optional[str] = None
    
    # 响应配置
    block_status_code: int = 403
    challenge_status_code: int = 429
    block_message: str = "Access Denied"
    challenge_message: str = "Please verify you are human"
    
    # 日志配置
    log_blocked: bool = True
    log_suspicious: bool = True
    
    @classmethod
    def from_json(cls, json_path: str) -> 'AntiCrawlerConfig':
        """从JSON文件加载配置"""
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # 转换set字段
        for key in ['bot_signatures', 'ip_blacklist', 'ip_whitelist', 'ua_blacklist']:
            if key in data and isinstance(data[key], list):
                data[key] = set(data[key])
        
        return cls(**data)
    
    def to_json(self, json_path: str):
        """导出配置到JSON"""
        data = self.__dict__.copy()
        # 转换set为list
        for key in ['bot_signatures', 'ip_blacklist', 'ip_whitelist', 'ua_blacklist']:
            if key in data:
                data[key] = list(data[key])
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
