"""
核心中间件 - 整合所有防御层
"""
import time
import logging
import json
from typing import Dict, Optional, Callable, Tuple
from dataclasses import dataclass, field

from anticrawler.config import AntiCrawlerConfig
from anticrawler.fingerprint import FingerprintDetector
from anticrawler.behavior import BehaviorAnalyzer
from anticrawler.rate_limiter import SlidingWindowRateLimiter, TokenBucketLimiter
from anticrawler.challenge import ChallengeManager
from anticrawler.threat_intel import ThreatIntelligence


logger = logging.getLogger('anticrawler')


@dataclass
class RequestDecision:
    """请求决策结果"""
    action: str  # 'allow', 'block', 'challenge', 'log'
    reason: str = ''
    details: Dict = field(default_factory=dict)
    headers: Dict = field(default_factory=dict)
    status_code: int = 200
    body: Optional[str] = None


class AntiCrawlerMiddleware:
    """
    防爬虫中间件
    
    防御层级:
    1. IP白名单/黑名单快速通道
    2. 威胁情报检查
    3. 指纹识别
    4. 速率限制
    5. 行为分析
    6. 挑战验证
    """
    
    def __init__(self, config: AntiCrawlerConfig = None):
        self.config = config or AntiCrawlerConfig()
        
        # 初始化各模块
        self.fingerprint_detector = FingerprintDetector(self.config)
        self.behavior_analyzer = BehaviorAnalyzer(self.config)
        self.rate_limiter = SlidingWindowRateLimiter(self.config)
        self.token_bucket = TokenBucketLimiter(self.config)
        self.challenge_manager = ChallengeManager(self.config)
        self.threat_intel = ThreatIntelligence(self.config)
        
        # 统计
        self.stats = {
            'total_requests': 0,
            'blocked': 0,
            'challenged': 0,
            'allowed': 0,
            'start_time': time.time()
        }
        
        # 回调函数
        self.on_block: Optional[Callable] = None
        self.on_challenge: Optional[Callable] = None
        self.on_allow: Optional[Callable] = None
    
    def process_request(self, request_info: Dict) -> RequestDecision:
        """
        处理请求 - 核心入口
        
        request_info 应包含:
        - ip: 客户端IP
        - user_agent: UA字符串
        - headers: 请求头字典
        - path: 请求路径
        - method: HTTP方法
        - session_id: 会话ID(可选)
        - tls_info: TLS指纹(可选)
        - h2_settings: HTTP/2设置(可选)
        """
        if not self.config.enabled:
            return RequestDecision(action='allow', reason='disabled')
        
        ip = request_info.get('ip', 'unknown')
        self.stats['total_requests'] += 1
        
        # ===== 第1层: 白名单快速通道 =====
        if ip in self.config.ip_whitelist:
            self.stats['allowed'] += 1
            return RequestDecision(action='allow', reason='whitelisted')
        
        # ===== 第2层: 黑名单直接拦截 =====
        if ip in self.config.ip_blacklist:
            self.stats['blocked'] += 1
            return self._block_decision('ip_blacklisted', {'ip': ip})
        
        # ===== 第3层: 威胁情报 =====
        threat_result = self.threat_intel.check(ip)
        if threat_result.is_threat:
            self.stats['blocked'] += 1
            return self._block_decision(
                f'threat_intel:{threat_result.threat_type}',
                {'threat_details': threat_result.details}
            )
        
        # ===== 第4层: 指纹识别 =====
        fp_result = self.fingerprint_detector.analyze(request_info)
        if fp_result.is_bot and fp_result.confidence >= 90:
            self.stats['blocked'] += 1
            return self._block_decision(
                f'bot_detected:{fp_result.bot_type}',
                {'fingerprint': fp_result.details, 'confidence': fp_result.confidence}
            )
        
        # ===== 第5层: 速率限制 =====
        rate_result = self.rate_limiter.check(ip)
        if not rate_result.allowed:
            self.stats['blocked'] += 1
            return RequestDecision(
                action='block',
                reason='rate_limit_exceeded',
                status_code=self.config.challenge_status_code,
                headers={
                    'Retry-After': str(int(rate_result.retry_after or 60)),
                    'X-RateLimit-Limit': str(rate_result.limit),
                    'X-RateLimit-Remaining': '0',
                },
                body=json.dumps({
                    'error': self.config.challenge_message,
                    'retry_after': rate_result.retry_after
                })
            )
        
        # 突发检查
        burst_result = self.token_bucket.check(ip)
        if not burst_result.allowed:
            self.stats['blocked'] += 1
            return RequestDecision(
                action='block',
                reason='burst_limit_exceeded',
                status_code=self.config.challenge_status_code,
                headers={
                    'Retry-After': str(int(burst_result.retry_after or 10)),
                },
                body=json.dumps({
                    'error': 'Too many requests',
                    'retry_after': burst_result.retry_after
                })
            )
        
        # ===== 第6层: 行为分析 =====
        behavior_result = self.behavior_analyzer.analyze(ip, request_info)
        
        # ===== 第7层: 综合评分 + 挑战 =====
        if self.config.enable_challenge:
            challenge_result = self.challenge_manager.should_challenge(
                ip,
                behavior_result.risk_score,
                fp_result.confidence
            )
            
            if challenge_result.required:
                self.stats['challenged'] += 1
                challenge_page = self.challenge_manager.get_challenge_page(
                    challenge_result.challenge_data,
                    challenge_result.challenge_type
                )
                return RequestDecision(
                    action='challenge',
                    reason=f'challenge_required:{challenge_result.challenge_type}',
                    status_code=self.config.challenge_status_code,
                    headers={'Content-Type': 'text/html; charset=utf-8'},
                    body=challenge_page,
                    details={
                        'risk_score': behavior_result.risk_score,
                        'fp_score': fp_result.confidence,
                        'patterns': behavior_result.patterns
                    }
                )
        
        # ===== 通过所有检查 =====
        self.stats['allowed'] += 1
        
        # 添加安全响应头
        headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'X-RateLimit-Limit': str(rate_result.limit),
            'X-RateLimit-Remaining': str(rate_result.remaining),
        }
        
        decision = RequestDecision(
            action='allow',
            reason='all_checks_passed',
            headers=headers,
            details={
                'fp_score': fp_result.confidence,
                'behavior_score': behavior_result.risk_score,
                'fp_type': fp_result.bot_type,
                'patterns': behavior_result.patterns
            }
        )
        
        # 日志
        if self.config.log_suspicious and behavior_result.is_suspicious:
            logger.warning(
                f"Suspicious request from {ip}: "
                f"risk={behavior_result.risk_score}, "
                f"patterns={behavior_result.patterns}"
            )
        
        if self.on_allow:
            self.on_allow(decision, request_info)
        
        return decision
    
    def verify_challenge(self, ip: str, challenge_id: str, response: str) -> bool:
        """验证挑战响应"""
        return self.challenge_manager.verify_challenge(ip, challenge_id, response)
    
    def _block_decision(self, reason: str, details: Dict) -> RequestDecision:
        """生成拦截决策"""
        decision = RequestDecision(
            action='block',
            reason=reason,
            status_code=self.config.block_status_code,
            headers={
                'Content-Type': 'application/json',
                'X-Blocked-Reason': reason,
            },
            body=json.dumps({
                'error': self.config.block_message,
                'reason': reason
            }),
            details=details
        )
        
        if self.config.log_blocked:
            logger.warning(f"Blocked request: {reason}, details={details}")
        
        if self.on_block:
            self.on_block(decision)
        
        return decision
    
    def get_stats(self) -> Dict:
        """获取统计信息"""
        uptime = time.time() - self.stats['start_time']
        return {
            **self.stats,
            'uptime_seconds': uptime,
            'block_rate': self.stats['blocked'] / max(1, self.stats['total_requests']),
            'challenge_rate': self.stats['challenged'] / max(1, self.stats['total_requests']),
        }
    
    def add_ip_to_blacklist(self, ip: str):
        """动态添加IP到黑名单"""
        self.config.ip_blacklist.add(ip)
        self.threat_intel.add_to_blacklist(ip)
    
    def remove_ip_from_blacklist(self, ip: str):
        """从黑名单移除IP"""
        self.config.ip_blacklist.discard(ip)
        self.threat_intel.remove_from_blacklist(ip)
