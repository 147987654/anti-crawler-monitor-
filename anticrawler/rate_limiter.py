"""
速率限制模块 - 滑动窗口令牌桶算法
"""
import time
import threading
from typing import Dict, Tuple, Optional
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class RateLimitResult:
    """速率限制结果"""
    allowed: bool
    remaining: int
    retry_after: Optional[float] = None
    limit: int = 0
    window: int = 0


class SlidingWindowRateLimiter:
    """滑动窗口速率限制器"""
    
    def __init__(self, config):
        self.config = config
        self.requests = defaultdict(list)  # key -> [timestamps]
        self.lock = threading.Lock()
    
    def check(self, key: str) -> RateLimitResult:
        """检查是否允许请求"""
        current_time = time.time()
        window = self.config.rate_limit_window
        limit = self.config.rate_limit_requests
        
        with self.lock:
            # 清理过期记录
            cutoff = current_time - window
            self.requests[key] = [
                t for t in self.requests[key] if t > cutoff
            ]
            
            current_count = len(self.requests[key])
            remaining = max(0, limit - current_count)
            
            if current_count >= limit:
                # 计算需要等待的时间
                oldest = self.requests[key][0] if self.requests[key] else current_time
                retry_after = oldest + window - current_time
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after=max(0, retry_after),
                    limit=limit,
                    window=window
                )
            
            # 允许请求，记录时间戳
            self.requests[key].append(current_time)
            return RateLimitResult(
                allowed=True,
                remaining=remaining - 1,
                limit=limit,
                window=window
            )


class TokenBucketLimiter:
    """令牌桶限制器 - 用于突发控制"""
    
    def __init__(self, config):
        self.config = config
        self.buckets = {}  # key -> {tokens, last_time}
        self.lock = threading.Lock()
    
    def check(self, key: str) -> RateLimitResult:
        """检查是否允许请求"""
        current_time = time.time()
        burst = self.config.burst_limit
        refill_rate = burst / self.config.rate_limit_window  # 每秒补充的令牌数
        
        with self.lock:
            if key not in self.buckets:
                self.buckets[key] = {
                    'tokens': burst,
                    'last_time': current_time
                }
            
            bucket = self.buckets[key]
            
            # 补充令牌
            elapsed = current_time - bucket['last_time']
            bucket['tokens'] = min(burst, bucket['tokens'] + elapsed * refill_rate)
            bucket['last_time'] = current_time
            
            if bucket['tokens'] >= 1:
                bucket['tokens'] -= 1
                return RateLimitResult(
                    allowed=True,
                    remaining=int(bucket['tokens']),
                    limit=burst,
                    window=self.config.rate_limit_window
                )
            else:
                # 计算等待时间
                retry_after = (1 - bucket['tokens']) / refill_rate
                return RateLimitResult(
                    allowed=False,
                    remaining=0,
                    retry_after=retry_after,
                    limit=burst,
                    window=self.config.rate_limit_window
                )
