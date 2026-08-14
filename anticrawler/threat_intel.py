"""
威胁情报模块 - 集成外部威胁情报源
"""
import time
import hashlib
import threading
from typing import Dict, Optional, Tuple, List
from dataclasses import dataclass
import json
import urllib.request
import urllib.error


@dataclass
class ThreatIntelResult:
    """威胁情报结果"""
    is_threat: bool
    threat_type: Optional[str] = None
    confidence: float = 0.0
    source: Optional[str] = None
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class ThreatIntelligence:
    """威胁情报管理器"""
    
    def __init__(self, config):
        self.config = config
        self.cache = {}  # ip -> {result, timestamp}
        self.lock = threading.Lock()
        self.cache_ttl = 3600  # 缓存1小时
        
        # 本地黑名单
        self.local_blacklist = set(config.ip_blacklist)
        
        # 启动缓存清理线程
        self._start_cleanup_thread()
    
    def check(self, ip: str) -> ThreatIntelResult:
        """检查IP威胁情报"""
        # 1. 检查本地黑名单
        if ip in self.local_blacklist:
            return ThreatIntelResult(
                is_threat=True,
                threat_type='blacklisted',
                confidence=100.0,
                source='local_blacklist'
            )
        
        # 2. 检查缓存
        with self.lock:
            if ip in self.cache:
                cached = self.cache[ip]
                if time.time() - cached['timestamp'] < self.cache_ttl:
                    return cached['result']
        
        # 3. 查询外部威胁情报(如果启用)
        if self.config.enable_threat_intel and self.config.threat_intel_api_key:
            result = self._query_external_api(ip)
        else:
            result = ThreatIntelResult(is_threat=False)
        
        # 4. 缓存结果
        with self.lock:
            self.cache[ip] = {
                'result': result,
                'timestamp': time.time()
            }
        
        return result
    
    def _query_external_api(self, ip: str) -> ThreatIntelResult:
        """查询外部威胁情报API"""
        try:
            # 这里以AbuseIPDB为例
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
            headers = {
                'Key': self.config.threat_intel_api_key,
                'Accept': 'application/json'
            }
            
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                abuse_score = data.get('data', {}).get('abuseConfidenceScore', 0)
                is_malicious = abuse_score > 50
                
                return ThreatIntelResult(
                    is_threat=is_malicious,
                    threat_type='malicious_ip' if is_malicious else None,
                    confidence=float(abuse_score),
                    source='abuseipdb',
                    details={
                        'abuse_score': abuse_score,
                        'country': data.get('data', {}).get('countryCode'),
                        'domain': data.get('data', {}).get('domain'),
                        'total_reports': data.get('data', {}).get('totalReports', 0)
                    }
                )
        except Exception as e:
            # API查询失败，返回未知
            return ThreatIntelResult(
                is_threat=False,
                details={'error': str(e)}
            )
    
    def _start_cleanup_thread(self):
        """启动缓存清理线程"""
        def cleanup():
            while True:
                time.sleep(3600)  # 每小时清理一次
                current_time = time.time()
                
                with self.lock:
                    ips_to_remove = [
                        ip for ip, data in self.cache.items()
                        if current_time - data['timestamp'] > self.cache_ttl
                    ]
                    for ip in ips_to_remove:
                        del self.cache[ip]
        
        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()
    
    def add_to_blacklist(self, ip: str):
        """添加IP到黑名单"""
        self.local_blacklist.add(ip)
    
    def remove_from_blacklist(self, ip: str):
        """从黑名单移除IP"""
        self.local_blacklist.discard(ip)
    
    def get_blacklist(self) -> List[str]:
        """获取黑名单列表"""
        return list(self.local_blacklist)
