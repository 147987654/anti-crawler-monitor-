"""
行为分析模块 - 分析请求行为模式识别爬虫
"""
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import threading


@dataclass
class RequestRecord:
    """请求记录"""
    timestamp: float
    path: str
    method: str
    status_code: int = 0


@dataclass
class BehaviorResult:
    """行为分析结果"""
    is_suspicious: bool
    risk_score: float  # 0-100
    patterns: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)


class BehaviorAnalyzer:
    """行为分析器"""
    
    def __init__(self, config):
        self.config = config
        self.request_history = defaultdict(list)  # ip -> [RequestRecord]
        self.session_data = defaultdict(dict)  # session_id -> data
        self.lock = threading.Lock()
        
        # 清理过期数据的线程
        self._start_cleanup_thread()
    
    def analyze(self, ip: str, request_info: Dict) -> BehaviorResult:
        """分析请求行为"""
        current_time = time.time()
        path = request_info.get('path', '/')
        method = request_info.get('method', 'GET')
        session_id = request_info.get('session_id', ip)
        
        # 记录请求
        record = RequestRecord(
            timestamp=current_time,
            path=path,
            method=method
        )
        
        with self.lock:
            self.request_history[ip].append(record)
            # 只保留最近5分钟的记录
            cutoff = current_time - 300
            self.request_history[ip] = [
                r for r in self.request_history[ip]
                if r.timestamp > cutoff
            ]
        
        # 多维度分析
        patterns = []
        risk_score = 0
        
        # 1. 请求频率分析
        freq_score, freq_patterns = self._analyze_frequency(ip, current_time)
        risk_score += freq_score
        patterns.extend(freq_patterns)
        
        # 2. 请求模式分析
        pattern_score, pattern_patterns = self._analyze_request_patterns(ip)
        risk_score += pattern_score
        patterns.extend(pattern_patterns)
        
        # 3. 路径访问模式
        path_score, path_patterns = self._analyze_path_patterns(ip)
        risk_score += path_score
        patterns.extend(path_patterns)
        
        # 4. 时间间隔分析
        timing_score, timing_patterns = self._analyze_timing(ip)
        risk_score += timing_score
        patterns.extend(timing_patterns)
        
        # 5. 错误率分析
        error_score, error_patterns = self._analyze_error_rate(ip)
        risk_score += error_score
        patterns.extend(error_patterns)
        
        # 限制最高分
        risk_score = min(100.0, risk_score)
        
        return BehaviorResult(
            is_suspicious=risk_score >= 50,
            risk_score=risk_score,
            patterns=patterns,
            details={
                'request_count': len(self.request_history[ip]),
                'time_window': 300
            }
        )
    
    def _analyze_frequency(self, ip: str, current_time: float) -> Tuple[float, List[str]]:
        """分析请求频率"""
        score = 0
        patterns = []
        
        records = self.request_history[ip]
        if len(records) < 2:
            return score, patterns
        
        # 计算每分钟请求数
        recent = [r for r in records if r.timestamp > current_time - 60]
        rpm = len(recent)
        
        if rpm > self.config.max_requests_per_minute:
            score += 40
            patterns.append(f'high_rpm:{rpm}')
        elif rpm > self.config.max_requests_per_minute * 0.7:
            score += 20
            patterns.append(f'elevated_rpm:{rpm}')
        
        # 突发请求检测
        last_5_seconds = [r for r in records if r.timestamp > current_time - 5]
        if len(last_5_seconds) > self.config.burst_limit:
            score += 30
            patterns.append(f'burst:{len(last_5_seconds)}')
        
        return score, patterns
    
    def _analyze_request_patterns(self, ip: str) -> Tuple[float, List[str]]:
        """分析请求模式"""
        score = 0
        patterns = []
        
        records = self.request_history[ip]
        if len(records) < 3:
            return score, patterns
        
        # 检查规律性间隔(机器人特征)
        intervals = []
        for i in range(1, len(records)):
            intervals.append(records[i].timestamp - records[i-1].timestamp)
        
        if len(intervals) >= 3:
            # 计算间隔的标准差
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            
            # 非常规律的间隔(机器人特征)
            if std_dev < 0.1 and avg_interval < 2:
                score += 35
                patterns.append('regular_interval')
        
        # 检查相同请求重复
        paths = [r.path for r in records[-10:]]
        if len(set(paths)) < len(paths) * 0.3:
            score += 20
            patterns.append('repetitive_requests')
        
        return score, patterns
    
    def _analyze_path_patterns(self, ip: str) -> Tuple[float, List[str]]:
        """分析路径访问模式"""
        score = 0
        patterns = []
        
        records = self.request_history[ip]
        if len(records) < 2:
            return score, patterns
        
        # 检查是否按顺序访问(爬虫特征)
        paths = [r.path for r in records]
        
        # 检测数字递增模式 (如 /page/1, /page/2, /page/3)
        import re
        numeric_paths = []
        for path in paths:
            match = re.search(r'/(\d+)$', path)
            if match:
                numeric_paths.append(int(match.group(1)))
        
        if len(numeric_paths) >= 3:
            is_sequential = all(
                numeric_paths[i] + 1 == numeric_paths[i+1]
                for i in range(len(numeric_paths)-1)
            )
            if is_sequential:
                score += 30
                patterns.append('sequential_paths')
        
        # 检查是否只访问API端点
        api_paths = [p for p in paths if '/api/' in p or p.endswith('.json')]
        if len(api_paths) > len(paths) * 0.8:
            score += 15
            patterns.append('api_focused')
        
        return score, patterns
    
    def _analyze_timing(self, ip: str) -> Tuple[float, List[str]]:
        """分析时间间隔"""
        score = 0
        patterns = []
        
        records = self.request_history[ip]
        if len(records) < 2:
            return score, patterns
        
        # 检查过快的请求
        intervals = [
            records[i].timestamp - records[i-1].timestamp
            for i in range(1, len(records))
        ]
        
        fast_requests = [i for i in intervals if i < self.config.min_request_interval]
        if len(fast_requests) > len(intervals) * 0.5:
            score += 25
            patterns.append('too_fast')
        
        # 检查24/7不间断访问
        if len(records) >= 10:
            first_time = records[0].timestamp
            last_time = records[-1].timestamp
            duration = last_time - first_time
            
            if duration > 0:
                rate = len(records) / duration
                if rate > 2:  # 每秒超过2个请求
                    score += 20
                    patterns.append('sustained_high_rate')
        
        return score, patterns
    
    def _analyze_error_rate(self, ip: str) -> Tuple[float, List[str]]:
        """分析错误率"""
        score = 0
        patterns = []
        
        records = self.request_history[ip]
        if len(records) < 5:
            return score, patterns
        
        # 统计404错误(爬虫探测特征)
        recent = records[-20:]
        error_count = sum(1 for r in recent if r.status_code == 404)
        
        if error_count > len(recent) * 0.3:
            score += 25
            patterns.append(f'high_404_rate:{error_count}/{len(recent)}')
        
        return score, patterns
    
    def _start_cleanup_thread(self):
        """启动清理线程"""
        def cleanup():
            while True:
                time.sleep(600)  # 每10分钟清理一次
                current_time = time.time()
                cutoff = current_time - 3600  # 清理1小时前的数据
                
                with self.lock:
                    ips_to_remove = [
                        ip for ip, records in self.request_history.items()
                        if not records or records[-1].timestamp < cutoff
                    ]
                    for ip in ips_to_remove:
                        del self.request_history[ip]
        
        thread = threading.Thread(target=cleanup, daemon=True)
        thread.start()
    
    def get_session_info(self, ip: str) -> Dict:
        """获取会话信息"""
        records = self.request_history.get(ip, [])
        if not records:
            return {}
        
        return {
            'total_requests': len(records),
            'first_seen': records[0].timestamp,
            'last_seen': records[-1].timestamp,
            'duration': records[-1].timestamp - records[0].timestamp,
            'unique_paths': len(set(r.path for r in records))
        }
