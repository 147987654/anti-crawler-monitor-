"""
防爬虫监控 - Flask公网部署版
支持数据库持久化存储
"""
import json
import time
import random
import threading
import os
from datetime import datetime
from collections import defaultdict
from flask import Flask, jsonify, request, Response
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from anticrawler import AntiCrawlerMiddleware, AntiCrawlerConfig


class Database:
    """数据库管理器 - 支持Supabase PostgreSQL"""
    
    def __init__(self):
        self.use_db = False
        self.conn = None
        
        db_url = os.getenv('DATABASE_URL')
        if db_url:
            try:
                import psycopg2
                self.conn = psycopg2.connect(db_url)
                self.use_db = True
                self._init_tables()
                print("✓ 数据库连接成功")
            except Exception as e:
                print(f"✗ 数据库连接失败: {e}")
                print("  使用内存模式运行")
    
    def _init_tables(self):
        with self.conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id SERIAL PRIMARY KEY,
                    ip VARCHAR(45) NOT NULL,
                    reason VARCHAR(255),
                    count INTEGER DEFAULT 1,
                    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(ip)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id SERIAL PRIMARY KEY,
                    time VARCHAR(20) NOT NULL,
                    type VARCHAR(20) NOT NULL,
                    ip VARCHAR(45) NOT NULL,
                    reason VARCHAR(255),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY DEFAULT 1,
                    total_requests INTEGER DEFAULT 0,
                    blocked INTEGER DEFAULT 0,
                    challenged INTEGER DEFAULT 0,
                    allowed INTEGER DEFAULT 0,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cur.execute("INSERT INTO stats (id) VALUES (1) ON CONFLICT (id) DO NOTHING")
            self.conn.commit()
    
    def save_blocked_ip(self, ip, reason):
        if not self.use_db:
            return
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO blocked_ips (ip, reason, count) VALUES (%s, %s, 1)
                    ON CONFLICT (ip) DO UPDATE SET count = blocked_ips.count + 1, reason = %s, last_seen = CURRENT_TIMESTAMP
                """, (ip, reason, reason))
                self.conn.commit()
        except Exception as e:
            print(f"保存IP失败: {e}")
    
    def save_log(self, time_str, log_type, ip, reason):
        if not self.use_db:
            return
        try:
            with self.conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO logs (time, type, ip, reason) VALUES (%s, %s, %s, %s)",
                    (time_str, log_type, ip, reason)
                )
                self.conn.commit()
        except Exception as e:
            print(f"保存日志失败: {e}")
    
    def update_stats(self, total=0, blocked=0, challenged=0, allowed=0):
        if not self.use_db:
            return
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    UPDATE stats SET 
                        total_requests = total_requests + %s,
                        blocked = blocked + %s,
                        challenged = challenged + %s,
                        allowed = allowed + %s,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = 1
                """, (total, blocked, challenged, allowed))
                self.conn.commit()
        except Exception as e:
            print(f"更新统计失败: {e}")
    
    def get_top_ips(self, limit=15):
        if not self.use_db:
            return []
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT ip, count, reason, last_seen 
                    FROM blocked_ips ORDER BY count DESC LIMIT %s
                """, (limit,))
                return [
                    {'ip': r[0], 'count': r[1], 'reason': r[2],
                     'last_seen': r[3].strftime('%H:%M:%S') if r[3] else '',
                     'type': r[2].split(':')[0] if r[2] and ':' in r[2] else (r[2] or '')}
                    for r in cur.fetchall()
                ]
        except Exception as e:
            print(f"获取IP失败: {e}")
            return []
    
    def get_recent_logs(self, limit=50):
        if not self.use_db:
            return []
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT time, type, ip, reason FROM logs ORDER BY id DESC LIMIT %s
                """, (limit,))
                return [{'time': r[0], 'type': r[1], 'ip': r[2], 'reason': r[3]} for r in cur.fetchall()]
        except Exception as e:
            print(f"获取日志失败: {e}")
            return []


class Monitor:
    """监控数据管理器"""
    
    def __init__(self):
        self.config = AntiCrawlerConfig(
            enabled=True, rate_limit_requests=100,
            rate_limit_window=60, burst_limit=20,
            enable_challenge=True, challenge_threshold=50,
        )
        self.middleware = AntiCrawlerMiddleware(self.config)
        self.db = Database()
        self.blocked_ips = defaultdict(lambda: {'count': 0, 'reason': '', 'last_seen': '', 'type': ''})
        self.logs = []
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.running = True
        self._start_simulation()
    
    def _simulate(self):
        while self.running:
            ip = f"{random.choice(['192.168.1','10.0.0','172.16.0','203.0.113','198.51.100'])}.{random.randint(1,254)}"
            r = random.random()
            if r < 0.15:
                ua = random.choice(['Googlebot/2.1','python-requests/2.28.0','Scrapy/2.5','curl/7.68.0','Wget/1.21'])
            elif r < 0.25:
                ua = 'Mozilla/5.0 (compatible; bot)'
            else:
                ua = random.choice([
                    'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X)',
                    'Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36',
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                ])
            
            request_info = {
                'ip': ip, 'user_agent': ua,
                'headers': {'Accept': 'text/html', 'User-Agent': ua},
                'path': f'/page/{random.randint(1,100)}', 'method': 'GET'
            }
            decision = self.middleware.process_request(request_info)
            ts = datetime.now().strftime('%H:%M:%S')
            
            with self.lock:
                if decision.action == 'block':
                    self.blocked_ips[ip]['count'] += 1
                    self.blocked_ips[ip]['reason'] = decision.reason
                    self.blocked_ips[ip]['last_seen'] = ts
                    self.blocked_ips[ip]['type'] = decision.reason.split(':')[0] if ':' in decision.reason else decision.reason
                    self.logs.append({'time': ts, 'type': 'blocked', 'ip': ip, 'reason': decision.reason})
                    self.db.save_blocked_ip(ip, decision.reason)
                    self.db.save_log(ts, 'blocked', ip, decision.reason)
                    self.db.update_stats(total=1, blocked=1)
                elif decision.action == 'challenge':
                    self.logs.append({'time': ts, 'type': 'challenge', 'ip': ip, 'reason': '需要验证'})
                    self.db.save_log(ts, 'challenge', ip, '需要验证')
                    self.db.update_stats(total=1, challenged=1)
                else:
                    self.logs.append({'time': ts, 'type': 'allowed', 'ip': ip, 'reason': '正常'})
                    self.db.save_log(ts, 'allowed', ip, '正常')
                    self.db.update_stats(total=1, allowed=1)
                if len(self.logs) > 500:
                    self.logs = self.logs[-500:]
            time.sleep(random.uniform(0.3, 1.5))
    
    def _start_simulation(self):
        t = threading.Thread(target=self._simulate, daemon=True)
        t.start()
    
    def get_data(self):
        stats = self.middleware.get_stats()
        if self.db.use_db:
            top_ips = self.db.get_top_ips(15)
            recent_logs = self.db.get_recent_logs(50)
        else:
            with self.lock:
                top_ips = sorted(self.blocked_ips.items(), key=lambda x: x[1]['count'], reverse=True)[:15]
                top_ips = [
                    {'ip': ip, 'count': d['count'], 'reason': d['reason'],
                     'last_seen': d['last_seen'], 'type': d['type']}
                    for ip, d in top_ips
                ]
                recent_logs = list(self.logs[-50:])
        return {
            'stats': {
                'total': stats['total_requests'],
                'blocked': stats['blocked'],
                'challenged': stats['challenged'],
                'allowed': stats['allowed'],
                'block_rate': round(stats['block_rate'] * 100, 1),
                'uptime': int(stats['uptime_seconds']),
            },
            'top_ips': top_ips,
            'logs': recent_logs,
        }


# Flask应用
app = Flask(__name__)
monitor = Monitor()


# 读取HTML页面
HTML_PATH = os.path.join(os.path.dirname(__file__), 'index.html')
if os.path.exists(HTML_PATH):
    with open(HTML_PATH, 'r', encoding='utf-8') as f:
        HTML_PAGE = f.read()
else:
    HTML_PAGE = "<h1>index.html not found</h1>"


@app.route('/')
def index():
    return Response(HTML_PAGE, mimetype='text/html')


@app.route('/api/data')
def api_data():
    data = monitor.get_data()
    return jsonify(data)


if __name__ == '__main__':
    port = 8080
    print("=" * 50)
    print("  防爬虫监控系统")
    print(f"  端口: {port}")
    print(f"  数据库: {'已连接' if monitor.db.use_db else '内存模式'}")
    print("=" * 50)
    app.run(host='0.0.0.0', port=port, debug=False)
