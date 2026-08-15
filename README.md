# AntiCrawler - 顶级防爬虫中间件系统

一个多层防御的防爬虫系统，提供指纹识别、行为分析、速率限制、挑战验证和威胁情报等功能。

## 特性

### 6层防御体系

1. **IP黑白名单** - 快速通道和直接拦截
2. **威胁情报** - 集成外部威胁情报API
3. **指纹识别** - 识别爬虫和自动化工具特征
4. **速率限制** - 滑动窗口+令牌桶算法
5. **行为分析** - 多维度请求行为模式检测
6. **挑战验证** - JavaScript挑战、数学题、令牌验证

### 指纹识别能力

- 已知搜索引擎爬虫识别(Googlebot、Bingbot等)
- 自动化工具检测(Selenium、Puppeteer、Playwright等)
- HTTP客户端识别(python-requests、curl、wget等)
- 请求头完整性检查
- TLS指纹(JA3)分析
- HTTP/2指纹分析

### 行为分析维度

- 请求频率分析
- 请求间隔规律性检测
- 路径访问模式识别
- 时间间隔异常检测
- 错误率分析

## 快速开始

### 安装依赖

```bash
pip install flask
```

### Flask集成示例

```python
from flask import Flask, request, jsonify, Response
from anticrawler import AntiCrawlerMiddleware, AntiCrawlerConfig

app = Flask(__name__)

# 配置
config = AntiCrawlerConfig(
    enabled=True,
    rate_limit_requests=100,      # 60秒内最大请求数
    rate_limit_window=60,         # 时间窗口(秒)
    burst_limit=20,               # 突发限制
    enable_challenge=True,        # 启用挑战验证
    challenge_threshold=50,       # 触发挑战的分数阈值
)

# 初始化中间件
middleware = AntiCrawlerMiddleware(config)

@app.before_request
def anti_crawler_check():
    request_info = {
        'ip': request.remote_addr,
        'user_agent': request.headers.get('User-Agent', ''),
        'headers': dict(request.headers),
        'path': request.path,
        'method': request.method,
    }
    
    decision = middleware.process_request(request_info)
    
    if decision.action == 'block':
        return Response(decision.body, status=decision.status_code, headers=decision.headers)
    elif decision.action == 'challenge':
        return Response(decision.body, status=decision.status_code, headers=decision.headers)

@app.route('/')
def index():
    return 'Hello, World!'

if __name__ == '__main__':
    app.run()
```

### 运行演示应用

```bash
cd /data/anti-crawler
python demo_app.py
```

访问:
- 主页: http://localhost:5000
- 统计: http://localhost:5000/admin/stats
- 监控面板: 打开 `dashboard/index.html`

### 运行测试

```bash
python tests/test_middleware.py
```

## 配置说明

```python
from anticrawler import AntiCrawlerConfig

config = AntiCrawlerConfig(
    # 基础配置
    enabled=True,                    # 是否启用
    debug=False,                     # 调试模式
    
    # 速率限制
    rate_limit_requests=100,         # 时间窗口内最大请求数
    rate_limit_window=60,            # 时间窗口(秒)
    burst_limit=20,                  # 突发请求限制
    
    # 行为分析
    min_request_interval=0.1,        # 最小请求间隔(秒)
    max_requests_per_minute=60,      # 每分钟最大请求数
    suspicious_patterns_threshold=5, # 可疑模式阈值
    
    # 指纹识别
    block_known_bots=True,           # 拦截已知爬虫
    bot_signatures={'googlebot', 'bingbot', ...},  # 爬虫签名
    
    # 挑战验证
    enable_challenge=True,           # 启用挑战
    challenge_threshold=50,          # 触发挑战的分数
    challenge_duration=300,          # 验证有效期(秒)
    
    # IP黑白名单
    ip_blacklist={'10.0.0.1'},       # 黑名单
    ip_whitelist={'192.168.1.1'},    # 白名单
    
    # User-Agent黑名单
    ua_blacklist={'python-requests', 'scrapy', ...},
    
    # 威胁情报
    enable_threat_intel=False,       # 启用外部威胁情报
    threat_intel_api_key=None,       # API密钥
    
    # 响应配置
    block_status_code=403,           # 拦截状态码
    challenge_status_code=429,       # 挑战状态码
    block_message="Access Denied",   # 拦截消息
    challenge_message="Please verify you are human",
)
```

### 从JSON加载配置

```python
config = AntiCrawlerConfig.from_json('config.json')
```

### 导出配置到JSON

```python
config.to_json('config.json')
```

## API参考

### AntiCrawlerMiddleware

核心中间件类。

#### `process_request(request_info: Dict) -> RequestDecision`

处理请求，返回决策结果。

**request_info 参数:**
- `ip`: 客户端IP (必需)
- `user_agent`: User-Agent字符串
- `headers`: 请求头字典
- `path`: 请求路径
- `method`: HTTP方法
- `session_id`: 会话ID (可选)
- `tls_info`: TLS指纹信息 (可选)
- `h2_settings`: HTTP/2设置 (可选)

**返回值:**
```python
@dataclass
class RequestDecision:
    action: str           # 'allow', 'block', 'challenge'
    reason: str           # 决策原因
    details: Dict         # 详细信息
    headers: Dict         # 响应头
    status_code: int      # HTTP状态码
    body: Optional[str]   # 响应体
```

#### `verify_challenge(ip: str, challenge_id: str, response: str) -> bool`

验证挑战响应。

#### `get_stats() -> Dict`

获取统计信息。

#### `add_ip_to_blacklist(ip: str)`

动态添加IP到黑名单。

#### `remove_ip_from_blacklist(ip: str)`

从黑名单移除IP。

## 挑战验证流程

当系统检测到可疑行为时，会返回挑战页面。支持三种挑战类型:

1. **JavaScript挑战** - 需要浏览器执行计算证明
2. **数学题挑战** - 简单数学题验证
3. **令牌挑战** - 复制令牌并点击验证

验证端点示例:

```python
@app.route('/verify-challenge', methods=['POST'])
def verify_challenge():
    data = request.get_json() or request.form
    
    verified = middleware.verify_challenge(
        request.remote_addr,
        data.get('challenge_id'),
        data.get('response')
    )
    
    if verified:
        return jsonify({'status': 'verified'})
    else:
        return jsonify({'status': 'failed'}), 403
```

## 监控面板

打开 `dashboard/index.html` 查看实时监控面板，包含:

- 请求统计(总数、拦截、验证、放行)
- 请求趋势图表
- 实时日志
- 防御层级状态

## 架构

```
请求 → IP白名单/黑名单 → 威胁情报 → 指纹识别 → 速率限制 → 行为分析 → 挑战验证 → 放行/拦截
```

每个层级独立工作，可以根据需要启用或禁用。

## 性能考虑

- 内存使用: 约10-50MB(取决于并发IP数量)
- CPU开销: <5%(现代服务器)
- 延迟增加: <1ms(纯内存操作)

## 扩展建议

1. **Redis集成** - 使用Redis存储请求历史，支持分布式部署
2. **机器学习** - 添加ML模型进行更精准的行为识别
3. **验证码集成** - 集成reCAPTCHA或hCaptcha
4. **Webhook通知** - 拦截事件通知到Slack/钉钉
5. **持久化存储** - 将日志和统计数据存储到数据库

## License

MIT
