"""
AntiCrawler - 顶级防爬虫中间件系统
多层防御: 指纹识别 → 行为分析 → 速率限制 → 挑战验证 → 威胁情报
"""

__version__ = "1.0.0"

from anticrawler.middleware import AntiCrawlerMiddleware
from anticrawler.config import AntiCrawlerConfig

__all__ = ["AntiCrawlerMiddleware", "AntiCrawlerConfig"]
