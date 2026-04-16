from redis import Redis
from rq import Queue

from app.config import get_settings

settings = get_settings()

redis_conn = Redis.from_url(settings.redis_url)
# 60 minutes — covers deep + aggressive scans on slow targets
# (nuclei alone can take 3+ min on real WordPress sites)
scan_queue = Queue("scans", connection=redis_conn, default_timeout=3600)
