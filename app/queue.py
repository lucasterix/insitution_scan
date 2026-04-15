from redis import Redis
from rq import Queue

from app.config import get_settings

settings = get_settings()

redis_conn = Redis.from_url(settings.redis_url)
scan_queue = Queue("scans", connection=redis_conn, default_timeout=1800)
