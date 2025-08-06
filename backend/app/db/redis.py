import redis.asyncio as redis

REDIS_URL = "redis://localhost:6379"
redis_client = redis.from_url(REDIS_URL, decode_responses=True)

def get_redis():
    return redis_client