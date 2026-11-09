"""Rate-limit backends for single-process and multi-worker API deployments."""

import hashlib
import math
import threading
import time
import uuid
from typing import Optional


class MemoryRateLimiter:
    """Thread-safe sliding-window limiter for a single application process."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._buckets = {}
        self._lock = threading.Lock()
        self._operations = 0

    def consume(self, client_key: str, cost: int, limit: int) -> Optional[int]:
        """Consume URL quota or return a retry delay in seconds when denied."""
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            entries = [
                (stamp, amount)
                for stamp, amount in self._buckets.get(client_key, ())
                if stamp > cutoff
            ]
            used = sum(amount for _, amount in entries)
            if used + cost > limit:
                retry_after = max(1, math.ceil(entries[0][0] + self.window_seconds - now)) if entries else self.window_seconds
                self._buckets[client_key] = entries
                return retry_after
            entries.append((now, cost))
            self._buckets[client_key] = entries

            # Bound stale-client memory without walking the map on every request.
            self._operations += 1
            if self._operations % 256 == 0:
                for key, bucket in list(self._buckets.items()):
                    active = [(stamp, amount) for stamp, amount in bucket if stamp > cutoff]
                    if active:
                        self._buckets[key] = active
                    else:
                        self._buckets.pop(key, None)
        return None


class RedisRateLimiter:
    """Redis-backed atomic sliding-window limiter shared across API workers."""

    _SCRIPT = """
    local key = KEYS[1]
    local redis_time = redis.call('TIME')
    local now = tonumber(redis_time[1]) * 1000 + math.floor(tonumber(redis_time[2]) / 1000)
    local window_ms = tonumber(ARGV[1])
    local cost = tonumber(ARGV[2])
    local limit = tonumber(ARGV[3])
    local nonce = ARGV[4]
    redis.call('ZREMRANGEBYSCORE', key, '-inf', now - window_ms)
    local used = redis.call('ZCARD', key)
    if used + cost > limit then
      local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
      if oldest[2] then
        return {0, math.max(1, tonumber(oldest[2]) + window_ms - now)}
      end
      return {0, window_ms}
    end
    for i = 1, cost do
      redis.call('ZADD', key, now, nonce .. ':' .. i)
    end
    redis.call('PEXPIRE', key, window_ms)
    return {1, 0}
    """

    def __init__(self, redis_client, window_seconds: int = 60, key_prefix: str = "security-header-scanner:rate:"):
        self.redis = redis_client
        self.window_seconds = window_seconds
        self.key_prefix = key_prefix

    def consume(self, client_key: str, cost: int, limit: int) -> Optional[int]:
        """Consume URL quota atomically across workers and return wait if denied."""
        digest = hashlib.sha256(client_key.encode("utf-8")).hexdigest()
        response = self.redis.eval(
            self._SCRIPT,
            1,
            self.key_prefix + digest,
            self.window_seconds * 1000,
            cost,
            limit,
            uuid.uuid4().hex,
        )
        if not isinstance(response, (list, tuple)) or len(response) != 2:
            raise RuntimeError("Rate-limit backend returned an invalid response")
        allowed, retry_after_ms = int(response[0]), int(response[1])
        if allowed:
            return None
        return max(1, (retry_after_ms + 999) // 1000)
