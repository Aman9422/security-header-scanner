"""Regression tests for process-local and shared API rate limiting."""

import hashlib

from src.rate_limit import MemoryRateLimiter, RedisRateLimiter


def test_memory_rate_limiter_enforces_weighted_sliding_window(monkeypatch):
    clock = [100.0]
    monkeypatch.setattr("src.rate_limit.time.monotonic", lambda: clock[0])
    limiter = MemoryRateLimiter(window_seconds=60)

    assert limiter.consume("client-a", cost=2, limit=3) is None
    assert limiter.consume("client-a", cost=1, limit=3) is None
    assert limiter.consume("client-a", cost=1, limit=3) == 60
    clock[0] += 0.5
    assert limiter.consume("client-a", cost=1, limit=3) == 60
    assert limiter.consume("client-b", cost=1, limit=3) is None

    clock[0] += 61
    assert limiter.consume("client-a", cost=1, limit=3) is None


def test_redis_rate_limiter_uses_atomic_script_and_hashed_client_key():
    class RedisStub:
        def __init__(self):
            self.calls = []

        def eval(self, *args):
            self.calls.append(args)
            return [0, 2501]

    client = RedisStub()
    limiter = RedisRateLimiter(client)
    assert limiter.consume("198.51.100.8", cost=2, limit=30) == 3

    script, num_keys, key, window, cost, limit, nonce = client.calls[0]
    assert "redis.call('TIME')" in script
    assert "ZREMRANGEBYSCORE" in script
    assert num_keys == 1
    assert key == "security-header-scanner:rate:" + hashlib.sha256(b"198.51.100.8").hexdigest()
    assert "198.51.100.8" not in key
    assert window == 60_000
    assert cost == 2
    assert limit == 30
    assert nonce


def test_redis_rate_limiter_accepts_atomically_when_backend_allows():
    class RedisStub:
        def eval(self, *args):
            return [1, 0]

    assert RedisRateLimiter(RedisStub()).consume("client", cost=1, limit=10) is None
