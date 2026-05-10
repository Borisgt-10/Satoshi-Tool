"""Tests del token bucket RateLimiter."""

import threading
import time

from satoshi_tool.config import RateLimiter


def test_burst_no_blocking():
    """Las primeras 'burst' adquisiciones no deben bloquear."""
    rl = RateLimiter(rate_per_sec=8.0, burst=16)
    start = time.monotonic()
    for _ in range(16):
        rl.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.05, f"burst no debería bloquear, tardó {elapsed:.3f}s"


def test_first_post_burst_blocks():
    """La adquisición 17 (post-burst) debe bloquear ~ 1/rate."""
    rl = RateLimiter(rate_per_sec=8.0, burst=2)
    rl.acquire()
    rl.acquire()
    start = time.monotonic()
    rl.acquire()
    elapsed = time.monotonic() - start
    expected = 1.0 / 8.0
    assert expected * 0.7 < elapsed < expected * 2.0, f"esperado ~{expected}s, fue {elapsed}s"


def test_concurrent_acquires_respect_rate():
    """4 hilos haciendo 25 acquires cada uno = 100 total. A 50/s con burst 5,
    deberían tardar aproximadamente (100-5)/50 = 1.9s."""
    rl = RateLimiter(rate_per_sec=50.0, burst=5)

    def worker():
        for _ in range(25):
            rl.acquire()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    start = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.monotonic() - start
    assert 1.5 < elapsed < 3.0, f"esperado ~1.9s, fue {elapsed:.3f}s"
