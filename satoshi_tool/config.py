"""Constantes y singletons compartidos: paths, sesión HTTP, rate limiter, thread pool."""

from __future__ import annotations

import concurrent.futures
import threading
import time
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PASSPHRASE_HITS_FILEPATH = str(PROJECT_ROOT / "Passphrases_Cazadas.txt")
SEED_HITS_FILEPATH = str(PROJECT_ROOT / "Semillas_Cazadas.txt")

BLOCKSTREAM_BASE = "https://blockstream.info/api"

_HTTP = requests.Session()
_HTTP.headers.update({"User-Agent": "Satoshi-Tool/0.4"})


class RateLimiter:
    """Token bucket simple y thread-safe.
    Permite hasta 'burst' peticiones inmediatas y luego rellena a 'rate_per_sec'."""

    def __init__(self, rate_per_sec: float, burst: int):
        self.rate = float(rate_per_sec)
        self.capacity = int(burst)
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = threading.Lock()

    def acquire(self) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                elapsed = now - self.last
                self.last = now
                self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            time.sleep(wait)


_BLOCKSTREAM_LIMITER = RateLimiter(rate_per_sec=8.0, burst=16)
_HTTP_POOL = concurrent.futures.ThreadPoolExecutor(
    max_workers=8, thread_name_prefix="btc-http"
)

PURPOSE_LABELS = {
    44: "BIP44  (Legacy P2PKH, 1...)",
    49: "BIP49  (P2SH-P2WPKH, 3...)",
    84: "BIP84  (P2WPKH bech32, bc1q...)",
    86: "BIP86  (Taproot P2TR, bc1p...)",
}
