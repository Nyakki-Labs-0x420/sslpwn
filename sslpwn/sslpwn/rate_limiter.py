"""Rate limiter using a simple token bucket."""
import time
import threading
from typing import Optional


class RateLimiter:
    """Token bucket rate limiter, thread‑safe."""

    def __init__(self, rate: float = 2.0, burst: int = 3) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._lock = threading.Lock()
        self._last_time = time.monotonic()

    def _add_tokens(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_time
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_time = now

    def wait(self) -> None:
        """Block until at least one token is available, then consume it."""
        with self._lock:
            self._add_tokens()
            if self._tokens < 1.0:
                sleep_time = (1.0 - self._tokens) / self._rate
                time.sleep(sleep_time)
                self._add_tokens()
            self._tokens -= 1.0