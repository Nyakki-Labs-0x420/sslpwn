"""
Adaptive rate‑limiting manager.

Detects server‑side rate limiting (HTTP 429, 503, Retry‑After headers,
connection timeouts/resets) and automatically backs off, rotates VPN,
swaps user‑agent profiles, and changes other request attributes before
continuing.
"""

import time
import random
import logging
from typing import Optional, Dict

from sslpwn.rate_limiter import RateLimiter
from sslpwn.user_agents import UserAgentRotator
from sslpwn.vpn import MullvadVPN
from sslpwn.device_profiles import DeviceProfile

logger = logging.getLogger(__name__)


class AdaptiveManager:
    def __init__(
        self,
        rate_limiter: RateLimiter,
        user_agents: UserAgentRotator,
        vpn: Optional[MullvadVPN],
        base_backoff: float = 1.0,
        max_backoff: float = 60.0,
        error_threshold: int = 3,
    ) -> None:
        self._limiter = rate_limiter
        self._ua_rotator = user_agents
        self._vpn = vpn
        self._base_backoff = base_backoff
        self._max_backoff = max_backoff
        self._error_threshold = error_threshold

        self._consecutive_errors = 0
        self._current_backoff = base_backoff
        self._last_evasion_time = 0.0
        self._current_profile: Optional[DeviceProfile] = None

    def wait_and_prepare(self) -> DeviceProfile:
        """Wait for rate‑limiting token and return a device profile to use.
        Automatically applies evasive actions if rate limiting is suspected."""
        if self._consecutive_errors >= self._error_threshold:
            self._evade()

        if self._current_profile is None:
            self._current_profile = self._ua_rotator.random_profile()

        self._limiter.wait()
        return self._current_profile

    def report_response(
        self,
        status: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Inform the manager of the outcome of a request."""
        is_rate_limited = False

        if status in (429, 503):
            is_rate_limited = True
        if headers and any("retry-after" in k.lower() for k in headers):
            is_rate_limited = True
        if error and error.lower() in ("timeout", "connection reset", "connection refused"):
            is_rate_limited = True

        if is_rate_limited:
            self._consecutive_errors += 1
            logger.info("Rate‑limit indicator received (consecutive: %d)", self._consecutive_errors)
            if self._consecutive_errors >= self._error_threshold:
                self._evade()
        else:
            self._consecutive_errors = 0
            self._current_backoff = self._base_backoff

    def _evade(self) -> None:
        """Perform a full evasion cycle."""
        backoff = min(
            self._current_backoff * (2 ** (self._consecutive_errors - self._error_threshold)),
            self._max_backoff,
        )
        backoff *= random.uniform(0.8, 1.2)
        logger.info("Backing off for %.1f seconds", backoff)
        time.sleep(backoff)

        if self._vpn:
            try:
                self._vpn.rotate_ip()
                logger.info("VPN endpoint rotated")
            except Exception as exc:
                logger.warning("VPN rotation failed: %s", exc)

        self._current_profile = self._ua_rotator.random_profile()
        logger.info("Switched to new device profile: %s", self._current_profile.user_agent)

        self._current_backoff = backoff
        self._last_evasion_time = time.time()