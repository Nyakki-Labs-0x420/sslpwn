"""Base class for all attacks."""
from abc import ABC, abstractmethod
from typing import Optional
import socket

from sslpwn.output import OutputManager
from sslpwn.vpn import MullvadVPN
from sslpwn.user_agents import UserAgentRotator
from sslpwn.rate_limiter import RateLimiter
from sslpwn.adaptive import AdaptiveManager


class BaseAttack(ABC):
    """Common attack scaffolding."""

    def __init__(
        self,
        target_url: str,
        output: OutputManager,
        vpn: Optional[MullvadVPN],
        user_agents: UserAgentRotator,
        rate_limiter: RateLimiter,
        adaptive: Optional[AdaptiveManager] = None,
    ) -> None:
        self.target_url = target_url
        self.output = output
        self.vpn = vpn
        self.user_agents = user_agents
        self.rate_limiter = rate_limiter
        self.adaptive = adaptive

    @abstractmethod
    def check_vulnerability(self) -> bool:
        """
        Perform a quick, low‑impact check to determine if the target is
        likely vulnerable to this attack.

        Returns True if vulnerability indicators are present.
        """
        ...

    async def check_vulnerability_async(self) -> bool:
        """
        Async version of the vulnerability check. Defaults to running the
        sync version in a thread. Override in modules that use aiohttp.
        """
        import asyncio
        return await asyncio.to_thread(self.check_vulnerability)

    @abstractmethod
    def exploit(self) -> bool:
        """
        Execute the full exploit against the target.

        Returns True if the exploit succeeded (e.g., cookie decrypted).
        """
        ...

    def _adaptive_connect_and_report(self, hostname: str, port: int) -> socket.socket:
        """Create a socket connection and report success/failure to the adaptive manager."""
        try:
            sock = socket.create_connection((hostname, port), timeout=10)
            if self.adaptive:
                self.adaptive.report_response()  # success
            return sock
        except socket.error as e:
            if self.adaptive:
                self.adaptive.report_response(error=str(e))
            raise
