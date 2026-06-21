"""
Device and browser fingerprint profiles that accompany User‑Agent strings.
Each profile includes realistic HTTP headers and device metrics.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class DeviceProfile:
    user_agent: str = ""
    sec_ch_ua: str = ""
    sec_ch_ua_platform: str = ""
    sec_ch_ua_mobile: str = "?0"
    sec_ch_ua_arch: str = ""
    sec_ch_ua_model: str = ""
    viewport_width: int = 1920
    viewport_height: int = 1080
    dpr: float = 1.0
    timezone: str = "America/New_York"
    accept_language: str = "en-US,en;q=0.9"
    platform: str = "Win32"

    def as_headers(self) -> Dict[str, str]:
        """Return a dictionary of HTTP headers for this profile."""
        headers = {
            "User-Agent": self.user_agent,
            "Sec-CH-UA": self.sec_ch_ua,
            "Sec-CH-UA-Platform": self.sec_ch_ua_platform,
            "Sec-CH-UA-Mobile": self.sec_ch_ua_mobile,
            "Viewport-Width": str(self.viewport_width),
            "DPR": str(self.dpr),
            "Accept-Language": self.accept_language,
        }
        if self.sec_ch_ua_arch:
            headers["Sec-CH-UA-Arch"] = self.sec_ch_ua_arch
        if self.sec_ch_ua_model:
            headers["Sec-CH-UA-Model"] = self.sec_ch_ua_model
        return headers


# Built‑in list of diverse, modern browser profiles
PROFILES = [
    DeviceProfile(
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Windows"',
        sec_ch_ua_mobile="?0",
        sec_ch_ua_arch='"x86"',
        sec_ch_ua_model='""',
        viewport_width=1920,
        viewport_height=1080,
        dpr=1.0,
        timezone="America/Chicago",
        platform="Win32",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"macOS"',
        sec_ch_ua_mobile="?0",
        viewport_width=1440,
        viewport_height=900,
        dpr=2.0,
        timezone="Europe/London",
        accept_language="en-GB,en;q=0.9",
        platform="MacIntel",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Linux"',
        sec_ch_ua_mobile="?0",
        viewport_width=1920,
        viewport_height=1080,
        dpr=1.0,
        timezone="Europe/Berlin",
        accept_language="de-DE,de;q=0.9,en;q=0.8",
        platform="Linux x86_64",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"iOS"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_model='"iPhone15,2"',
        viewport_width=390,
        viewport_height=844,
        dpr=3.0,
        timezone="Asia/Tokyo",
        accept_language="ja-JP,ja;q=0.9,en;q=0.8",
        platform="iPhone",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"iPadOS"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_model='"iPad13,8"',
        viewport_width=810,
        viewport_height=1080,
        dpr=2.0,
        timezone="America/Los_Angeles",
        accept_language="en-US,en;q=0.9",
        platform="iPad",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (Linux; Android 13; SM-S908B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.43 Mobile Safari/537.36",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Android"',
        sec_ch_ua_mobile="?1",
        sec_ch_ua_model='"SM-S908B"',
        viewport_width=412,
        viewport_height=915,
        dpr=2.75,
        timezone="America/Sao_Paulo",
        accept_language="pt-BR,pt;q=0.9,en;q=0.8",
        platform="Linux armv8l",
    ),
]