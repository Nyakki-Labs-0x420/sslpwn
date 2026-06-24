"""
Device and browser fingerprint profiles that accompany User‑Agent strings.

Each profile includes realistic screen metrics, color depth, device memory,
hardware concurrency, and a VPN country code that matches the device's
expected geographic origin.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass
class DeviceProfile:
    user_agent: str = ""
    # Sec-CH-UA headers
    sec_ch_ua: str = ""
    sec_ch_ua_platform: str = ""
    sec_ch_ua_mobile: str = "?0"
    sec_ch_ua_arch: str = ""
    sec_ch_ua_model: str = ""
    # Viewport (actual browser window)
    viewport_width: int = 1920
    viewport_height: int = 1080
    dpr: float = 1.0
    # Screen metrics
    screen_width: int = 1920
    screen_height: int = 1080
    color_depth: int = 24
    pixel_depth: int = 24
    # Device memory in GB
    device_memory: int = 8
    hardware_concurrency: int = 8
    # Locale / timezone
    timezone: str = "America/New_York"
    accept_language: str = "en-US,en;q=0.9"
    platform: str = "Win32"
    # Additional HTTP headers
    accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    accept_encoding: str = "gzip, deflate, br"
    # TLS preferences
    ciphers: str = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:ECDHE+AES256:!aNULL:!eNULL:!MD5"
    # Certificate subject fields
    cert_common_name: str = "sslpwn"
    cert_org: str = "sslpwn"
    cert_country: str = "XX"
    # VPN endpoint country (used by adaptive evasion to match IP to profile)
    vpn_country: str = ""

    def as_headers(self) -> Dict[str, str]:
        """Return a dictionary of HTTP headers for this profile."""
        headers = {
            "User-Agent": self.user_agent,
            "Sec-CH-UA": self.sec_ch_ua,
            "Sec-CH-UA-Platform": self.sec_ch_ua_platform,
            "Sec-CH-UA-Mobile": self.sec_ch_ua_mobile,
            "Viewport-Width": str(self.viewport_width),
            "Screen-Width": str(self.screen_width),
            "Screen-Height": str(self.screen_height),
            "Color-Depth": str(self.color_depth),
            "DPR": str(self.dpr),
            "Device-Memory": str(self.device_memory),
            "Accept-Language": self.accept_language,
            "Accept": self.accept,
            "Accept-Encoding": self.accept_encoding,
        }
        if self.sec_ch_ua_arch:
            headers["Sec-CH-UA-Arch"] = self.sec_ch_ua_arch
        if self.sec_ch_ua_model:
            headers["Sec-CH-UA-Model"] = self.sec_ch_ua_model
        return headers


# Profiles now include VPN country codes matching the device's expected location
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
        screen_width=1920,
        screen_height=1080,
        color_depth=24,
        pixel_depth=24,
        device_memory=8,
        hardware_concurrency=8,
        timezone="America/Chicago",
        platform="Win32",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        accept_encoding="gzip, deflate, br",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
        cert_common_name="Desktop Chrome on Windows",
        cert_org="Google Inc.",
        cert_country="US",
        vpn_country="us",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"macOS"',
        sec_ch_ua_mobile="?0",
        viewport_width=1440,
        viewport_height=900,
        dpr=2.0,
        screen_width=1440,
        screen_height=900,
        color_depth=24,
        pixel_depth=24,
        device_memory=16,
        hardware_concurrency=10,
        timezone="Europe/London",
        accept_language="en-GB,en;q=0.9",
        platform="MacIntel",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_encoding="gzip, deflate, br",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
        cert_common_name="Safari on macOS",
        cert_org="Apple Inc.",
        cert_country="GB",
        vpn_country="gb",
    ),
    DeviceProfile(
        user_agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
        sec_ch_ua='"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
        sec_ch_ua_platform='"Linux"',
        sec_ch_ua_mobile="?0",
        viewport_width=1920,
        viewport_height=1080,
        dpr=1.0,
        screen_width=1920,
        screen_height=1080,
        color_depth=24,
        pixel_depth=24,
        device_memory=16,
        hardware_concurrency=12,
        timezone="Europe/Berlin",
        accept_language="de-DE,de;q=0.9,en;q=0.8",
        platform="Linux x86_64",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        accept_encoding="gzip, deflate",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256",
        cert_common_name="Firefox on Linux",
        cert_org="Mozilla",
        cert_country="DE",
        vpn_country="de",
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
        screen_width=390,
        screen_height=844,
        color_depth=24,
        pixel_depth=24,
        device_memory=6,
        hardware_concurrency=6,
        timezone="Asia/Tokyo",
        accept_language="ja-JP,ja;q=0.9,en;q=0.8",
        platform="iPhone",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_encoding="gzip, deflate, br",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
        cert_common_name="Mobile Safari on iPhone",
        cert_org="Apple Inc.",
        cert_country="JP",
        vpn_country="jp",
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
        screen_width=810,
        screen_height=1080,
        color_depth=24,
        pixel_depth=24,
        device_memory=8,
        hardware_concurrency=8,
        timezone="America/Los_Angeles",
        accept_language="en-US,en;q=0.9",
        platform="iPad",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        accept_encoding="gzip, deflate, br",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256",
        cert_common_name="Safari on iPad",
        cert_org="Apple Inc.",
        cert_country="US",
        vpn_country="us",
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
        screen_width=1440,
        screen_height=3088,
        color_depth=24,
        pixel_depth=24,
        device_memory=8,
        hardware_concurrency=8,
        timezone="America/Sao_Paulo",
        accept_language="pt-BR,pt;q=0.9,en;q=0.8",
        platform="Linux armv8l",
        accept="text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        accept_encoding="gzip, deflate, br",
        ciphers="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES128-GCM-SHA256",
        cert_common_name="Chrome on Samsung S23",
        cert_org="Samsung Electronics",
        cert_country="KR",
        vpn_country="kr",
    ),
]
