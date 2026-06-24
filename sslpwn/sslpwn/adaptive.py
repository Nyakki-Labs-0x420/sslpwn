"""
Adaptive rate‑limiting manager with per‑profile TLS certificate generation
and VPN endpoint matching the device profile's country.
"""

import time
import random
import logging
import ssl
import tempfile
import os
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
        self._current_cert_file: Optional[str] = None
        self._current_key_file: Optional[str] = None

    def wait_and_prepare(self) -> DeviceProfile:
        """Wait for token and return the active device profile."""
        if self._consecutive_errors >= self._error_threshold:
            self._evade()

        if self._current_profile is None:
            self._current_profile = self._ua_rotator.random_profile()
            self._generate_cert()

        self._limiter.wait()
        return self._current_profile

    def report_response(
        self,
        status: Optional[int] = None,
        headers: Optional[Dict[str, str]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Inform the manager of the outcome of a request. I added other resp codes js in case. """
        is_rate_limited = False
        if status in (403, 404, 420, 429, 500, 502, 503):
            is_rate_limited = True
        if headers and any(
            h in (k.lower() for k in headers) for h in ("retry-after", "x-retry-after")
        ):
            is_rate_limited = True
        if error and error.lower() in (
            "timeout", "connection reset", "connection refused", "connection aborted"
        ):
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
        """Perform full evasion: backoff, VPN rotation with country match, profile & cert swap."""
        backoff = min(
            self._current_backoff * (2 ** (self._consecutive_errors - self._error_threshold)),
            self._max_backoff,
        )
        backoff *= random.uniform(0.8, 1.2)
        logger.info("Backing off for %.1f seconds", backoff)
        time.sleep(backoff)

        # Clean up old certificate files
        self._cleanup_cert()

        # Swap to a fresh device profile
        self._current_profile = self._ua_rotator.random_profile()
        self._generate_cert()

        # Rotate VPN, using the profile's country code if set
        if self._vpn:
            location = self._current_profile.vpn_country or None
            try:
                self._vpn.rotate_ip(location=location)
                logger.info("VPN endpoint rotated to %s", location or "random")
            except Exception as exc:
                logger.warning("VPN rotation failed: %s", exc)

        logger.info("Switched to new profile: %s", self._current_profile.user_agent)

        self._current_backoff = backoff
        self._last_evasion_time = time.time()

    def _generate_cert(self) -> None:
        """Generate a self‑signed client certificate matching the current profile."""
        profile = self._current_profile
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, profile.cert_common_name),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, profile.cert_org),
            x509.NameAttribute(NameOID.COUNTRY_NAME, profile.cert_country),
        ])
        now = datetime.datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )

        cert_fd, cert_path = tempfile.mkstemp(suffix=".pem")
        key_fd, key_path = tempfile.mkstemp(suffix=".pem")
        with os.fdopen(cert_fd, "wb") as cf:
            cf.write(cert.public_bytes(serialization.Encoding.PEM))
        with os.fdopen(key_fd, "wb") as kf:
            kf.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.TraditionalOpenSSL,
                    serialization.NoEncryption(),
                )
            )

        self._current_cert_file = cert_path
        self._current_key_file = key_path

    def _cleanup_cert(self) -> None:
        for path in (self._current_cert_file, self._current_key_file):
            if path and os.path.exists(path):
                try:
                    os.unlink(path)
                except Exception:
                    pass
        self._current_cert_file = None
        self._current_key_file = None

    def get_cert_files(self) -> Optional[tuple]:
        if self._current_cert_file and self._current_key_file:
            return (self._current_cert_file, self._current_key_file)
        return None

    def cleanup(self) -> None:
        self._cleanup_cert()
