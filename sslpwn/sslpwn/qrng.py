"""
Quantum Random Number Generator (QRNG) module for sslpwn.

Fetches true quantum randomness from free, no‑auth REST APIs.
Integrates with the adaptive evasion system for unpredictable behavior.
"""

import os
import logging
import random
import time
from typing import Optional, Union, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


@dataclass
class QRNGResult:
    """Container for QRNG API response."""
    value: Union[int, str, bytes]
    source: str
    verified: bool
    timestamp: datetime = field(default_factory=datetime.now)
    raw_response: Optional[Dict[str, Any]] = None


class QuantumRNG:
    """
    Quantum Random Number Generator client.

    Supports multiple free QRNG APIs with automatic fallback.
    """

    # Available QRNG endpoints
    ENDPOINTS = {
        "atomadic": "https://atomadic.tech/v1/rng/quantum",
        "freeuniversesplitter": "https://api.freeuniversesplitter.com/rndnum",
        "lizaonair": "https://lizaonair.com/qrng/",
    }

    def __init__(
        self,
        pPreferredSource: str = "atomadic",
        pTimeoutSeconds: int = 5,
        pMaxRetries: int = 2,
    ) -> None:
        """
        Initialize the QRNG client.

        Args:
            pPreferredSource: Preferred API source ('atomadic', 'freeuniversesplitter', 'lizaonair')
            pTimeoutSeconds: HTTP timeout per request
            pMaxRetries: Number of fallback attempts if primary fails
        """
        self._preferred_source = pPreferredSource
        self._timeout = pTimeoutSeconds
        self._max_retries = pMaxRetries
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": "sslpwn-qrng/2.1.0"})
        self._last_result: Optional[QRNGResult] = None

    def get_random_int(self, pMin: int = 0, pMax: int = 2**32 - 1) -> int:
        """
        Get a true quantum random integer in the range [min, max].

        Args:
            pMin: Minimum value (inclusive)
            pMax: Maximum value (inclusive)

        Returns:
            A quantum‑derived random integer.

        Raises:
            RuntimeError: If all QRNG sources fail.
        """
        if pMin > pMax:
            raise ValueError("pMin must be <= pMax")

        # Try each source in order of preference
        sources = [self._preferred_source] + [
            s for s in self.ENDPOINTS.keys() if s != self._preferred_source
        ]

        for source in sources:
            try:
                result = self._fetch_from_source(source, pMin, pMax)
                if result is not None:
                    self._last_result = result
                    logger.debug(f"QRNG success from {source}: {result.value}")
                    return result.value
            except Exception as e:
                logger.warning(f"QRNG source {source} failed: {e}")
                continue

        raise RuntimeError("All QRNG sources failed. Falling back to classical PRNG.")

    def get_random_bytes(self, pNumBytes: int) -> bytes:
        """
        Get quantum random bytes.

        Args:
            pNumBytes: Number of random bytes to generate.

        Returns:
            Bytes object containing quantum‑derived randomness.
        """
        # Get a large random integer and convert to bytes
        if pNumBytes <= 4:
            value = self.get_random_int(0, (1 << (pNumBytes * 8)) - 1)
            return value.to_bytes(pNumBytes, "big")

        # For larger requests, fetch multiple integers
        result = b""
        remaining = pNumBytes
        while remaining > 0:
            chunk_size = min(remaining, 4)
            max_val = (1 << (chunk_size * 8)) - 1
            value = self.get_random_int(0, max_val)
            result += value.to_bytes(chunk_size, "big")
            remaining -= chunk_size

        return result

    def get_random_hex(self, pNumBytes: int) -> str:
        """Get quantum random bytes as a hex string."""
        return self.get_random_bytes(pNumBytes).hex()

    def _fetch_from_source(
        self,
        pSource: str,
        pMin: int,
        pMax: int,
    ) -> Optional[QRNGResult]:
        """
        Fetch a random integer from a specific QRNG source.
        """
        url = self.ENDPOINTS.get(pSource)
        if not url:
            return None

        try:
            if pSource == "atomadic":
                return self._fetch_atomadic(url, pMin, pMax)
            elif pSource == "freeuniversesplitter":
                return self._fetch_freeuniversesplitter(url, pMin, pMax)
            elif pSource == "lizaonair":
                return self._fetch_lizaonair(url, pMin, pMax)
            else:
                return None
        except Exception as e:
            logger.warning(f"Error fetching from {pSource}: {e}")
            return None

    def _fetch_atomadic(self, url: str, pMin: int, pMax: int) -> Optional[QRNGResult]:
        """Fetch from atomadic.tech (256‑bit hex)."""
        resp = self._session.get(url, timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()

        hex_str = data.get("random", "").replace("0x", "")
        if not hex_str:
            return None

        value = int(hex_str, 16)
        range_size = pMax - pMin + 1
        scaled = pMin + (value % range_size)

        return QRNGResult(
            value=scaled,
            source="atomadic",
            verified=data.get("verified", False),
            raw_response=data,
        )

    def _fetch_freeuniversesplitter(
        self, url: str, pMin: int, pMax: int
    ) -> Optional[QRNGResult]:
        """Fetch from freeuniversesplitter.com (plain text integer)."""
        resp = self._session.get(url, timeout=self._timeout)
        resp.raise_for_status()

        value = int(resp.text.strip())
        range_size = pMax - pMin + 1
        scaled = pMin + (value % range_size)

        return QRNGResult(
            value=scaled,
            source="freeuniversesplitter",
            verified=True,
            raw_response={"raw": resp.text},
        )

    def _fetch_lizaonair(self, url: str, pMin: int, pMax: int) -> Optional[QRNGResult]:
        """Fetch from lizaonair.com (JSON with 'value' field)."""
        params = {"min": pMin, "max": pMax}
        headers = {"Accept": "application/json"}
        resp = self._session.get(url, params=params, headers=headers, timeout=self._timeout)
        resp.raise_for_status()
        data = resp.json()

        value = data.get("value")
        if value is None:
            return None

        return QRNGResult(
            value=value,
            source="lizaonair",
            verified=True,
            raw_response=data,
        )


# Global singleton
_g_qrng: Optional[QuantumRNG] = None


def get_qrng() -> QuantumRNG:
    """Get or create the global QRNG instance."""
    global _g_qrng
    if _g_qrng is None:
        _g_qrng = QuantumRNG()
    return _g_qrng


def quantum_random_int(pMin: int = 0, pMax: int = 2**32 - 1) -> int:
    """Convenience function: get a quantum random integer."""
    return get_qrng().get_random_int(pMin, pMax)


def quantum_random_bytes(pNumBytes: int) -> bytes:
    """Convenience function: get quantum random bytes."""
    return get_qrng().get_random_bytes(pNumBytes)


def quantum_random_hex(pNumBytes: int) -> str:
    """Convenience function: get quantum random hex string."""
    return get_qrng().get_random_hex(pNumBytes)
