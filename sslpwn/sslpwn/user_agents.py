"""Rotate User‑Agent strings and full device profiles."""
import random
import os
from typing import List, Optional

from sslpwn.device_profiles import DeviceProfile, PROFILES

BUILTIN_USER_AGENTS: List[str] = [p.user_agent for p in PROFILES]


class UserAgentRotator:
    """Provide random User‑Agent strings and complete device profiles."""

    def __init__(self, file_path: Optional[str] = None) -> None:
        self._profiles = list(PROFILES)
        if file_path and os.path.isfile(file_path):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    custom_agents = [line.strip() for line in f if line.strip()]
                if custom_agents:
                    self._profiles = [
                        DeviceProfile(user_agent=ua) for ua in custom_agents
                    ]
            except OSError as exc:
                raise RuntimeError(f"Failed to read User‑Agent file: {exc}") from exc

    def random(self) -> str:
        """Return a random User‑Agent string."""
        return random.choice(self._profiles).user_agent

    def random_profile(self) -> DeviceProfile:
        """Return a random device profile (User‑Agent + metrics)."""
        return random.choice(self._profiles)