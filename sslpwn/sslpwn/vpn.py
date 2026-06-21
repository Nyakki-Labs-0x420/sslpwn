"""Interface with mullvad-cli for IP rotation."""
import subprocess
import shutil
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class MullvadVPN:
    """Manage Mullvad VPN connections via the mullvad-cli tool."""

    def __init__(self) -> None:
        """Check that mullvad-cli is available."""
        if not shutil.which("mullvad"):
            raise EnvironmentError(
                "mullvad-cli not found. Install it and ensure it is in PATH."
            )

    def is_connected(self) -> bool:
        """Return True if Mullvad is currently connected."""
        try:
            result = subprocess.run(
                ["mullvad", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return "Connected" in result.stdout
        except subprocess.TimeoutExpired:
            logger.warning("mullvad status timed out")
            return False
        except Exception as exc:
            logger.error("Error checking Mullvad status: %s", exc)
            return False

    def connect(self) -> None:
        """Connect to Mullvad (random server)."""
        logger.info("Connecting to Mullvad...")
        try:
            subprocess.run(
                ["mullvad", "connect"],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except subprocess.CalledProcessError as exc:
            logger.error("Mullvad connect failed: %s", exc.stderr)
            raise RuntimeError("Mullvad connect failed.") from exc
        time.sleep(3)

    def disconnect(self) -> None:
        """Disconnect from Mullvad."""
        logger.info("Disconnecting from Mullvad...")
        try:
            subprocess.run(
                ["mullvad", "disconnect"],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except subprocess.CalledProcessError as exc:
            logger.error("Mullvad disconnect failed: %s", exc.stderr)
            raise RuntimeError("Mullvad disconnect failed.") from exc

    def rotate_ip(self, max_retries: int = 3) -> None:
        """Obtain a new IP address by disconnecting and reconnecting."""
        for attempt in range(1, max_retries + 1):
            try:
                self.disconnect()
                time.sleep(1)
                self.connect()
                return
            except RuntimeError:
                logger.warning("Rotation attempt %d failed.", attempt)
                time.sleep(5)
        raise RuntimeError("Failed to rotate IP after multiple attempts.")