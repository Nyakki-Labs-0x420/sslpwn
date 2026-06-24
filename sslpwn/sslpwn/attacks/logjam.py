"""
Logjam attack (CVE-2015-4000).

Checks if export DHE ciphers are supported. Full exploitation requires
precomputation of 512‑bit DH parameters, which can be done with tools
like openssl dhparam + CADO‑NFS.
"""

import socket
import ssl
from sslpwn.attacks.base import BaseAttack


class LogjamAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def check_vulnerability(self) -> bool:
        """Check if server supports any EXPORT DHE cipher suite."""
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        export_dhe_ciphers = "EXP:EDH"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(export_dhe_ciphers)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def exploit(self) -> bool:
        """
        Perform Logjam check. If vulnerable, log the ephemeral DH parameters
        for later discrete‑log precomputation.
        """
        self.output.log("Starting Logjam check", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        export_dhe_ciphers = "EXP:EDH"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(export_dhe_ciphers)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            sock = self._adaptive_connect_and_report(hostname, port)
        except Exception as e:
            self.output.log(f"Connection failed: {e}", "ERROR")
            return False

        try:
            ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            # We can't easily extract DH params from the Python ssl module.
            # imma js log that the export cipher was accepted. To expl follow instr below XD
            # I may do a writeup on how to accurately do this n have it b effective. mehhhhhh documentation, a red teamers worst nightmare amirite?
            # But the heavy math is up to the user to do XD cz im no matha-magician
            self.output.log(
                "Export DHE cipher accepted. Server is vulnerable to Logjam. "
                "To exploit, capture the ServerKeyExchange with weak DH params and "
                "perform a discrete‑log attack on the 512‑bit prime.",
                "SUCCESS"
            )
            return True
        except Exception as e:
            self.output.log(f"Logjam exploit failed: {e}", "ERROR")
            return False
        finally:
            ssl_sock.close()
