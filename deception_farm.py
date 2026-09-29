#!/usr/bin/env python3
"""Isolated, non-executing deception network for defensive research.

The decoys emit synthetic responses and record metadata plus payload hashes.
They never execute commands, authenticate users, store credentials, or make
outbound connections.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import signal
import time
from pathlib import Path
from typing import Any

SERVICE_CONFIG = {
    "http": {"port": 8080, "banner": ""},
    "ssh": {"port": 2222, "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-20.04\r\n"},
    "ftp": {"port": 2121, "banner": "220 FTP Service Ready\r\n"},
    "telnet": {"port": 2323, "banner": "Ubuntu 20.04 LTS login:\r\n"},
}
INDICATOR_RE = re.compile(
    r"(?i)(?:https?://[^\s'\"<>]+|(?:[a-z0-9-]+\.)+[a-z]{2,}|"
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b|powershell|cmd\.exe|"
    r"wget|curl|bash|nc\s|netcat|chmod|/etc/passwd)"
)


def extract_indicators(payload: bytes) -> list[str]:
    text = payload.decode("utf-8", errors="replace")
    findings: list[str] = []
    for match in INDICATOR_RE.findall(text):
        value = match
        if value not in findings:
            if value.startswith(("http://", "https://")):
                findings.append(value[:200])
            else:
                findings.append(value.lower()[:100])
    return findings[:20]


def payload_metadata(payload: bytes) -> dict[str, Any]:
    return {
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "payload_length": len(payload),
        "indicators": extract_indicators(payload),
    }


def valid_peer_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return "unknown"


class EventLogger:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = asyncio.Lock()

    async def write(self, event: dict[str, Any]) -> None:
        line = json.dumps(event, sort_keys=True)
        async with self.lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")


class DeceptionFarm:
    def __init__(self, host: str, log_path: str, max_payload: int = 512) -> None:
        self.host = host
        self.logger = EventLogger(log_path)
        self.max_payload = max_payload
        self.servers: list[asyncio.AbstractServer] = []

    async def start(self) -> None:
        for service, config in SERVICE_CONFIG.items():
            server = await asyncio.start_server(
                lambda reader, writer, service=service: self.handle(service, reader, writer),
                self.host,
                int(config["port"]),
            )
            self.servers.append(server)
            sockets = ", ".join(str(sock.getsockname()) for sock in server.sockets or [])
            print(f"[+] {service} decoy listening on {sockets}")
        print("[+] Safe mode: no command execution, authentication, or outbound traffic")

    async def handle(
        self, service: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername") or ("unknown", 0)
        source_ip = valid_peer_ip(str(peer[0]))
        source_port = int(peer[1]) if len(peer) > 1 and str(peer[1]).isdigit() else None
        destination_port = int(SERVICE_CONFIG[service]["port"])
        opened_at = time.time()
        payload = b""
        try:
            if service != "http":
                writer.write(SERVICE_CONFIG[service]["banner"].encode())
                await writer.drain()
            payload = await asyncio.wait_for(reader.read(self.max_payload), timeout=3)
            await self.log_interaction(
                service, source_ip, source_port, destination_port, payload, opened_at
            )
            if service == "http":
                response = (
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n"
                    b"Content-Length: 75\r\nConnection: close\r\n\r\n"
                    b"<html><title>Maintenance</title><body>Service maintenance</body></html>"
                )
                writer.write(response)
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionError, BrokenPipeError):
            await self.log_interaction(
                service, source_ip, source_port, destination_port, payload, opened_at,
                outcome="timeout-or-disconnect",
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def log_interaction(
        self, service: str, source_ip: str, source_port: int | None,
        destination_port: int, payload: bytes, opened_at: float,
        outcome: str = "observed",
    ) -> None:
        event = {
            "timestamp": time.time(),
            "event_type": "honeypot_interaction",
            "service": service,
            "src_ip": source_ip,
            "src_port": source_port,
            "dst_port": destination_port,
            "duration_ms": round((time.time() - opened_at) * 1000, 2),
            "outcome": outcome,
            "safe_mode": True,
            "payload_stored": False,
            **payload_metadata(payload),
        }
        await self.logger.write(event)

    async def stop(self) -> None:
        for server in self.servers:
            server.close()
            await server.wait_closed()


async def run() -> None:
    host = os.getenv("DECOY_HOST", "0.0.0.0")
    log_path = os.getenv("DECOY_LOG", "logs/interactions.jsonl")
    farm = DeceptionFarm(host, log_path)
    await farm.start()
    loop = asyncio.get_running_loop()
    stopped = asyncio.Event()

    for name in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(signal, name), stopped.set)
        except (NotImplementedError, AttributeError):
            pass
    await stopped.wait()
    await farm.stop()


def main() -> int:
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
