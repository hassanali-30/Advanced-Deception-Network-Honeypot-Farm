import asyncio
import hashlib
from unittest.mock import AsyncMock

from deception_farm import (
    DeceptionFarm,
    extract_indicators,
    http_response,
    payload_metadata,
    valid_peer_ip,
)


def test_payload_is_hashed_not_stored():
    payload = b"GET /?q=example.test HTTP/1.1\r\n"
    metadata = payload_metadata(payload)
    assert metadata["payload_sha256"] == hashlib.sha256(payload).hexdigest()
    assert metadata["payload_length"] == len(payload)
    assert "payload" not in metadata


def test_indicators_are_bounded():
    indicators = extract_indicators(b"powershell http://example.test 203.0.113.5")
    assert "powershell" in indicators
    assert "http://example.test" in indicators
    assert len(indicators) <= 20


def test_peer_validation():
    assert valid_peer_ip("192.0.2.10") == "192.0.2.10"
    assert valid_peer_ip("not-an-ip") == "unknown"


def test_http_response_content_length_matches_body():
    headers, body = http_response().split(b"\r\n\r\n", 1)
    length_header = next(
        line for line in headers.split(b"\r\n")
        if line.lower().startswith(b"content-length:")
    )
    assert int(length_header.split(b":", 1)[1]) == len(body)


def test_http_disconnect_after_logging_does_not_duplicate_event(tmp_path):
    class Reader:
        async def read(self, _limit):
            return b"GET / HTTP/1.1\r\n\r\n"

    class Writer:
        def get_extra_info(self, _name):
            return ("192.0.2.10", 49152)

        def write(self, _data):
            pass

        async def drain(self):
            raise BrokenPipeError

        def close(self):
            pass

        async def wait_closed(self):
            pass

    farm = DeceptionFarm("127.0.0.1", str(tmp_path / "events.jsonl"))
    farm.log_interaction = AsyncMock()
    asyncio.run(farm.handle("http", Reader(), Writer()))

    assert farm.log_interaction.await_count == 1
