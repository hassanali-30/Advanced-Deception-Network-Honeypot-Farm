import hashlib

from deception_farm import extract_indicators, payload_metadata, valid_peer_ip


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
