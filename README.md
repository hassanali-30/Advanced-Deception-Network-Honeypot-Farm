# Advanced Deception Network Honeypot Farm

[![CI](https://github.com/hassanali-30/Advanced-Deception-Network-Honeypot-Farm/actions/workflows/ci.yml/badge.svg)](https://github.com/hassanali-30/Advanced-Deception-Network-Honeypot-Farm/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/docker-isolated-blue.svg)](https://www.docker.com/)

An isolated defensive deception lab with synthetic SSH, FTP, Telnet, and HTTP decoys. The farm records interaction metadata, payload hashes, bounded indicator matches, and timing without executing commands or storing credentials.

> **Safety boundary:** This is a non-executing honeypot. It makes no outbound connections, authenticates no users, and never runs received input.

## Highlights

- Multi-service decoy farm
- JSONL interaction telemetry
- Payload SHA-256 and size instead of raw payload storage
- Bounded IP, domain, URL, and command-indicator extraction
- Synthetic service banners and maintenance responses
- Non-root Docker image
- Dropped Linux capabilities
- Read-only container filesystem
- No-new-privileges security option
- Internal Docker network
- CPU, memory, and payload-size limits
- CI tests and security policy

## Run with Docker Compose

Requires Docker Engine and Docker Compose.

```
git clone https://github.com/hassanali-30/Advanced-Deception-Network-Honeypot-Farm.git
cd Advanced-Deception-Network-Honeypot-Farm
mkdir logs
docker compose up --build
```

The decoys are published locally on:

| Decoy | Local port |
| --- | ---: |
| HTTP maintenance page | 8080 |
| SSH-like banner | 2222 |
| FTP-like banner | 2121 |
| Telnet-like banner | 2323 |

Interaction events are written to `logs/interactions.jsonl`. The raw payload is not stored.

Stop the lab:

```
docker compose down
```

## Run without Docker

Requires Python 3.10+:

```
python deception_farm.py
```

Set a custom log path:

```
DECOY_LOG=logs/interactions.jsonl python deception_farm.py
```

## Telemetry schema

Each interaction includes:

- Timestamp and decoy service
- Source IP and source port
- Destination port
- Connection duration
- Outcome
- Payload SHA-256
- Payload length
- Bounded indicator matches
- `safe_mode=true`
- `payload_stored=false`

Example:

```
{"event_type":"honeypot_interaction","service":"ssh","src_ip":"192.0.2.50","dst_port":2222,"payload_sha256":"...","payload_length":42,"indicators":["powershell"],"safe_mode":true,"payload_stored":false}
```

## Security design

The container runs as an unprivileged `decoy` user with all Linux capabilities dropped. The Docker network is marked internal, the filesystem is read-only, and resource limits reduce the blast radius of unexpected activity.

This is still a lab component. Keep it separate from production workloads, monitor the host, and deploy only under an approved deception-monitoring plan.

## Testing

```
python -m pip install -r requirements.txt
python -m pytest -q
```

## Limitations

This project is intentionally a safe decoy and is not a full SSH/FTP/Telnet implementation. It does not provide attacker persistence, command execution, malware detonation, or a production-grade network sensor.

## License

See [LICENSE](LICENSE).
