# Security Policy

This project is a defensive deception lab.

## Safety boundaries

The farm:

- uses synthetic banners and responses
- never executes commands or scripts received from a connection
- never authenticates users or stores credentials
- stores payload hashes, lengths, and bounded indicator matches instead of raw payloads
- makes no outbound connections
- runs as a non-root user in Docker with dropped capabilities
- uses an internal Docker network and resource limits

Deploy only in an isolated lab or a network segment explicitly approved for deception monitoring. Do not expose the farm to production networks without an approved design and monitoring plan.

## Reporting

Use a private security report when possible. Do not publish credentials, raw malware, private IP telemetry, or sensitive interaction logs.