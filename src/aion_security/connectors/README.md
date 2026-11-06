# connectors/: External telemetry adapters

Adapters to scanners, IdP, EDR, and cloud-posture sources. All of them are
optional.

- **Read-only by default.** A connector never remediates. Remediation is a
  gateway command (see `../blue/`).
- Credentials come from the secrets architecture owned by `aion-infra`. They
  are never committed or defined here.
- Each connector returns normalized observations that the `blue/` runners
  consume.
