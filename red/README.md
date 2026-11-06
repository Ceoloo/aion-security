# red/: Adversarial playbooks and harnesses

> **Status: DISABLED.** Nothing in this directory may run until GE-001-style
> gates exist. Adversarial runs must not contaminate revenue proof.

## Constraints (non-negotiable)

- Every run has a **separate mission and a separate tenant**.
- The default mode is **Assist / Observe**.
- Any **Execute** against a live system goes through the gateway
  (`POST /v1/commands`) with explicit grants.
- **No silent prod writes.** Every run is scoped, logged, and has its evidence
  packaged.

## Run lifecycle

```
plan ──▶ scope (targets, window, tenant) ──▶ MISSION GATE ──▶ simulate ──▶ report
```
