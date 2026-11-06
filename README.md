# aion-security

Security operations satellite for the AION platform: blue-team Continuous
Assurance (CA) runners, scoped red-team harnesses, and audit evidence
packaging. It is a **client of the Execution Gateway**, and it reads the SIS /
CA / SEL contracts. It is not a second operating system.

Ownership and dependency rules: [ADR-001](docs/adr/ADR-001-aion-security-satellite.md).

## Where it sits

```
aion-docs (SIS / CA / SEL contracts)
        │ governs
aion-security  ──HTTP──▶  aion-runtime (/v1/commands, /v1/assurance, registry)
        │                      │
        │                      ├─ aion-core (policy / gates)
        │                      └─ aion-data (durable evidence)
        └─ may use scanners / IdP / EDR connectors (optional)

aion-infra still owns platform host hardening & deploy
```

Dependencies point one way only: `aion-security → aion-runtime / aion-core
contracts`. Nothing in the six core repos may import from, call, or depend on
this repo.

## Owns

- **Blue-team connectors and check runners.** They run the CA catalog against
  live telemetry: scanners, IdP, EDR, cloud posture.
- **Red-team playbooks and harnesses.** Adversarial runs are scoped, gated by
  a mission, and run against a separate tenant.
- **Evidence packaging** for TechOps audits and Continuous Assurance reports.
- **Client delivery kits** that use Runtime. They never reimplement
  PolicyEngine.

## Does not own

| Concern | Owner |
| --- | --- |
| Gateway, PolicyEngine, agent registry schema | `aion-runtime` / `aion-core` |
| Canonical Postgres tables, durable evidence store | `aion-data` |
| Platform IaC, host hardening, secrets architecture | `aion-infra` |
| SIS / CA / SEL normative text | `aion-docs` |
| Product UIs (the Operator Console *displays* assurance; it is not a SOC) | product repos |

Runtime's `/v1/assurance` stays the platform control surface. Connector-heavy
work and red-team harnesses live here so that Runtime does not turn into a
SIEM.

## Red vs blue

| Team | Fit | Production constraint |
| --- | --- | --- |
| **Blue** ([`blue/`](blue/)) | Home for Continuous Assurance *operations* that need too many connectors to live in Runtime | Observe → recommend → **human approve** → remediate → verify. R3 is always gated. |
| **Red** ([`red/`](red/)) | Home for attack simulations and readiness probes | Separate mission and tenant. Assist/Observe by default. Any Execute against a live system goes through the gateway with grants. No silent prod writes. |

Blue comes first (customer-zero / TechOps). Red is **disabled** until the
GE-001-style gates exist, so that adversarial runs cannot contaminate revenue
proof.

## Layout

```
docs/adr/         Architecture decisions for this satellite
connectors/       Read-only adapters to external telemetry (scanner, IdP, EDR, cloud)
blue/             CA check runners: map CA catalog controls → connector queries → findings
red/              Adversarial playbooks + harnesses (gated; see red/README.md)
evidence/         Evidence packaging for audits / CA reports (writes via Runtime → aion-data)
delivery-kits/    Client-facing kits that consume Runtime APIs
```

## Rules of the road

1. **All state changes go through the gateway.** Use `POST /v1/commands` with
   a grant. No direct DB writes, no side channels to customer systems.
2. **Contracts come from `aion-docs`.** CA control IDs, SIS schemas, and SEL
   levels are referenced by ID and version, never copied here and edited.
3. **Connectors are read-only by default.** Remediation is a gateway command
   that a human has approved, never a connector call.
4. **Evidence is durable only in `aion-data`.** This repo builds evidence
   bundles and submits them through Runtime. It holds no system of record.
5. **Host hardening and secrets architecture belong in `aion-infra`.** If a
   request is only IaC, it goes there.
