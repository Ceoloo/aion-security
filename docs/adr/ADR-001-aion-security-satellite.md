# ADR-001: aion-security as a satellite repository

- **Status:** Proposed
- **Date:** 2026-11-06
- **Pattern:** Same as ADR-004 (desks): a satellite repository with declared
  ownership, a one-way dependency direction, and explicit non-goals.
- **Normative home:** Once accepted, a copy of this ADR goes into `aion-docs`.
  The copy in this repo is the working draft.

## Context

Security work for AION splits into two shapes:

1. **Platform controls.** These are the gateway, PolicyEngine, grants, and
   `/v1/assurance`. They already live in `aion-runtime` / `aion-core`, and
   every product uses them.
2. **Security operations.** These are CA check runners backed by many
   connectors (scanners, IdP, EDR, cloud posture), adversarial simulation, and
   audit evidence packaging. This work is heavy on connectors and specific to
   a mission. Putting it in Runtime would turn Runtime into a SIEM.

The six-repo constitution should grow only when a capability becomes a
**shared platform primitive** that several products reuse (the
platformization rule). Security operations are not one yet.

## Decision

Create `aion-security` as a **satellite**, outside the six-repo constitution.

### Ownership

`aion-security` owns:

- Blue-team connectors and check runners that run the CA catalog against live
  telemetry.
- Red-team playbooks and harnesses. They are scoped and gated by a mission.
- Evidence packaging for TechOps audits and Continuous Assurance reports.
- Client delivery kits that use Runtime.

`aion-security` does **not** own:

- The Gateway, PolicyEngine, the agent registry schema, or canonical Postgres
  tables.
- Platform IaC, host hardening, or the secrets architecture (`aion-infra`).
- SIS / CA / SEL normative text (`aion-docs`).
- Product UIs. The Operator Console may display assurance but must not grow
  into a SOC.

### Dependency direction

```
aion-security ──▶ aion-runtime HTTP API (/v1/commands, /v1/assurance, registry)
aion-security ──▶ aion-docs contracts (by ID + version)
aion-security ──▶ aion-core contracts (types/schemas only, never internals)
```

- **Never the reverse.** No core repo imports, calls, or configures anything
  in `aion-security`.
- Writes reach `aion-data` only through Runtime. Nothing writes directly.
- External connectors (scanner, IdP, EDR) are optional and read-only by
  default.

### Operating constraints

| Team | Loop | Hard constraints |
| --- | --- | --- |
| Blue | Observe → recommend → **human approve** → remediate → verify | R3 is always gated. Remediation is a gateway command with a grant, never a connector call. |
| Red | Plan → scope → **mission gate** → simulate → report | Separate mission and tenant. Assist/Observe by default. Execute against a live system goes only through the gateway with grants. No silent prod writes. |

### Sequencing

1. **Blue first.** CA for customer-zero / TechOps.
2. **Red later.** Red stays disabled until GE-001-style gates exist, so that
   adversarial runs cannot contaminate revenue proof.
3. If a need is only host hardening or secrets, it goes in `aion-infra`. No
   new repo is created for IaC that `aion-infra` already owns.

## Consequences

**Positive**

- Runtime keeps a small, stable control surface (`/v1/assurance`).
- Connector sprawl and adversarial tooling are isolated from the core blast
  radius.
- Evidence keeps one durable home (`aion-data`), reached only through the
  gateway, so it stays auditable.

**Negative / risks**

- There is drift risk if CA control definitions get copied here instead of
  referenced. *Mitigation:* reference by ID and version only, and pin contract
  versions.
- There is a temptation to add "just one" direct DB write or side channel.
  *Mitigation:* code review rule: every state change goes through
  `POST /v1/commands`.
- **Promotion trigger:** if two or more products start depending on a
  capability here, it becomes a candidate for platformization through a new
  ADR in `aion-docs`.

## Non-goals

- Not a parallel policy engine, gateway, or registry.
- Not a SIEM or SOC product.
- Not an IaC or secrets repository.
- Not the place where SIS / CA / SEL text is authored.
