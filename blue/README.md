# blue/: Continuous Assurance runners

CA check runners map **CA catalog controls** (defined in `aion-docs`,
referenced by ID and version) to **connector queries** (`../connectors/`).
Each run produces **findings and evidence** (`../evidence/`).

## Loop

```
observe ──▶ recommend ──▶ HUMAN APPROVE ──▶ remediate ──▶ verify
 (connectors)  (finding)     (Runtime grant)   (POST /v1/commands)  (re-run check)
```

- Observation is read-only.
- Remediation is always a gateway command issued under a grant that a human
  approved. R3 actions are always gated.
- Results are reported to Runtime's `/v1/assurance`, which remains the control
  surface.

## Priority

Customer-zero / TechOps comes first.
