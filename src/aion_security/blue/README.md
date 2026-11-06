# blue/: Continuous Assurance runners

CA check runners map **CA catalog controls** (defined in `aion-docs`,
referenced by ID and version) to **connector queries** (`../connectors/`).
Each run produces **findings and evidence** (`../evidence/`).

## Loop

```
observe ──▶ evaluate ──▶ recommend ║ HUMAN APPROVE ──▶ remediate ──▶ verify
 (connector)  (findings)  (proposal)║  (Runtime grant)  (gateway)    (re-run check)
            ── runner stops here ───╜
```

- Observation is read-only. If the runner cannot trust an observation, the run
  is `error`, never `pass` (fail closed).
- The runner stops at **recommend**. Proposals go to `/v1/commands` with
  `mode: propose` and `requires_human_approval: true`. Privileged subjects are
  tiered **R3**.
- Results are reported to Runtime's `/v1/assurance`, which remains the control
  surface.

## Control pinning

`controls.lock.json` maps each check to a CA control `{id, version}` copied
from aion-docs. An `UNPINNED` check can still run as a dry run, but the Runtime
client refuses to report it or propose remediations for it.

## Checks

| Check | Connector | What it asserts |
| --- | --- | --- |
| `idp-mfa` | IdP (`idp.file` for now) | Every active human identity has a strong MFA factor. If an identity has only weak factors (SMS, voice, email), the finding is MEDIUM, or HIGH if privileged. If it has no factor at all, the finding is HIGH, or CRITICAL if privileged. |

## Running

```bash
pip install -e '.[dev]'
aion-security blue run idp-mfa --idp-export export.json                  # dry run
aion-security blue run idp-mfa --idp-export export.json --report         # → /v1/assurance
aion-security blue run idp-mfa --idp-export export.json --propose        # + proposals
```

`--report` and `--propose` read `AION_RUNTIME_URL` and `AION_RUNTIME_TOKEN`.
Exit codes: `0` pass, `1` findings, `2` error.
