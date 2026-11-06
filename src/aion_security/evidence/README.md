# evidence/: Audit and CA evidence packaging

Builds evidence bundles for TechOps audits and Continuous Assurance reports.

- Bundles are **submitted through Runtime**. Durable storage is `aion-data`,
  never this repo and never a direct DB write.
- Each bundle references the CA control ID and version, the check run, and
  the gateway command IDs (for any remediation) so that it can be traced end
  to end.
