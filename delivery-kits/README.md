# delivery-kits/: Client delivery kits

Client-facing packaging (runbooks, configs, report templates) that **uses the
Runtime APIs**.

- Kits call Runtime (`/v1/commands`, `/v1/assurance`, registry). They **never
  reimplement PolicyEngine** or gateway logic.
- Kits contain no product UI. The Operator Console may display assurance but
  is not a SOC.
