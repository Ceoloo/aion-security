"""idp-mfa: every active human identity has a phishing-resistant or app-based MFA factor.

Scope: identities with kind == "human" and status == "active". Service
accounts and suspended or deprovisioned identities are out of scope for
this check.

Outcomes per in-scope identity:
- strong factor enrolled               -> pass
- only weak factors (sms/voice/email)  -> finding, MEDIUM (HIGH if privileged)
- no factor at all                     -> finding, HIGH (CRITICAL if privileged)

Each finding carries a remediation *proposal*, never an action. Privileged
subjects are tiered R3, so they are always human-gated at the gateway.

The factor lists below are this check's operating defaults. If the CA
control in aion-docs defines acceptable factors, the control wins: pass
overrides through the constructor rather than editing the defaults.
"""

from __future__ import annotations

from ...connectors.base import Identity, IdentityConnector
from ...contracts import ControlRef, Finding, RemediationProposal, RiskTier, Severity
from ..runner import Evaluation

DEFAULT_STRONG = frozenset({"webauthn", "fido2", "u2f", "totp", "push", "smartcard", "platform_authenticator"})
DEFAULT_WEAK = frozenset({"sms", "voice", "email"})

REMEDIATION_ACTION = "idp.require_mfa_enrollment"


class IdpMfaCheck:
    name = "idp-mfa"

    def __init__(
        self,
        connector: IdentityConnector,
        *,
        strong_factors: frozenset[str] = DEFAULT_STRONG,
        weak_factors: frozenset[str] = DEFAULT_WEAK,
    ):
        self._connector = connector
        self._strong = frozenset(f.lower() for f in strong_factors)
        self._weak = frozenset(f.lower() for f in weak_factors)

    @property
    def connector_id(self) -> tuple[str, str]:
        return self._connector.name, self._connector.version

    def observe(self) -> list[Identity]:
        return self._connector.list_identities()

    def snapshot(self) -> bytes:
        return self._connector.snapshot()

    @staticmethod
    def in_scope(ident: Identity) -> bool:
        return ident.kind == "human" and ident.status == "active"

    def evaluate(self, control: ControlRef, subjects: list[Identity]) -> Evaluation:
        ev = Evaluation(evaluated=0, passed=0)
        for ident in sorted(subjects, key=lambda i: i.id):
            if not self.in_scope(ident):
                continue
            ev.evaluated += 1
            factors = set(ident.mfa_factors)
            strong = factors & self._strong
            if strong:
                ev.passed += 1
                continue

            weak = sorted(factors & self._weak)
            unknown = sorted(factors - self._strong - self._weak)
            if weak:
                reason = "only weak MFA factors enrolled"
                sev = Severity.HIGH if ident.privileged else Severity.MEDIUM
            else:
                reason = "no MFA factor enrolled"
                sev = Severity.CRITICAL if ident.privileged else Severity.HIGH

            ev.findings.append(
                Finding(
                    control=control,
                    subject=ident.id,
                    severity=sev,
                    reason=reason,
                    detail={
                        "username": ident.username,
                        "privileged": ident.privileged,
                        "weak_factors": weak,
                        "unrecognized_factors": unknown,
                    },
                )
            )
            ev.proposals.append(
                RemediationProposal(
                    control=control,
                    subject=ident.id,
                    action=REMEDIATION_ACTION,
                    risk_tier=RiskTier.R3 if ident.privileged else RiskTier.R2,
                    params={"username": ident.username, "allowed_factors": sorted(self._strong)},
                )
            )
        return ev
