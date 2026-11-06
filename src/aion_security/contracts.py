"""Shared types for runners, connectors and evidence.

These are local data shapes, not normative contracts. CA control definitions
live in aion-docs and are referenced here only by ID + version (ControlRef).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskTier(str, Enum):
    """Gateway risk tier for a proposed remediation. R3 is always human-gated."""

    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


class RunStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"  # could not observe; never reported as pass


UNPINNED = "UNPINNED"


@dataclass(frozen=True)
class ControlRef:
    """Pointer to a CA catalog control in aion-docs. Never copy control text here."""

    id: str
    version: str

    @property
    def pinned(self) -> bool:
        return UNPINNED not in (self.id, self.version) and bool(self.id) and bool(self.version)


@dataclass(frozen=True)
class EvidenceRef:
    """Tamper-evident pointer to the raw observation snapshot a run evaluated."""

    connector: str
    connector_version: str
    collected_at: str  # ISO-8601 UTC
    snapshot_sha256: str
    subject_count: int


@dataclass(frozen=True)
class Finding:
    control: ControlRef
    subject: str
    severity: Severity
    reason: str
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RemediationProposal:
    """A *recommendation* for a gateway command. The runner never executes it.

    It is submitted to Runtime as pending human approval. Execution, if any,
    happens through the gateway under a grant after a human approves.
    """

    control: ControlRef
    subject: str
    action: str
    risk_tier: RiskTier
    params: dict[str, Any] = field(default_factory=dict)
    requires_human_approval: bool = True


@dataclass(frozen=True)
class RunResult:
    check: str
    control: ControlRef
    status: RunStatus
    started_at: str
    finished_at: str
    evaluated: int
    passed: int
    findings: list[Finding]
    proposals: list[RemediationProposal]
    evidence: EvidenceRef | None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        def enc(v: Any) -> Any:
            if isinstance(v, Enum):
                return v.value
            if isinstance(v, dict):
                return {k: enc(x) for k, x in v.items()}
            if isinstance(v, list):
                return [enc(x) for x in v]
            return v

        return enc(asdict(self))
