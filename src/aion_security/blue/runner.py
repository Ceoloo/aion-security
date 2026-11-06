"""Generic CA check runner: observe -> evaluate -> recommend.

The runner stops at *recommend*. Human approval, remediation (a gateway
command under a grant) and verification (re-running the check) happen
outside it, so a runner can never change a live system on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Generic, Protocol, TypeVar

from ..connectors.base import ConnectorError
from ..contracts import ControlRef, Finding, RemediationProposal, RunResult, RunStatus
from ..evidence import evidence_ref, utcnow_iso

S = TypeVar("S")


@dataclass
class Evaluation:
    evaluated: int
    passed: int
    findings: list[Finding] = field(default_factory=list)
    proposals: list[RemediationProposal] = field(default_factory=list)


class Check(Protocol, Generic[S]):
    name: str

    def observe(self) -> list[S]: ...

    def snapshot(self) -> bytes: ...

    def evaluate(self, control: ControlRef, subjects: list[S]) -> Evaluation: ...

    @property
    def connector_id(self) -> tuple[str, str]: ...


def run_check(check: Check, control: ControlRef) -> RunResult:
    started = utcnow_iso()
    try:
        subjects = check.observe()
        snap = check.snapshot()
    except ConnectorError as e:
        # Fail closed: an observation we cannot trust is an ERROR, never a PASS.
        return RunResult(
            check=check.name,
            control=control,
            status=RunStatus.ERROR,
            started_at=started,
            finished_at=utcnow_iso(),
            evaluated=0,
            passed=0,
            findings=[],
            proposals=[],
            evidence=None,
            error=str(e),
        )

    ev = check.evaluate(control, subjects)
    cname, cver = check.connector_id
    evidence = evidence_ref(
        connector=cname,
        connector_version=cver,
        snapshot=snap,
        subject_count=len(subjects),
        collected_at=started,
    )
    return RunResult(
        check=check.name,
        control=control,
        status=RunStatus.FAIL if ev.findings else RunStatus.PASS,
        started_at=started,
        finished_at=utcnow_iso(),
        evaluated=ev.evaluated,
        passed=ev.passed,
        findings=ev.findings,
        proposals=ev.proposals,
        evidence=evidence,
    )
