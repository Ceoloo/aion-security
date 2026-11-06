"""Thin HTTP client for aion-runtime. The only way this repo touches platform state.

ASSUMPTION: the request paths and payload shapes below are this repo's best
reading of the Runtime API (/v1/assurance, /v1/commands). They are kept in
this one module so they can be aligned with the aion-runtime contract in one
place. Nothing here bypasses the gateway, and nothing writes to aion-data
directly.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable

from .contracts import RemediationProposal, RunResult

ASSURANCE_RUNS_PATH = "/v1/assurance/runs"
COMMANDS_PATH = "/v1/commands"
SOURCE = "aion-security"

# (method, url, headers, body) -> (status, response body)
Transport = Callable[[str, str, dict[str, str], bytes], tuple[int, bytes]]


class RuntimeError_(RuntimeError):
    pass


class UnpinnedControlError(RuntimeError_):
    """Refuse to report a run that is not tied to a pinned CA control."""


def _urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


@dataclass
class RuntimeClient:
    base_url: str
    token: str | None = None
    transport: Transport = _urllib_transport

    def _post(self, path: str, payload: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        headers = {
            "Content-Type": "application/json",
            "Idempotency-Key": idempotency_key,
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(payload, sort_keys=True).encode()
        status, resp = self.transport("POST", self.base_url.rstrip("/") + path, headers, body)
        if not 200 <= status < 300:
            raise RuntimeError_(f"POST {path} -> HTTP {status}: {resp[:500]!r}")
        return json.loads(resp) if resp else {}

    def report_run(self, result: RunResult) -> dict[str, Any]:
        if not result.control.pinned:
            raise UnpinnedControlError(
                f"check {result.check!r} has no pinned CA control; pin it in controls.lock.json "
                "from aion-docs before reporting to Runtime"
            )
        payload = {"source": SOURCE, **result.to_dict()}
        key = _key(result.check, result.started_at, result.evidence.snapshot_sha256 if result.evidence else "none")
        return self._post(ASSURANCE_RUNS_PATH, payload, key)

    def propose(self, proposal: RemediationProposal, result: RunResult) -> dict[str, Any]:
        """Submit a remediation as a *proposal* pending human approval. Never executes."""
        if not proposal.requires_human_approval:
            raise RuntimeError_("aion-security never submits remediations without human approval")
        if not proposal.control.pinned:
            raise UnpinnedControlError("cannot propose remediation for an unpinned control")
        evidence_sha = result.evidence.snapshot_sha256 if result.evidence else "none"
        payload = {
            "action": proposal.action,
            "mode": "propose",
            "requires_human_approval": True,
            "risk_tier": proposal.risk_tier.value,
            "subject": proposal.subject,
            "params": proposal.params,
            "source": {
                "repo": SOURCE,
                "check": result.check,
                "control": {"id": proposal.control.id, "version": proposal.control.version},
                "run_started_at": result.started_at,
                "evidence_sha256": evidence_sha,
            },
        }
        key = _key(proposal.action, proposal.subject, evidence_sha)
        return self._post(COMMANDS_PATH, payload, key)


def _key(*parts: str) -> str:
    return hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
