"""Connector interfaces. Connectors observe, never mutate.

A connector exposes read methods only. Remediation is never a connector call:
it is a gateway command proposed by a runner and approved by a human.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


class ConnectorError(RuntimeError):
    """The connector could not produce a trustworthy observation."""


@dataclass(frozen=True)
class Identity:
    """Normalized identity record, independent of the IdP vendor."""

    id: str
    username: str
    kind: str  # "human" | "service"
    status: str  # "active" | "suspended" | "deprovisioned"
    privileged: bool = False
    mfa_factors: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)


@runtime_checkable
class IdentityConnector(Protocol):
    name: str
    version: str

    def list_identities(self) -> list[Identity]:
        """Return every identity in scope. Raise ConnectorError on partial reads."""
        ...

    def snapshot(self) -> bytes:
        """Canonical bytes of what was observed, for evidence hashing."""
        ...
