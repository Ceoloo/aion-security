"""Evidence references for check runs.

This only fingerprints what was observed. Durable storage of the snapshot
belongs to aion-data, reached through Runtime; nothing is persisted here.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from ..contracts import EvidenceRef


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def evidence_ref(
    *, connector: str, connector_version: str, snapshot: bytes, subject_count: int, collected_at: str
) -> EvidenceRef:
    return EvidenceRef(
        connector=connector,
        connector_version=connector_version,
        collected_at=collected_at,
        snapshot_sha256=hashlib.sha256(snapshot).hexdigest(),
        subject_count=subject_count,
    )
