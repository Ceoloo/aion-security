"""IdP connector backed by a JSON export file.

Use it with an export from any IdP, normalized to this shape:

    {"identities": [
        {"id": "u1", "username": "alice@example.com", "kind": "human",
         "status": "active", "privileged": true, "mfa_factors": ["webauthn"]}
    ]}

It is also the offline / fixture connector for tests and customer-zero dry
runs. Live vendor adapters (Okta, Entra ID, Google) implement the same
IdentityConnector protocol.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import ConnectorError, Identity

_KINDS = {"human", "service"}
_STATUSES = {"active", "suspended", "deprovisioned"}


class FileIdentityConnector:
    name = "idp.file"
    version = "1"

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._doc: dict | None = None

    def _load(self) -> dict:
        if self._doc is None:
            try:
                doc = json.loads(self._path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as e:
                raise ConnectorError(f"cannot read IdP export {self._path}: {e}") from e
            if not isinstance(doc, dict) or not isinstance(doc.get("identities"), list):
                raise ConnectorError("IdP export must be an object with an 'identities' list")
            self._doc = doc
        return self._doc

    def list_identities(self) -> list[Identity]:
        out: list[Identity] = []
        seen: set[str] = set()
        for i, rec in enumerate(self._load()["identities"]):
            if not isinstance(rec, dict):
                raise ConnectorError(f"identities[{i}] is not an object")
            try:
                ident = Identity(
                    id=str(rec["id"]),
                    username=str(rec["username"]),
                    kind=str(rec["kind"]),
                    status=str(rec["status"]),
                    privileged=bool(rec.get("privileged", False)),
                    mfa_factors=tuple(str(f).lower() for f in rec.get("mfa_factors") or ()),
                    raw=rec,
                )
            except KeyError as e:
                raise ConnectorError(f"identities[{i}] missing field {e}") from e
            if ident.kind not in _KINDS:
                raise ConnectorError(f"identities[{i}] has unknown kind {ident.kind!r}")
            if ident.status not in _STATUSES:
                raise ConnectorError(f"identities[{i}] has unknown status {ident.status!r}")
            if ident.id in seen:
                raise ConnectorError(f"duplicate identity id {ident.id!r}")
            seen.add(ident.id)
            out.append(ident)
        return out

    def snapshot(self) -> bytes:
        return json.dumps(self._load(), sort_keys=True, separators=(",", ":")).encode()
