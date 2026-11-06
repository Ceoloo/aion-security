"""Resolve check name -> pinned CA control reference."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

from ..contracts import UNPINNED, ControlRef


def load_control_pins(path: str | Path | None = None) -> dict[str, ControlRef]:
    if path is None:
        text = resources.files(__package__).joinpath("controls.lock.json").read_text("utf-8")
    else:
        text = Path(path).read_text("utf-8")
    doc = json.loads(text)
    return {
        name: ControlRef(id=str(v.get("id", UNPINNED)), version=str(v.get("version", UNPINNED)))
        for name, v in doc.items()
        if not name.startswith("_")
    }


def control_for(check: str, path: str | Path | None = None) -> ControlRef:
    return load_control_pins(path).get(check, ControlRef(UNPINNED, UNPINNED))
