from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _strip_generated_at(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_generated_at(item)
            for key, item in value.items()
            if key != "generated_at_utc"
        }
    if isinstance(value, list):
        return [_strip_generated_at(item) for item in value]
    return value


def stabilize_generated_at(existing: Any, current: Any) -> Any:
    if _strip_generated_at(existing) == _strip_generated_at(current):
        return existing
    return current


def write_stable_json(path: Path, payload: Any) -> Any:
    stabilized = payload
    if path.exists():
        try:
            existing = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            existing = None
        if existing is not None:
            stabilized = stabilize_generated_at(existing, payload)
    output_text = json.dumps(stabilized, ensure_ascii=False, indent=2)
    if path.exists():
        try:
            if path.read_text(encoding="utf-8") == output_text:
                return stabilized
        except OSError:
            pass
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(output_text, encoding="utf-8")
    return stabilized
