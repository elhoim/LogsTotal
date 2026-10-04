"""Pure event-reader contract; no database, worker, web or settings imports."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from app.json_utils import load_file, loads


@dataclass
class RawMatch:
    event: dict
    rule_name: str = ""
    rule_id: str = ""
    severity: object = None
    tags: list[str] = field(default_factory=list)
    timestamp: str | None = None


def event_timestamp(event: dict) -> str | None:
    ts = event.get("Timestamp") or event.get("timestamp")
    if isinstance(ts, str) and len(ts) >= 13:
        return ts
    root = event.get("Event")
    system = root.get("System") if isinstance(root, dict) else None
    tc = system.get("TimeCreated_attributes") if isinstance(system, dict) else None
    st = tc.get("SystemTime") if isinstance(tc, dict) else None
    return st if isinstance(st, str) and len(st) >= 13 else None


def json_records(path: Path, *, jsonl: bool = False) -> Iterator[dict]:
    """Historical output readers tolerate individual malformed JSONL records."""
    if not jsonl:
        raw = load_file(path)
        if isinstance(raw, list):
            yield from (item for item in raw if isinstance(item, dict))
        return
    with path.open("rb") as stream:
        for line in stream:
            if not line.strip():
                continue
            try:
                item = loads(line)
            except ValueError:
                continue
            if isinstance(item, dict):
                yield item
