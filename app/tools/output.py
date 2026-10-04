"""Pure event-reader contract; no database, worker, web or settings imports."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class RawMatch:
    event: dict
    rule_name: str = ""
    rule_id: str = ""
    severity: object = None
    tags: list[str] = field(default_factory=list)
    timestamp: str | None = None


def event_timestamp(event: dict) -> str | None:
    from app.tools.event_fields import EventView

    return EventView(event).timestamp


def json_records(path: Path, *, jsonl: bool = False) -> Iterator[dict]:
    """Historical output readers tolerate individual malformed JSONL records."""
    from app.tools.mapping import file_records

    return file_records(path, format="jsonl" if jsonl else "json")
