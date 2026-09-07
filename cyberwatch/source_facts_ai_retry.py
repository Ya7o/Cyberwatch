"""Pont entre l'extracteur sémantique et sa file persistante."""
from __future__ import annotations

from . import source_facts_retry
from .collectors.base import RawEntry
from .model import Item


def defer(item: Item, entry: RawEntry, fields: set[str], reason: str) -> None:
    source_facts_retry.enqueue(item, entry, fields, reason)


def settle(
    item: Item,
    entry: RawEntry,
    fields: set[str],
    *,
    completed: bool,
    statuses: dict[str, str] | None = None,
) -> None:
    if not completed:
        defer(item, entry, fields, "TECHNICAL_FAILURE")
        return
    statuses = statuses or {}
    terminal = {field for field in fields if statuses.get(field) in {"accepted", "abstained"}}
    retryable = {field for field in fields if statuses.get(field) == "miss"}
    source_facts_retry.resolve(item, entry, terminal)
    defer(item, entry, retryable, "SEMANTIC_MISS")
