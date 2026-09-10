"""Pont entre l'extracteur sémantique et sa file persistante."""
from __future__ import annotations

from . import source_facts_retry
from .collectors.base import RawEntry
from .model import Item
from .source_facts_ai_contract import (
    CACHE_STATUS_REJECTED,
    CACHE_STATUS_REJECTED_EXHAUSTED,
    DEFER_SEMANTIC_MISS,
    DEFER_SEMANTIC_REJECTED,
    DEFER_TECHNICAL_FAILURE,
)


def defer(item: Item, entry: RawEntry, fields: set[str], reason: str,
          *, reasons: dict[str, str] | None = None) -> None:
    source_facts_retry.enqueue(item, entry, fields, reason, reasons=reasons)


def settle(
    item: Item,
    entry: RawEntry,
    fields: set[str],
    *,
    completed: bool,
    statuses: dict[str, str] | None = None,
    reasons: dict[str, str] | None = None,
) -> None:
    """Répercute l'issue de chaque champ sur la file de reprise.

    Une panne technique ne rend jamais rien terminal : elle redemande tout.
    """
    if not completed:
        defer(item, entry, fields, DEFER_TECHNICAL_FAILURE)
        return
    statuses = statuses or {}
    terminal = {field for field in fields if statuses.get(field) in {"accepted", "abstained"}}
    retryable = {field for field in fields if statuses.get(field) == "miss"}
    rejected = {field for field in fields if statuses.get(field) == CACHE_STATUS_REJECTED}
    exhausted = {
        field for field in fields if statuses.get(field) == CACHE_STATUS_REJECTED_EXHAUSTED
    }
    source_facts_retry.resolve(item, entry, terminal)
    pending = retryable | rejected
    if pending:
        # Un seul appel : deux `enqueue` successifs sur la même clé écraseraient
        # le motif scalaire. Le détail par champ reste dans `field_reasons`.
        defer(item, entry, pending,
              DEFER_SEMANTIC_REJECTED if rejected else DEFER_SEMANTIC_MISS,
              reasons={field: str((reasons or {}).get(field, "")) for field in pending})
    if exhausted:
        source_facts_retry.mark_exhausted(
            item, entry, exhausted,
            {field: str((reasons or {}).get(field, "")) for field in exhausted},
        )
