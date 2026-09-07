"""Extraction courante et reprise différée des faits de source."""
from __future__ import annotations

import os

from . import source_facts, source_facts_ai, source_facts_retry, sources
from .collectors.base import RawEntry, SourceSpec
from .model import Item


def extract(item: Item, entry: RawEntry, spec: SourceSpec) -> dict | None:
    semantic = None
    if item.Source_ID in source_facts_ai.TARGET_SOURCES:
        semantic = source_facts_ai.extract_semantic(item, entry)
    return source_facts.extract_source_fact(item, entry, spec, semantic=semantic)


def retry_pending(queued_at_start: list[dict]) -> tuple[list[dict], dict]:
    """Reprend quelques champs différés, même après la fenêtre de collecte."""
    retry_rows: list[dict] = []
    retry_limit = max(0, int(os.getenv("SOURCE_FACTS_RETRY_MAX_PER_RUN", "5")))
    attempted = 0
    active_keys = {str(row.get("key") or "") for row in source_facts_retry.load()}
    if source_facts_ai._runtime().enabled:
        for pending in queued_at_start:
            key = str(pending.get("key") or "")
            if attempted >= retry_limit:
                break
            if not key or key not in active_keys:
                continue
            try:
                pending_item, pending_entry = source_facts_retry.restore(pending)
            except (TypeError, ValueError):
                continue
            spec = sources.by_id(pending_item.Source_ID)
            if spec is None or pending_item.Source_ID not in source_facts_ai.TARGET_SOURCES:
                continue
            source_facts_retry.mark_attempt(key)
            attempted += 1
            try:
                fact = extract(pending_item, pending_entry, spec)
            except Exception as exc:  # noqa: BLE001 — une reprise ne bloque pas le snapshot
                source_facts_ai._runtime().record_event(
                    item_id=pending_item.Item_ID,
                    url=pending_item.URL,
                    status="retry_failed",
                    reason=type(exc).__name__,
                )
                continue
            if fact is not None:
                retry_rows.append(fact)
            active_keys = {
                str(row.get("key") or "") for row in source_facts_retry.load()
            }
    return retry_rows, {
        "queued_before": len(queued_at_start),
        "attempted": attempted,
        "facts_refreshed": len(retry_rows),
        "queued_after": len(source_facts_retry.load()),
    }
