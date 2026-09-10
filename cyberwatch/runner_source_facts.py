"""Extraction courante et reprise différée des faits de source."""
from __future__ import annotations

import os

from . import source_facts, source_facts_ai, source_facts_retry, sources
from .collectors.base import RawEntry, SourceSpec
from .model import Item


def extract(item: Item, entry: RawEntry, spec: SourceSpec, *,
            only_fields: set[str] | None = None) -> dict | None:
    semantic = None
    if item.Source_ID in source_facts_ai.TARGET_SOURCES:
        # L'appel historique à deux arguments reste la forme par défaut : les
        # adaptateurs et doublures qui remplacent `extract_semantic` continuent
        # de fonctionner tant qu'aucun périmètre n'est demandé.
        semantic = (
            source_facts_ai.extract_semantic(item, entry, only_fields=only_fields)
            if only_fields is not None
            else source_facts_ai.extract_semantic(item, entry)
        )
    return source_facts.extract_source_fact(item, entry, spec, semantic=semantic)


def retry_scope() -> set[str] | None:
    """Champs auxquels restreindre la reprise ; None pour tous.

    Permet une reprise sectorielle sans recalculer les autres champs en
    attente des mêmes dossiers, ni les retirer de la file.
    """
    raw = os.getenv("SOURCE_FACTS_RETRY_FIELDS", "").strip()
    scope = {part.strip() for part in raw.split(",") if part.strip()}
    return scope or None


def _pending_by_key(scope: set[str] | None) -> dict[str, set[str] | None]:
    """Dossiers ayant encore du travail dans le périmètre demandé.

    La valeur ``None`` signifie « tous les champs », pour les lignes écrites
    avant le suivi par champ.
    """
    pending: dict[str, set[str] | None] = {}
    for row in source_facts_retry.load():
        key = str(row.get("key") or "")
        fields = source_facts_retry.pending_for(row, scope)
        if key and fields is None:
            pending[key] = None
        elif key and fields:
            pending[key] = fields
    return pending


def retry_pending(queued_at_start: list[dict], *,
                  fields: set[str] | None = None) -> tuple[list[dict], dict]:
    """Reprend quelques champs différés, même après la fenêtre de collecte."""
    retry_rows: list[dict] = []
    retry_limit = max(0, int(os.getenv("SOURCE_FACTS_RETRY_MAX_PER_RUN", "5")))
    attempted = 0
    scope = fields if fields is not None else retry_scope()
    # Un dossier réduit à un rejet persistant n'a plus de travail : il reste
    # visible mais ne consomme aucun des créneaux de reprise du run.
    active = _pending_by_key(scope)
    if source_facts_ai._runtime().enabled:
        for pending in queued_at_start:
            key = str(pending.get("key") or "")
            if attempted >= retry_limit:
                break
            if not key or key not in active:
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
                # Sans périmètre, l'appel garde sa forme historique à trois
                # arguments : les doublures de `extract` restent compatibles.
                only = active[key]
                fact = (extract(pending_item, pending_entry, spec, only_fields=only)
                        if only is not None else extract(pending_item, pending_entry, spec))
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
            active = _pending_by_key(scope)
    return retry_rows, {
        "queued_before": len(queued_at_start),
        "attempted": attempted,
        "facts_refreshed": len(retry_rows),
        "queued_after": len(source_facts_retry.load()),
    }
