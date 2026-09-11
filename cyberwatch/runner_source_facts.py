"""Extraction courante et reprise différée des faits de source."""
from __future__ import annotations

import os

from . import config, source_facts, source_facts_ai, source_facts_retry, sources
from .collectors.base import RawEntry, SourceSpec
from .model import Incident, Item


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
    from .source_facts_ai_contract import RETIRED_LLM_FIELDS

    source_facts_retry.retire_fields(RETIRED_LLM_FIELDS)
    retry_limit = max(0, int(os.getenv("SOURCE_FACTS_RETRY_MAX_PER_RUN", "5")))
    attempted = 0
    scope = fields if fields is not None else retry_scope()
    # Un dossier réduit à un rejet persistant n'a plus de travail : il reste
    # visible mais ne consomme aucun des créneaux de reprise du run.
    from .sector_activity import ACTIVITY_FIELDS
    from .sector_resolution import entry_sector_decision
    for pending in queued_at_start:
        try:
            item, entry = source_facts_retry.restore(pending)
        except (TypeError, ValueError):
            continue
        if entry_sector_decision(item, entry):
            source_facts_retry.resolve(item, entry, ACTIVITY_FIELDS)
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


def settle_sectors(rows: list[dict], incidents: list[Incident]) -> dict:
    """Clôt la reprise sectorielle une fois les décisions finales établies."""
    from .sector_activity import ACTIVITY_FIELDS
    from .sector_resolution import qualification_summary

    summary = qualification_summary(rows, incidents)
    resolved = set(summary["resolved_item_ids"])
    for pending in source_facts_retry.load():
        if (pending.get("item") or {}).get("Item_ID") not in resolved:
            continue
        try:
            item, entry = source_facts_retry.restore(pending)
        except (TypeError, ValueError):
            continue
        source_facts_retry.resolve(item, entry, ACTIVITY_FIELDS)
    return summary


def settle_published_fields(
    rows: list[dict], items: list[Item], incidents: list[Incident]
) -> None:
    """Retire les reprises sans effet lorsque la publication a déjà une valeur.

    Une tentative sémantique reste utile seulement si elle peut encore changer
    la fiche : un résumé déterministe publiable ou une menace finale connue ne
    justifient pas un nouvel appel au run suivant.
    """
    facts = {str(row.get("Item_ID") or ""): row for row in rows}
    threat_urls = "\n".join(
        incident.Source_URLs for incident in incidents
        if incident.Menace and incident.Menace != config.THREAT_UNKNOWN
    )
    items_by_id = {item.Item_ID: item for item in items}
    for pending in source_facts_retry.load():
        try:
            item, entry = source_facts_retry.restore(pending)
        except (TypeError, ValueError):
            continue
        current = items_by_id.get(item.Item_ID, item)
        fact = facts.get(item.Item_ID, {})
        resolved: set[str] = set()
        if str(fact.get("Summary") or "").strip():
            resolved.update({"summary", "incident_summary"})
        if current.URL and current.URL in threat_urls:
            resolved.add("threat_candidate")
        if current.Event_Date or str(fact.get("Attack_Date") or "").strip():
            resolved.add("attack_date")
        if resolved:
            source_facts_retry.resolve(item, entry, resolved)
