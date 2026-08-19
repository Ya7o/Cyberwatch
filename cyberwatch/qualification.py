"""Phase canonique, offline et idempotente de qualification d'un snapshot."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import (
    config,
    context_sector,
    enrichment,
    identity,
    sector as sector_policy,
    sector_registry,
    sector_registry_safety,
    source_llm_fallback,
    store,
)
from .dedup import build_incidents_with_registry
from .model import Incident, Item
from .sector_fallback_migration import restore_legacy_sector_fallbacks


_AUTHORITATIVE_NATIVE_THREAT_SOURCES = frozenset({"VEILLE_LLM"})
_AUTHORITATIVE_DEFAULT_THREATS = {"RANSOMWARE_LIVE": config.THREAT_RANSOMWARE}
_SOURCE_SCOPE_THREATS = {
    "FRENCHBREACHES": config.THREAT_LEAK,
    "BONJOURLAFUITE": config.THREAT_LEAK,
}
_STRONG_SOURCE_SCOPE_OVERRIDES = frozenset({
    config.THREAT_RANSOMWARE,
    config.THREAT_DDOS,
    config.THREAT_MALWARE,
    config.THREAT_ACCOUNT,
    config.THREAT_LEAK,
    config.THREAT_PHISHING,
    config.THREAT_THIRD_PARTY,
})

_SECTOR_FALLBACK_AUTO_APPLY = False


@dataclass(frozen=True)
class QualificationReport:
    items: list[Item]
    incidents: list[Incident]
    changes: dict[str, int]
    provenance: list[dict[str, str]]
    incident_id_registry: list[dict[str, str]]
    items_hash: str
    incidents_hash: str


def stabilize_threats(items: list[Item]) -> int:
    changed = 0
    for item in items:
        before = item.Threat
        if item.Source_ID in _AUTHORITATIVE_NATIVE_THREAT_SOURCES:
            native = (item.Threat_Raw or "").strip()
            if native in config.THREATS:
                item.Threat = native
        elif item.Source_ID in _AUTHORITATIVE_DEFAULT_THREATS:
            item.Threat = _AUTHORITATIVE_DEFAULT_THREATS[item.Source_ID]
        elif item.Source_ID in _SOURCE_SCOPE_THREATS:
            scoped = _SOURCE_SCOPE_THREATS[item.Source_ID]
            if item.Threat not in _STRONG_SOURCE_SCOPE_OVERRIDES:
                item.Threat = scoped
        if item.Threat != before:
            changed += 1
    return changed


def backfill_safe_name_sectors(items: list[Item]) -> int:
    """Applique uniquement les règles nominatives explicitement jugées sûres."""
    changed = 0
    for item in items:
        if item.Sector != config.SECTOR_UNKNOWN:
            continue
        candidate = sector_policy.classify_sector_name(item.Organisation_Raw)
        if candidate == config.SECTOR_UNKNOWN:
            continue
        item.Sector = candidate
        changed += 1
    return changed


def backfill_structured_source_sectors(
    items: list[Item], source_fact_rows: list[dict[str, str]] | None = None
) -> int:
    """Réapplique uniquement les secteurs structurés ransomware.live mappés."""
    rows = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    raw_by_item: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        if row.get("Source_ID") != "RANSOMWARE_LIVE":
            continue
        raw = (row.get("Source_Sector_Raw") or "").strip()
        item_id = (row.get("Item_ID") or "").strip()
        if item_id and raw:
            raw_by_item[item_id].add(raw)

    changed = 0
    for item in items:
        if item.Source_ID != "RANSOMWARE_LIVE" or item.Sector != config.SECTOR_UNKNOWN:
            continue
        raw_values = raw_by_item.get(item.Item_ID, set())
        if len(raw_values) != 1:
            continue
        candidate = sector_policy.classify_source_sector(next(iter(raw_values)))
        if candidate == config.SECTOR_UNKNOWN:
            continue
        item.Sector = candidate
        changed += 1
    return changed


def neutralize_sector_fallback(
    items: list[Item],
    changes: dict[str, int],
    provenance: list[dict[str, str]],
) -> int:
    """Neutralise uniquement les mutations Sector du challenger JSON."""
    if _SECTOR_FALLBACK_AUTO_APPLY:
        return 0
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    neutralized = 0
    for row in provenance:
        if (
            row.get("Origin") != "LLM_SOURCE_FALLBACK"
            or row.get("Field") != "Sector"
            or row.get("Decision") != "APPLIED"
        ):
            continue
        item = by_id.get(row.get("Item_ID", ""))
        if item is None:
            continue
        previous = row.get("Previous_Value", config.SECTOR_UNKNOWN)
        applied = row.get("Final_Value", "")
        if not applied or item.Sector != applied:
            continue
        item.Sector = previous or config.SECTOR_UNKNOWN
        row["Final_Value"] = item.Sector
        row["Confidence"] = ""
        row["Decision"] = "REJECTED_POLICY_DISABLED"
        neutralized += 1
    if neutralized:
        changes["llm_sector_fallback"] = max(0, changes.get("llm_sector_fallback", 0) - neutralized)
        changes["llm_sector_rejected"] = changes.get("llm_sector_rejected", 0) + neutralized
    changes["llm_sector_policy_rejected"] = neutralized
    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return neutralized


def qualify(items: list[Item]) -> QualificationReport:
    """Applique les couches canoniques avec propagation Sector réversible."""
    ordered = identity.sort_items(items)
    previous_provenance = store.load_qualification_provenance()

    restored = restore_legacy_sector_fallbacks(ordered, previous_provenance)
    registry_restored = sector_registry.restore_registry_applications(ordered, previous_provenance)

    reference = enrichment.load_reference()
    changes = enrichment.enrich_items(ordered, reference)
    changes["llm_sector_restored"] = restored
    changes["sector_registry_restored"] = registry_restored
    changes.update(enrichment.backfill_unknowns(ordered, reference))
    changes["sector_safe_name_backfill"] = backfill_safe_name_sectors(ordered)

    source_facts = store.read_csv(store.SOURCE_FACTS_CSV)
    org_cache = store.load_org_enrichment_cache()
    changes["sector_structured_source_backfill"] = backfill_structured_source_sectors(ordered, source_facts)

    context_applied, context_provenance, context_conflicts = context_sector.resolve_contextual_sectors(
        ordered,
        source_facts,
        org_cache,
    )
    changes["sector_context_applied"] = context_applied
    changes["sector_context_conflicts"] = context_conflicts
    changes["threat_stabilized"] = stabilize_threats(ordered)

    registry_rows = sector_registry.build_registry(
        ordered,
        reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        previous_provenance=previous_provenance,
    )
    sector_registry_safety.enforce_candidate_conflicts(registry_rows)
    registry_applied, registry_provenance, registry_known_conflicts = sector_registry.apply_registry(
        ordered, registry_rows
    )
    changes["sector_registry_applied"] = registry_applied
    changes["sector_registry_known_conflicts"] = registry_known_conflicts
    changes["sector_registry_auto_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_AUTO for row in registry_rows)
    changes["sector_registry_review_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_REVIEW for row in registry_rows)
    changes["sector_registry_conflict_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_CONFLICT for row in registry_rows)

    llm_changes, provenance = source_llm_fallback.apply_source_llm_fallback(ordered)
    changes.update(llm_changes)
    neutralize_sector_fallback(ordered, changes, provenance)

    provenance.extend(context_provenance)
    provenance.extend(registry_provenance)
    provenance.sort(
        key=lambda row: (
            row["Item_ID"], row["Field"], row["Decision"], row.get("Origin", "")
        )
    )

    incidents, incident_id_registry = build_incidents_with_registry(
        ordered, store.load_incident_id_registry()
    )
    return QualificationReport(
        items=ordered,
        incidents=incidents,
        changes=changes,
        provenance=provenance,
        incident_id_registry=incident_id_registry,
        items_hash=identity.items_hash(ordered),
        incidents_hash=identity.incidents_hash(incidents),
    )
