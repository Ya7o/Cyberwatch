"""Résolution sectorielle sourcée ; les absences et conflits restent explicites."""
from __future__ import annotations

import json
from dataclasses import dataclass

from . import config
from . import sector as sector_policy
from .collectors.base import RawEntry
from .model import Incident, Item
from .normalize import organisation_key

SECTOR_UNKNOWN_TARGET_PCT = 10.0  # Alerte, jamais un secteur par défaut.
POLICY_VERSION = "2026-09-06.sector.3"


@dataclass(frozen=True)
class SectorDecision:
    sector: str
    status: str
    reason: str
    confidence: float
    evidence: str
    evidence_url: str = ""


def _valid(sector: str) -> bool:
    return sector in config.SECTORS and sector != config.SECTOR_UNKNOWN


def _unknown(reason: str = "NO_ACTIVITY_EVIDENCE", evidence: str = "") -> SectorDecision:
    return SectorDecision(config.SECTOR_UNKNOWN, "unknown", reason, 0.0, evidence)


def _decision_from_facts(item: Item, fact: dict) -> SectorDecision | None:
    from .sector_activity import supported_activity

    raw = str(fact.get("Source_Sector_Raw") or "").strip()
    sector = sector_policy.classify_source_sector(raw)
    reported = (SectorDecision(sector, "reported", "SOURCE_SECTOR_RAW", 0.70, raw, item.URL)
                if _valid(sector) else None)
    activity = str(fact.get("Activity_Description") or "").strip()
    try:
        evidence = json.loads(fact.get("Evidence_JSON") or "{}")
    except (ValueError, TypeError):
        evidence = {}
    proof = str(evidence.get("Activity_Description") or "") if isinstance(evidence, dict) else ""
    matched = str(fact.get("Activity_Sector_Match") or "").strip()
    if not activity:
        return reported or (_unknown("ORPHAN_SECTOR_MATCH") if _valid(matched) else None)
    if not supported_activity(item.Organisation_Raw, activity, proof):
        return reported or _unknown("ACTIVITY_EVIDENCE_REJECTED", proof)
    rule = sector_policy.classify_sector_activity(activity)
    proof_rule = sector_policy.classify_sector_activity(proof)
    if _valid(proof_rule) and _valid(rule) and proof_rule != rule:
        return SectorDecision(
            proof_rule,
            "inferred",
            "ACTIVITY_EVIDENCE_RULE",
            0.80,
            f"{proof} [description sémantique écartée : {activity}]",
            item.URL,
        )
    if _valid(rule) and _valid(matched) and rule != matched:
        return _unknown("ACTIVITY_SECTOR_CONFLICT", f"{rule} | {matched} : {proof}")
    value = rule if _valid(rule) else matched
    if _valid(value):
        reason = "ACTIVITY_RULE" if _valid(rule) else "SEMANTIC_ACTIVITY_MATCH"
        if reported and reported.sector != value:
            reason = "ACTIVITY_OVERRIDES_SOURCE_LABEL"
            proof = f"{proof} [étiquette source écartée : {raw}]"
        return SectorDecision(value, "inferred", reason, 0.80, proof, item.URL)
    return reported or _unknown("ACTIVITY_TAXONOMY_UNRESOLVED", proof)


def _decision_from_reference(item: Item, reference: dict) -> SectorDecision | None:
    entry = reference.get(organisation_key(item.Organisation_Raw))
    sector = str(getattr(entry, "sector", "") or "")
    url = str(getattr(entry, "validation_url", "") or "")
    if not _valid(sector) or not url:
        return None
    return SectorDecision(sector, "referenced", "REFERENCE_EXACT", 0.90,
                          str(getattr(entry, "reason", "") or item.Organisation_Raw), url)


def _previous_decision(item: Item, previous: dict) -> SectorDecision | None:
    if previous.get("Resolved_Sector") != item.Sector:
        return None
    if previous.get("Reason") == "DEFAULT_OPERATIONAL_FALLBACK":
        return _unknown()
    try:
        confidence = float(previous.get("Confidence") or 0)
    except (ValueError, TypeError):
        confidence = 0.0
    return SectorDecision(item.Sector, str(previous.get("Status") or "reported"),
                          str(previous.get("Reason") or "LEGACY_KNOWN_SECTOR"), confidence,
                          str(previous.get("Evidence") or ""),
                          str(previous.get("Evidence_URL") or ""))


def resolve_item(
    item: Item, fact: dict, reference: dict, previous: dict | None = None,
) -> SectorDecision:
    """Référence validée, nom institutionnel sûr, activité ; aucun repli inventé."""
    referenced = _decision_from_reference(item, reference)
    if referenced:
        return referenced
    named = sector_policy.classify_sector_name(item.Organisation_Raw)
    if _valid(named):
        return SectorDecision(named, "inferred", "ORGANISATION_NAME_RULE", 0.80,
                              item.Organisation_Raw, item.URL)
    facts = _decision_from_facts(item, fact)
    if facts:
        return facts
    preserved = _previous_decision(item, previous or {})
    if preserved:
        return preserved
    if _valid(item.Sector):
        return SectorDecision(item.Sector, "reported", "LEGACY_KNOWN_SECTOR", 0.50,
                              item.Sector, item.URL)
    return _unknown()


def resolve_items(
    items: list[Item], source_facts: list[dict], reference: dict,
    *, run_id: str = "", as_of: str = "", previous_rows: list[dict] | None = None,
) -> list[dict]:
    facts = {str(row.get("Item_ID") or ""): row for row in source_facts}
    previous = {str(row.get("Item_ID") or ""): row for row in previous_rows or []}
    rows: list[dict] = []
    for item in items:
        before = item.Sector or config.SECTOR_UNKNOWN
        decision = resolve_item(item, facts.get(item.Item_ID, {}), reference,
                                previous.get(item.Item_ID))
        item.Sector = decision.sector
        item._sector_decision = decision
        rows.append({
            "Run_ID": run_id, "As_Of": as_of, "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Organisation_Key": item.Organisation_Key or organisation_key(item.Organisation_Raw),
            "Organisation": item.Organisation_Raw, "Previous_Sector": before,
            "Resolved_Sector": decision.sector, "Status": decision.status,
            "Reason": decision.reason, "Confidence": f"{decision.confidence:.2f}",
            "Evidence": decision.evidence, "Evidence_URL": decision.evidence_url,
            "Policy_Version": POLICY_VERSION,
        })
    return sorted(rows, key=lambda row: (row["Organisation_Key"], row["Item_ID"]))


def component_sector(items: list[Item]) -> str:
    """Un désaccord entre sources ne dépend jamais de leur ordre."""
    return component_sector_rows([
        {"Resolved_Sector": item.Sector,
         "Reason": getattr(getattr(item, "_sector_decision", None), "reason", "")}
        for item in items
    ])


def component_sector_rows(rows: list[dict]) -> str:
    """An activity with evidence outranks an unsubstantiated source label.

    Conflicting activities remain unresolved; no voting by source count.
    The same policy is used when projecting persisted decisions to the site.
    """
    if any("CONFLICT" in str(row.get("Reason", "")) for row in rows):
        return config.SECTOR_UNKNOWN
    known = [row for row in rows if _valid(str(row.get("Resolved_Sector") or ""))]
    sectors = {row["Resolved_Sector"] for row in known}
    if len(sectors) > 1:
        supported = {row["Resolved_Sector"] for row in known if row.get("Reason") in {
            "REFERENCE_EXACT", "ACTIVITY_RULE", "SEMANTIC_ACTIVITY_MATCH",
            "ACTIVITY_OVERRIDES_SOURCE_LABEL", "ORGANISATION_NAME_RULE",
        }}
        weak_only = all(row["Resolved_Sector"] in supported or row.get("Reason") in {
            "SOURCE_SECTOR_RAW", "LEGACY_KNOWN_SECTOR",
        } for row in known)
        if len(supported) == 1 and weak_only:
            return next(iter(supported))
    return next(iter(sectors)) if len(sectors) == 1 else config.SECTOR_UNKNOWN


def transport_gaps(items: list[Item], rows: list[dict]) -> list[str]:
    decisions = {row.get("Item_ID"): row for row in rows}
    return [item.Item_ID for item in items if decisions.get(item.Item_ID, {}).get(
        "Resolved_Sector", item.Sector) != item.Sector]


def fact_transport_gaps(items: list[Item], facts: list[dict], reference: dict) -> list[str]:
    by_id = {row.get("Item_ID"): row for row in facts}
    gaps = []
    for item in items:
        expected = resolve_item(item, by_id.get(item.Item_ID, {}), reference)
        if _valid(expected.sector) and item.Sector != expected.sector:
            gaps.append(item.Item_ID)
    return gaps


def unknown_rate(items: list[Item]) -> float:
    unknown = sum(item.Sector == config.SECTOR_UNKNOWN for item in items)
    return round(100.0 * unknown / len(items), 2) if items else 0.0


# Une valeur héritée sans preuve n'est pas une qualification achevée.
SUPPORTED_REASONS = frozenset({
    "REFERENCE_EXACT", "ORGANISATION_NAME_RULE", "SOURCE_SECTOR_RAW",
    "ACTIVITY_RULE", "ACTIVITY_EVIDENCE_RULE", "SEMANTIC_ACTIVITY_MATCH",
    "ACTIVITY_OVERRIDES_SOURCE_LABEL",
})


def entry_sector_decision(item: Item, entry: RawEntry) -> SectorDecision | None:
    """Preuve indépendante de la description métier, disponible avant le LLM."""
    from . import article_body, enrichment
    from .source_facts import _native_frenchbreaches_sector

    raw = entry.sector
    if item.Source_ID == "FRENCHBREACHES":
        raw = _native_frenchbreaches_sector(article_body.body(entry.content)) or raw
    decision = resolve_item(item, {"Source_Sector_Raw": raw}, enrichment.load_reference())
    return decision if decision.reason in SUPPORTED_REASONS and _valid(decision.sector) else None


def qualification_summary(rows: list[dict], incidents: list[Incident] | None = None) -> dict:
    """Couverture sectorielle distincte de la qualité d'une description métier."""
    resolved = [row["Item_ID"] for row in rows
                if _valid(str(row.get("Resolved_Sector") or ""))
                and row.get("Reason") in SUPPORTED_REASONS]
    conflicts = [row["Item_ID"] for row in rows if "CONFLICT" in str(row.get("Reason", ""))]
    unknown = [row["Item_ID"] for row in rows if row["Item_ID"] not in resolved]
    unknown_incidents = (sum(i.Secteur == config.SECTOR_UNKNOWN for i in incidents)
                         if incidents is not None else None)
    return {
        "resolved_item_ids": sorted(resolved), "unknown_item_ids": sorted(unknown),
        "conflict_item_ids": sorted(conflicts), "items": len(rows),
        "resolved": len(resolved), "unknown_incidents": unknown_incidents,
        "state": "PARTIAL" if unknown or unknown_incidents else "COMPLETE",
    }
