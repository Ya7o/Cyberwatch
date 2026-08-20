"""Gardes supplémentaires du registre Sector.

Toute contradiction entre preuves connues bloque l'auto-propagation par
défaut. Une exception étroite existe pour une preuve officielle fortement
attribuée au sujet : elle peut dominer des signaux secondaires désactivés
(structured/known item), mais jamais une référence manuelle ni un autre canal
auto contradictoire.
"""
from __future__ import annotations

from . import company_subject_evidence, config, sector_registry, store


def _strong_official_override(row: dict, cache_by_key: dict[str, dict]) -> str | None:
    if row.get("Decision") != sector_registry.DECISION_CONFLICT:
        return None
    evidence_types = {
        part.strip()
        for part in (row.get("Evidence_Types") or "").split(" | ")
        if part.strip()
    }
    if "manual_reference" in evidence_types:
        return None
    if "official_subject_activity" not in evidence_types:
        return None

    key = (row.get("Organisation_Key") or "").strip()
    cached = cache_by_key.get(key) or {}
    if cached.get("Validated_Via") != "official_subject_activity":
        return None
    cached_sector = (cached.get("Validated_Sector") or "").strip()
    if cached_sector not in config.SECTORS or cached_sector == config.SECTOR_UNKNOWN:
        return None

    strong = company_subject_evidence.strong_subject_attributed_activity(
        row.get("Organisation") or cached.get("Query_Name") or key,
        cached.get("Activity_Label") or "",
    )
    if strong is None or strong[0] != cached_sector:
        return None
    return cached_sector


def enforce_candidate_conflicts(rows: list[dict]) -> list[dict]:
    cache_by_key = {
        (entry.get("Organisation_Key") or "").strip(): entry
        for entry in store.load_org_enrichment_cache()
        if (entry.get("Organisation_Key") or "").strip()
    }
    for row in rows:
        candidates = {
            part.strip()
            for part in (row.get("Candidate_Sectors") or "").split(" | ")
            if part.strip() and part.strip() != config.SECTOR_UNKNOWN
        }
        if len(candidates) <= 1:
            continue

        override = _strong_official_override(row, cache_by_key)
        if override is not None:
            row["Decision"] = sector_registry.DECISION_AUTO
            row["Sector"] = override
            row["Confidence"] = "HIGH"
            row["Evidence_Type"] = "official_subject_activity"
            row["Policy_Auto_Enabled"] = "1"
            continue

        row["Decision"] = sector_registry.DECISION_CONFLICT
        row["Sector"] = config.SECTOR_UNKNOWN
        row["Confidence"] = ""
        row["Policy_Auto_Enabled"] = "0"
    return rows
