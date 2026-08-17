#!/usr/bin/env python3
"""Enrichit la file Sector sans modifier directement la vérité canonique.

Le registre public sert à établir une identité exacte et des métadonnées. La
preuve de secteur officielle utilise le résolveur avec attribution du sujet.
Tous les résultats sont stockés dans ``org_enrichment_cache.csv`` ; seule la
politique du registre décide ensuite si un candidat peut être appliqué.
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import company_subject_evidence, config, org_enrichment, sector_registry, store
from cyberwatch.model import ORG_ENRICHMENT_CACHE_COLUMNS


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _empty_cache_row() -> dict[str, str]:
    return {column: "" for column in ORG_ENRICHMENT_CACHE_COLUMNS}


def main() -> int:
    queue_path = store.ITEMS_CSV.parent / sector_registry.QUEUE_CSV.name
    queue = store.read_csv(queue_path)
    if not queue:
        print("SECTOR ENRICHMENT: queue vide")
        return 0

    limit = max(0, _env_int("SECTOR_ENRICHMENT_MAX_ORGS", 60))
    selected = queue[:limit] if limit else []
    state = org_enrichment.start_state()
    if not state.enabled:
        # Ce worker a son propre budget explicite ; l'enrichissement réseau est
        # activé ici même si la collecte courante désactive ORG_ENRICHMENT.
        state.enabled = True
    state.max_calls = max(state.max_calls, len(selected))
    # Le fallback officiel historique n'est jamais appelé depuis resolve() :
    # seule la version subject-attributed ci-dessous est admissible en Sprint C.
    state.official_site_max_calls = 0

    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=4))).isoformat()
    stats = {
        "selected": len(selected),
        "registry_attempted": 0,
        "registry_matched": 0,
        "strict_official_attempted": 0,
        "strict_official_matched": 0,
        "cache_existing": 0,
    }

    for queue_row in selected:
        key = (queue_row.get("Organisation_Key") or "").strip()
        organisation = (queue_row.get("Organisation") or "").strip()
        if not key or not organisation:
            continue

        existing = state.cache.get(key)
        if existing:
            stats["cache_existing"] += 1

        # Tente le registre exact pour conserver SIREN/NAF/localisation. Avec
        # official_site_max_calls=0, aucun ancien moteur officiel n'intervient.
        record = None
        if not existing or existing.get("Match_Status") not in {
            org_enrichment.MATCHED, org_enrichment.AMBIGUOUS
        }:
            stats["registry_attempted"] += 1
            record = org_enrichment.resolve(key, organisation, now, state)
        elif existing.get("Match_Status") == org_enrichment.MATCHED:
            stats["registry_matched"] += 1

        if record is not None and record.Match_Status == org_enrichment.MATCHED:
            stats["registry_matched"] += 1

        # La recherche officielle stricte est indépendante du résultat légal :
        # elle peut confirmer une marque que le registre ne résout pas ou dont
        # le véhicule juridique ne décrit pas correctement l'activité réelle.
        stats["strict_official_attempted"] += 1
        try:
            evidence = company_subject_evidence.resolve_official_site_subject_attributed(
                organisation
            )
        except Exception:
            evidence = None
        if evidence is None:
            continue

        stats["strict_official_matched"] += 1
        current = dict(state.cache.get(key) or _empty_cache_row())
        current.update({
            "Organisation_Key": key,
            "Query_Name": organisation,
            "Matched_Name": current.get("Matched_Name") or organisation,
            "Activity_Label": evidence.evidence_text,
            "Evidence_Source": evidence.evidence_source,
            "Evidence_URL": evidence.evidence_url,
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": now,
            "Validated_Sector": evidence.sector,
            "Validated_Via": "official_subject_activity",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        })
        state.cache[key] = current

    rows = [
        {column: row.get(column, "") for column in ORG_ENRICHMENT_CACHE_COLUMNS}
        for _key, row in sorted(state.cache.items())
    ]
    store.save_org_enrichment_cache(rows)

    print("SECTOR ENRICHMENT")
    for key, value in stats.items():
        print(f"{key}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
