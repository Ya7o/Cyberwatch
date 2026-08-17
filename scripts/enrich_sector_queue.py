#!/usr/bin/env python3
"""Enrichit la file Sector sans modifier directement la vérité canonique.

La résolution du registre public reste séquentielle car elle partage un état de
budget/cache. Les lectures de sites officiels, indépendantes et read-only, sont
parallélisées avec un petit pool borné. La politique du registre reste la seule
couche autorisée à écrire ensuite un Sector canonique.
"""
from __future__ import annotations

import datetime as dt
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import company_subject_evidence, org_enrichment, sector_registry, store
from cyberwatch.model import ORG_ENRICHMENT_CACHE_COLUMNS


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _empty_cache_row() -> dict[str, str]:
    return {column: "" for column in ORG_ENRICHMENT_CACHE_COLUMNS}


def _strict_official(organisation: str):
    try:
        return company_subject_evidence.resolve_official_site_subject_attributed(
            organisation
        )
    except Exception:
        return None


def main() -> int:
    queue_path = store.ITEMS_CSV.parent / sector_registry.QUEUE_CSV.name
    queue = store.read_csv(queue_path)
    if not queue:
        print("SECTOR ENRICHMENT: queue vide")
        return 0

    limit = max(0, _env_int("SECTOR_ENRICHMENT_MAX_ORGS", 60))
    workers = max(1, min(8, _env_int("SECTOR_ENRICHMENT_WORKERS", 6)))
    selected = queue[:limit] if limit else []
    state = org_enrichment.start_state()
    if not state.enabled:
        state.enabled = True
    state.max_calls = max(state.max_calls, len(selected))
    # Le fallback officiel historique de org_enrichment reste coupé : seul le
    # résolveur subject-attributed peut produire une preuve officielle Sector.
    state.official_site_max_calls = 0

    now = dt.datetime.now(dt.timezone(dt.timedelta(hours=4))).isoformat()
    stats = {
        "selected": len(selected),
        "registry_attempted": 0,
        "registry_matched": 0,
        "strict_official_attempted": 0,
        "strict_official_matched": 0,
        "cache_existing": 0,
        "official_workers": workers,
    }
    targets: list[tuple[str, str]] = []

    # Phase 1 : état partagé, donc volontairement séquentielle.
    for queue_row in selected:
        key = (queue_row.get("Organisation_Key") or "").strip()
        organisation = (queue_row.get("Organisation") or "").strip()
        if not key or not organisation:
            continue
        targets.append((key, organisation))

        existing = state.cache.get(key)
        if existing:
            stats["cache_existing"] += 1
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

    # Phase 2 : chaque appel est une lecture HTTP indépendante. Aucun thread ne
    # touche state.cache ; les résultats sont fusionnés séquentiellement après.
    evidence_by_key = {}
    stats["strict_official_attempted"] = len(targets)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(_strict_official, organisation): (key, organisation)
            for key, organisation in targets
        }
        for future in as_completed(futures):
            key, organisation = futures[future]
            evidence = future.result()
            if evidence is not None:
                evidence_by_key[key] = (organisation, evidence)

    for key, (organisation, evidence) in sorted(evidence_by_key.items()):
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
