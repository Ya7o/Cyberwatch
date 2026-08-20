#!/usr/bin/env python3
"""Exécute une réévaluation Sector Golden réellement ciblée.

Ce wrapper rend la purge observable et vérifiable avant tout appel réseau :
- détecte les organisations Golden dont le Sector courant est faux ;
- purge uniquement leur conclusion Sector et conserve l'identité légale ;
- persiste immédiatement l'invalidation du cache Sector ;
- force le rejeu de ces seules organisations en contournant le TTL ;
- réapplique avant le Golden une décision AUTO officielle/manuelle du registre ;
- échoue si des mismatches existent mais qu'aucune purge effective n'a lieu.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import (
    config,
    enrichment,
    org_enrichment,
    sector_registry,
    sector_registry_safety,
    store,
)
from cyberwatch.model import ORG_ENRICHMENT_CACHE_COLUMNS
from scripts import enrich_sector_queue


_AUTHORITATIVE_PROPAGATION_CHANNELS = {
    "manual_reference",
    "official_subject_activity",
}


def _current_mismatch_keys(items) -> set[str]:
    expected = enrich_sector_queue._golden_expected_sector_by_key()
    explicit = enrich_sector_queue._target_keys_from_env()
    current: dict[str, set[str]] = {}
    for item in items:
        if not item.Organisation_Key:
            continue
        current.setdefault(item.Organisation_Key, set()).add(item.Sector)
    return {
        key
        for key, expected_sector in expected.items()
        if (not explicit or key in explicit)
        and key in current
        and any(value != expected_sector for value in current[key])
    }


def _save_cache(cache: dict[str, dict]) -> None:
    rows = [
        {column: row.get(column, "") for column in ORG_ENRICHMENT_CACHE_COLUMNS}
        for _key, row in sorted(cache.items())
    ]
    store.save_org_enrichment_cache(rows)


def _apply_authoritative_registry_rows(items, registry_rows: list[dict], target_keys: set[str]) -> int:
    """Propage les décisions AUTO fortes vers les items ciblés, même déjà connus.

    ``sector_registry.apply_registry`` reste volontairement conservateur pour le
    pipeline général et n'écrase pas un secteur déjà connu. Le closeout Golden a
    toutefois besoin de matérialiser une décision plus forte fraîchement établie
    après purge. Seules les décisions AUTO issues d'une référence manuelle ou
    d'une activité officielle explicitement attribuée au sujet peuvent écraser
    la valeur précédente ; un signal structuré faible ne le peut jamais.
    """
    authoritative = {
        (row.get("Organisation_Key") or "").strip(): row
        for row in registry_rows
        if (row.get("Organisation_Key") or "").strip() in target_keys
        and row.get("Decision") == sector_registry.DECISION_AUTO
        and row.get("Evidence_Type") in _AUTHORITATIVE_PROPAGATION_CHANNELS
        and row.get("Sector") in config.SECTORS
        and row.get("Sector") != config.SECTOR_UNKNOWN
    }
    changed = 0
    for item in items:
        row = authoritative.get(item.Organisation_Key)
        if row is None or item.Sector == row["Sector"]:
            continue
        item.Sector = row["Sector"]
        changed += 1
    return changed


def _propagate_authoritative_registry(target_keys: set[str]) -> int:
    """Reconstruit le registre après enrichissement puis matérialise ses AUTO forts."""
    if not target_keys:
        print("REGISTRY_PROPAGATION changed_items=0 authoritative_orgs=0")
        return 0

    items = store.load_items()
    reference = enrichment.load_reference()
    source_facts = store.read_csv(store.SOURCE_FACTS_CSV)
    cache_rows = store.load_org_enrichment_cache()
    previous_provenance = store.load_qualification_provenance()
    registry_rows = sector_registry.build_registry(
        items,
        reference,
        source_fact_rows=source_facts,
        org_cache_rows=cache_rows,
        previous_provenance=previous_provenance,
    )
    sector_registry_safety.enforce_candidate_conflicts(registry_rows)

    authoritative_orgs = {
        (row.get("Organisation_Key") or "").strip()
        for row in registry_rows
        if (row.get("Organisation_Key") or "").strip() in target_keys
        and row.get("Decision") == sector_registry.DECISION_AUTO
        and row.get("Evidence_Type") in _AUTHORITATIVE_PROPAGATION_CHANNELS
        and row.get("Sector") in config.SECTORS
        and row.get("Sector") != config.SECTOR_UNKNOWN
    }
    changed = _apply_authoritative_registry_rows(items, registry_rows, target_keys)
    if changed:
        store.save_items(items)

    print(
        "REGISTRY_PROPAGATION "
        f"changed_items={changed} authoritative_orgs={len(authoritative_orgs)} "
        f"keys={','.join(sorted(authoritative_orgs))}"
    )
    return changed


def main() -> int:
    os.environ["SECTOR_ENRICHMENT_MODE"] = "golden-only"
    os.environ.setdefault("SECTOR_PURGE_GOLDEN_MISMATCHES", "1")

    items = store.load_items()
    mismatch_keys = _current_mismatch_keys(items)
    state = org_enrichment.start_state()
    if not state.enabled:
        state.enabled = True

    legal_identity_retained = sum(
        1
        for key in mismatch_keys
        if (state.cache.get(key) or {}).get("Company_ID")
        or (state.cache.get(key) or {}).get("Matched_Name")
        or (state.cache.get(key) or {}).get("Evidence_URL")
    )

    purge_keys, stats = enrich_sector_queue._purge_golden_mismatches(
        items, state.cache, "golden-only"
    )

    print("GOLDEN_PURGE_DIAGNOSTIC")
    print(f"mismatch_organisations={len(mismatch_keys)}")
    print(f"purged_organisations={stats['purged_organisations']}")
    print(f"purged_items={stats['purged_items']}")
    print(f"purged_cache_rows={stats['purged_cache_rows']}")
    print(f"legal_identity_retained={legal_identity_retained}")
    print("mismatch_keys=" + ",".join(sorted(mismatch_keys)))
    print("purge_keys=" + ",".join(sorted(purge_keys)))

    if mismatch_keys and not purge_keys:
        print(
            "GOLDEN_PURGE_ERROR: des mismatches existent mais aucune purge n'a été effectuée",
            file=sys.stderr,
        )
        return 3

    if purge_keys != mismatch_keys:
        missing = sorted(mismatch_keys - purge_keys)
        unexpected = sorted(purge_keys - mismatch_keys)
        print(
            "GOLDEN_PURGE_ERROR: scope de purge incohérent "
            f"missing={','.join(missing)} unexpected={','.join(unexpected)}",
            file=sys.stderr,
        )
        return 4

    _save_cache(state.cache)

    if not purge_keys:
        print("TARGETED_QUEUE count=0 keys=")
        print("Aucun mismatch Sector Golden à réévaluer.")
        return 0

    os.environ["SECTOR_ENRICHMENT_TARGET_KEYS"] = ",".join(sorted(purge_keys))
    # La purge a déjà été exécutée et persistée ci-dessus. Le runner sous-jacent
    # ne doit pas recalculer son scope une seconde fois.
    os.environ["SECTOR_PURGE_GOLDEN_MISMATCHES"] = "0"

    print(
        f"TARGETED_QUEUE count={len(purge_keys)} keys="
        + ",".join(sorted(purge_keys))
    )
    result = enrich_sector_queue.main()
    if result != 0:
        return result

    # Le cache et le registre viennent d'être recalculés. Matérialiser maintenant
    # les décisions AUTO les plus fortes évite que le backfill suivant réinjecte
    # d'abord une ancienne catégorie structurée faible puis refuse de l'écraser.
    _propagate_authoritative_registry(purge_keys)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
