#!/usr/bin/env python3
"""Reconstruit l'état Sector utile après une base dérivée vidée.

Objectif volontairement étroit : repartir des sources, reconstruire les preuves
organisationnelles nécessaires, puis appliquer la qualification Sector. Aucun
benchmark ni Golden n'est exécuté ici.

Usage normal après purge des fichiers dérivés::

    python scripts/bootstrap_sector_state.py

Le script :
1. lance ``cyberwatch create`` seulement si ``items.csv`` est absent/vide ;
2. reconstruit registre + queue Sector depuis les items/source facts présents ;
3. enrichit en mode ``full`` les organisations encore inconnues ainsi que les
   organisations provenant de ransomware.live (secteur source à challenger) ;
4. rejoue la qualification canonique et persiste items/incidents/provenance.

Les sources/configurations versionnées ne sont jamais supprimées par ce script.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import config, enrichment, sector_registry, store
from cyberwatch.qualification import qualify
from cyberwatch.runner import save_snapshot_provenance


def _run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    merged = os.environ.copy()
    if env:
        merged.update(env)
    subprocess.run(command, cwd=ROOT, env=merged, check=True)


def _write_registry_and_queue() -> tuple[list[dict], list[dict]]:
    items = store.load_items()
    source_facts = store.load_source_facts()
    org_cache = store.load_org_enrichment_cache()
    provenance = store.load_qualification_provenance()
    reference = enrichment.load_reference()

    registry = sector_registry.build_registry(
        items,
        reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        previous_provenance=provenance,
    )
    queue = sector_registry.build_enrichment_queue(
        items,
        registry,
        source_fact_rows=source_facts,
        challenger_provenance=provenance,
    )
    store.write_csv(
        store.ITEMS_CSV.parent / sector_registry.REGISTRY_CSV.name,
        sector_registry.REGISTRY_COLUMNS,
        registry,
    )
    store.write_csv(
        store.ITEMS_CSV.parent / sector_registry.QUEUE_CSV.name,
        sector_registry.QUEUE_COLUMNS,
        queue,
    )
    return registry, queue


def _target_keys() -> set[str]:
    """Cible utile : inconnus + secteurs natifs ransomware.live à challenger."""
    targets: set[str] = set()
    for item in store.load_items():
        if not item.Organisation_Key:
            continue
        if item.Sector == config.SECTOR_UNKNOWN or item.Source_ID == "RANSOMWARE_LIVE":
            targets.add(item.Organisation_Key)
    return targets


def _persist_final_qualification() -> tuple[int, int, int]:
    qualified = qualify(store.load_items())
    store.save_items(qualified.items)
    store.save_incidents(qualified.incidents)
    store.save_qualification_provenance(qualified.provenance)
    store.save_incident_id_registry(qualified.incident_id_registry)
    _write_registry_and_queue()
    save_snapshot_provenance(
        qualified.items,
        qualified.incidents,
        operation="SECTOR_COLD_BOOTSTRAP",
    )
    unknown = sum(item.Sector == config.SECTOR_UNKNOWN for item in qualified.items)
    return len(qualified.items), len(qualified.incidents), unknown


def bootstrap(*, workers: int = 6, max_orgs: int = 0, skip_create: bool = False) -> int:
    if not store.load_items():
        if skip_create:
            print("SECTOR_BOOTSTRAP=FAIL reason=no_items_and_create_disabled")
            return 2
        print("SECTOR_BOOTSTRAP create_from_sources=1")
        _run([sys.executable, "-m", "cyberwatch", "create"])

    if not store.load_items():
        print("SECTOR_BOOTSTRAP=FAIL reason=create_produced_no_items")
        return 2

    registry_before, queue_before = _write_registry_and_queue()
    targets = _target_keys()
    print(
        "SECTOR_BOOTSTRAP prepare "
        f"items={len(store.load_items())} registry={len(registry_before)} "
        f"queue={len(queue_before)} targets={len(targets)}"
    )

    if targets:
        env = {
            "SECTOR_ENRICHMENT_MODE": "full",
            "SECTOR_ENRICHMENT_TARGET_KEYS": ",".join(sorted(targets)),
            "SECTOR_ENRICHMENT_MAX_ORGS": str(max(0, max_orgs)),
            "SECTOR_ENRICHMENT_WORKERS": str(max(1, min(8, workers))),
            # Le bootstrap froid ne doit jamais utiliser la logique Golden/purge.
            "SECTOR_PURGE_GOLDEN_MISMATCHES": "0",
        }
        _run([sys.executable, "scripts/enrich_sector_queue.py"], env=env)

    items_count, incidents_count, unknown_count = _persist_final_qualification()
    cache = store.load_org_enrichment_cache()
    official = sum(
        row.get("Validated_Via") == "official_subject_activity"
        and bool(row.get("Validated_Sector"))
        for row in cache
    )
    print(
        "SECTOR_BOOTSTRAP=PASS "
        f"items={items_count} incidents={incidents_count} unknown={unknown_count} "
        f"cache={len(cache)} official_proofs={official}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Reconstruit les preuves et secteurs après purge de la base dérivée."
    )
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument(
        "--max-orgs",
        type=int,
        default=0,
        help="0 = toutes les organisations ciblées (défaut pour un cold bootstrap).",
    )
    parser.add_argument(
        "--skip-create",
        action="store_true",
        help="échoue au lieu de lancer create lorsque items.csv est vide",
    )
    args = parser.parse_args()
    return bootstrap(workers=args.workers, max_orgs=args.max_orgs, skip_create=args.skip_create)


if __name__ == "__main__":
    raise SystemExit(main())
