#!/usr/bin/env python3
"""Audit offline de la couverture Sector, du registre et de la file d'enrichissement."""
from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import enrichment, quality, sector_registry, sector_registry_safety, store
from cyberwatch.qualification import backfill_structured_source_sectors


def build_report() -> tuple[dict, list[dict], list[dict]]:
    items = store.load_items()
    facts = store.read_csv(store.SOURCE_FACTS_CSV)
    provenance = store.load_qualification_provenance()
    current = quality.metrics(items)
    ransomware = quality.ransomware_source_sector_audit(items, facts)

    projected_items = copy.deepcopy(items)
    projected_applied = backfill_structured_source_sectors(projected_items, facts)
    projected = quality.metrics(projected_items)
    current_global = current["global"]
    projected_global = projected["global"]

    registry = sector_registry.build_registry(
        items,
        enrichment.load_reference(),
        source_fact_rows=facts,
        org_cache_rows=store.load_org_enrichment_cache(),
        previous_provenance=provenance,
    )
    sector_registry_safety.enforce_candidate_conflicts(registry)
    queue = sector_registry.build_enrichment_queue(
        items,
        registry,
        source_fact_rows=facts,
        challenger_provenance=provenance,
    )
    registry_info = sector_registry.registry_summary(registry, queue)

    report = {
        "schema_version": 2,
        "snapshot": {
            "code_commit": store.load_snapshot().get("Code_Commit", ""),
            "items_hash": store.load_snapshot().get("Items_Hash", ""),
            "incidents_hash": store.load_snapshot().get("Incidents_Hash", ""),
        },
        "sector": current,
        "ransomware_live": ransomware,
        "structured_backfill_projection": {
            "applied": projected_applied,
            "sector_unknown_before": current_global["sector_unknown"],
            "sector_unknown_after": projected_global["sector_unknown"],
            "sector_coverage_before": current_global["sector_coverage_ratio"],
            "sector_coverage_after": projected_global["sector_coverage_ratio"],
            "metrics": projected,
        },
        "organisation_registry": registry_info,
        "auto_policy": sector_registry.load_policy(),
    }
    return report, registry, queue


def print_report(report: dict) -> None:
    global_metrics = report["sector"]["global"]
    print("SECTOR COVERAGE AUDIT")
    print(
        "global: "
        f"items={global_metrics['items']} known={global_metrics['sector_known']} "
        f"unknown={global_metrics['sector_unknown']} "
        f"coverage={global_metrics['sector_coverage_ratio'] * 100:.2f}% "
        f"unknown_orgs={global_metrics['sector_unknown_organisations']} "
        f"repeated_unknown_orgs={global_metrics['sector_unknown_repeated_organisations']}"
    )
    for source_id, metrics in report["sector"]["sources"].items():
        print(
            f"source={source_id} items={metrics['items']} "
            f"unknown={metrics['sector_unknown']} "
            f"coverage={metrics['sector_coverage_ratio'] * 100:.2f}% "
            f"unknown_orgs={metrics['sector_unknown_organisations']}"
        )

    ransomware = report["ransomware_live"]
    print()
    print(
        "RANSOMWARE_LIVE: "
        f"items={ransomware['items']} current_unknown={ransomware['current_unknown']} "
        f"unknown_with_raw={ransomware['unknown_with_raw']} "
        f"unknown_without_raw={ransomware['unknown_without_raw']} "
        f"raw_mappable={ransomware['unknown_raw_mappable']} "
        f"raw_unmapped={ransomware['unknown_raw_unmapped']}"
    )
    print("raw_value\titems\tcurrent_unknown\tmapped_sector")
    for raw, row in ransomware["raw_values"].items():
        print(f"{raw}\t{row['items']}\t{row['current_unknown']}\t{row['mapped_sector']}")

    projection = report["structured_backfill_projection"]
    print()
    print(
        "STRUCTURED BACKFILL PROJECTION: "
        f"applied={projection['applied']} "
        f"unknown={projection['sector_unknown_before']}->{projection['sector_unknown_after']} "
        f"coverage={projection['sector_coverage_before'] * 100:.2f}%"
        f"->{projection['sector_coverage_after'] * 100:.2f}%"
    )

    registry = report["organisation_registry"]
    print()
    print(
        "ORGANISATION REGISTRY: "
        f"rows={registry['registry_rows']} auto={registry['auto_rows']} "
        f"review={registry['review_rows']} conflicts={registry['conflict_rows']} "
        f"queue={registry['queue_organisations']}"
    )
    print("registry_channels=" + json.dumps(registry["registry_channels"], ensure_ascii=False, sort_keys=True))
    print("queue_categories=" + json.dumps(registry["queue_categories"], ensure_ascii=False, sort_keys=True))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "sector_quality.json"),
        help="Rapport JSON à écrire. Chaîne vide = lecture seule.",
    )
    args = parser.parse_args()
    report, registry, queue = build_report()
    print_report(report)
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        sector_registry.write_outputs(registry, queue)
        print(f"json={target}")
        print(f"registry={sector_registry._aux_path(sector_registry.REGISTRY_CSV)}")
        print(f"queue={sector_registry._aux_path(sector_registry.QUEUE_CSV)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
