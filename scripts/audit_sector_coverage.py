#!/usr/bin/env python3
"""Audit offline de la couverture Sector et des catégories ransomware.live.

Le rapport est volontairement descriptif : il mesure le stock d'Inconnu et les
valeurs source structurées susceptibles d'être mappées, sans jamais modifier la
base. Il peut être versionné après un rebuild afin de disposer d'un point de
mesure exact, contrairement à l'ancienne baseline historique.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import quality, store


def build_report() -> dict:
    items = store.load_items()
    facts = store.read_csv(store.SOURCE_FACTS_CSV)
    return {
        "schema_version": 1,
        "snapshot": {
            "code_commit": store.load_snapshot().get("Code_Commit", ""),
            "items_hash": store.load_snapshot().get("Items_Hash", ""),
            "incidents_hash": store.load_snapshot().get("Incidents_Hash", ""),
        },
        "sector": quality.metrics(items),
        "ransomware_live": quality.ransomware_source_sector_audit(items, facts),
    }


def print_report(report: dict) -> None:
    global_metrics = report["sector"]["global"]
    print("SECTOR COVERAGE AUDIT")
    print(
        "global: "
        f"items={global_metrics['items']} "
        f"known={global_metrics['sector_known']} "
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
        print(
            f"{raw}\t{row['items']}\t{row['current_unknown']}\t{row['mapped_sector']}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "sector_quality.json"),
        help="Rapport JSON à écrire. Utiliser une chaîne vide pour ne rien écrire.",
    )
    args = parser.parse_args()

    report = build_report()
    print_report(report)
    if args.output:
        target = Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"json={target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
