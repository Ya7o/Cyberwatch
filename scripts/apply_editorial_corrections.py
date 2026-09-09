"""Applique le registre de corrections éditoriales puis reconstruit le site."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import enrichment, identity, site, source_facts, store  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Écrit le snapshot et le site après validation")
    args = parser.parse_args()

    items = store.load_items()
    facts = store.load_source_facts()
    facts, corrected_facts = source_facts.sanitize_source_facts(facts)
    snapshot = store.load_snapshot()
    report = enrichment.finalize_snapshot(
        items,
        facts,
        run_id="EDITORIAL-CORRECTION-20260909",
        as_of=str(snapshot.get("As_Of") or snapshot.get("as_of") or "2026-09-09"),
    )
    summary = {
        "corrected_source_facts": corrected_facts,
        "items": len(report.items),
        "incidents": len(report.incidents),
    }
    if args.write:
        store.save_source_facts(facts)
        store.save_items(report.items)
        store.save_incidents(report.incidents)
        store.save_incident_id_registry(report.incident_id_registry)
        store.save_sector_resolution(report.sector_resolution_rows)
        snapshot.update(
            Items_Count=len(report.items),
            Incidents_Count=len(report.incidents),
            Items_Hash=identity.items_hash(report.items),
            Incidents_Hash=identity.incidents_hash(report.incidents),
        )
        store.save_snapshot(snapshot)
        site.build()
        summary["written"] = True
    else:
        summary["written"] = False
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
