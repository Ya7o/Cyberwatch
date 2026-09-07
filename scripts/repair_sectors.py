"""Reprise sectorielle ciblée : simulation par défaut, --write pour appliquer."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import enrichment, identity, sector_repair, store  # noqa: E402
from cyberwatch.model import ITEM_COLUMNS, INCIDENT_COLUMNS, SOURCE_FACT_COLUMNS, SECTOR_RESOLUTION_COLUMNS, Item, Incident  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data")
    parser.add_argument("--output-dir", type=Path, help="Écrire une copie dans ce dossier")
    parser.add_argument("--write", action="store_true", help="Appliquer à data-dir après validation")
    args = parser.parse_args()
    directory = args.data_dir.resolve()
    items = [Item.from_row(r) for r in store.read_csv(directory / "items.csv")]
    incidents = [Incident.from_row(r) for r in store.read_csv(directory / "incidents.csv")]
    facts = store.read_csv(directory / "source_facts.csv")
    cache = json.loads((directory / "source_facts_ai_cache.json").read_text(encoding="utf-8"))
    decisions, report = sector_repair.repair_snapshot(
        items, incidents, facts, cache, enrichment.load_reference(),
        store.read_csv(directory / "sector_resolution.csv"),
    )
    destination = args.output_dir.resolve() if args.output_dir else directory if args.write else None
    if destination:
        destination.mkdir(parents=True, exist_ok=True)
        store.write_csv(destination / "items.csv", ITEM_COLUMNS, [i.to_row() for i in items])
        store.write_csv(destination / "incidents.csv", INCIDENT_COLUMNS, [i.to_row() for i in incidents])
        store.write_csv(destination / "source_facts.csv", SOURCE_FACT_COLUMNS, facts)
        store.write_csv(destination / "sector_resolution.csv", SECTOR_RESOLUTION_COLUMNS, decisions)
        store.write_json(destination / "source_facts_ai_cache.json", cache)
        snapshot_path = directory / "snapshot.json"
        if snapshot_path.exists():
            snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
            snapshot.update(Items_Hash=identity.items_hash(items), Incidents_Hash=identity.incidents_hash(incidents))
            store.write_json(destination / "snapshot.json", snapshot)
        store.write_json(destination / "sector_repair_report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
