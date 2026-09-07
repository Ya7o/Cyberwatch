"""Recalcule secteur, menace et localisation hors réseau ; simulation par défaut."""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cyberwatch import enrichment, identity, store  # noqa: E402

ITEM_FIELDS = ("Sector", "Threat", "Location")
INCIDENT_FIELDS = ("Secteur", "Menace", "Localisation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    items = store.load_items()
    incidents = store.load_incidents()
    as_of = dt.datetime.now(dt.UTC).isoformat()
    result = enrichment.finalize_snapshot(
        copy.deepcopy(items), store.load_source_facts(),
        run_id="QUALIFICATION-REPAIR-20260907", as_of=as_of,
        previous_sector_rows=store.load_sector_resolution(),
    )
    before_items = {item.Item_ID: item for item in items}
    before_incidents = {incident.Incident_ID: incident for incident in incidents}
    if set(before_items) != {item.Item_ID for item in result.items}:
        raise ValueError("La reprise a modifié les identifiants d'items.")
    if set(before_incidents) != {incident.Incident_ID for incident in result.incidents}:
        raise ValueError("La reprise a modifié les identifiants d'incidents.")
    for current in result.items:
        previous = before_items[current.Item_ID]
        if {key: value for key, value in previous.to_row().items() if key not in ITEM_FIELDS} != {
            key: value for key, value in current.to_row().items() if key not in ITEM_FIELDS
        }:
            raise ValueError(f"Champ d'item hors qualification modifié : {current.Item_ID}")
    for current in result.incidents:
        previous = before_incidents[current.Incident_ID]
        if {key: value for key, value in previous.to_row().items() if key not in INCIDENT_FIELDS} != {
            key: value for key, value in current.to_row().items() if key not in INCIDENT_FIELDS
        }:
            raise ValueError(f"Champ d'incident hors qualification modifié : {current.Incident_ID}")

    item_changes = []
    for current in result.items:
        previous = before_items[current.Item_ID]
        changed = {field: {"before": getattr(previous, field), "after": getattr(current, field)}
                   for field in ITEM_FIELDS if getattr(previous, field) != getattr(current, field)}
        if changed:
            item_changes.append({"id": current.Item_ID, "name": current.Organisation_Raw,
                                 "fields": changed})
    incident_changes = []
    for current in result.incidents:
        previous = before_incidents[current.Incident_ID]
        changed = {field: {"before": getattr(previous, field), "after": getattr(current, field)}
                   for field in INCIDENT_FIELDS if getattr(previous, field) != getattr(current, field)}
        if changed:
            incident_changes.append({"id": current.Incident_ID, "name": current.Organisation,
                                     "fields": changed})
    report = {
        "as_of": as_of,
        "written": bool(args.write),
        "items": len(result.items),
        "incidents": len(result.incidents),
        "item_changes": item_changes,
        "incident_changes": incident_changes,
    }
    if args.write:
        store.save_items(result.items)
        store.save_incidents(result.incidents)
        if any("Sector" in row["fields"] for row in item_changes):
            store.save_sector_resolution(result.sector_resolution_rows)
        snapshot = store.load_snapshot()
        snapshot.update(
            Items_Hash=identity.items_hash(result.items),
            Incidents_Hash=identity.incidents_hash(result.incidents),
        )
        store.save_snapshot(snapshot)
        store.write_json(store.DATA_DIR / "qualification_repair_report.json", report)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
