#!/usr/bin/env python3
"""Exporte les fusions faibles réellement appliquées par le moteur de dédup."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import incident_dedup
from cyberwatch.dedup_metrics import weak_merge_rows
from cyberwatch.model import Item


COLUMNS = [
    "Left_Item_ID",
    "Right_Item_ID",
    "Organisation",
    "Left_Source",
    "Right_Source",
    "Left_Date",
    "Right_Date",
    "Days_Apart",
    "Reason_Code",
    "Left_Event_Date",
    "Right_Event_Date",
    "Left_Threat",
    "Right_Threat",
    "Left_Title",
    "Right_Title",
    "Left_URL",
    "Right_URL",
]


def _load_items(path: Path) -> list[Item]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return [Item.from_row(row) for row in csv.DictReader(handle)]


def export(items_path: Path, output_path: Path, incident_registry_path: Path) -> int:
    incident_rows = []
    if incident_registry_path.exists():
        with incident_registry_path.open(encoding="utf-8", newline="") as handle:
            incident_rows = list(csv.DictReader(handle))
    rows = weak_merge_rows(
        _load_items(items_path),
        incident_dedup.decision_map(incident_rows),
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--items", default=str(ROOT / "data" / "items.csv"))
    parser.add_argument(
        "--output",
        default=str(ROOT / "data" / "dedup_weak_merges.csv"),
    )
    parser.add_argument(
        "--incident-registry",
        default=str(ROOT / "data" / "incident_dedup_registry.csv"),
    )
    args = parser.parse_args()
    total = export(
        Path(args.items),
        Path(args.output),
        Path(args.incident_registry),
    )
    print(f"dedup_weak_merges={total}")
    print(f"dedup_weak_merges_output={args.output}")


if __name__ == "__main__":
    main()
