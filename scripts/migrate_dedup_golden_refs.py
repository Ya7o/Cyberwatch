#!/usr/bin/env python3
"""Migre le golden dédup vers des références source stables.

La commande est locale et déterministe. Elle enrichit chaque paire avec les
Source_ID / Source_Item_ID / URL nécessaires pour retrouver l'item courant même
si son Item_ID interne est régénéré.
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store
from cyberwatch.dedup_golden_refs import STABLE_REF_COLUMNS, enrich_golden_row

BASE_COLUMNS = [
    "Case_ID",
    "Left_Item_ID",
    "Right_Item_ID",
    *STABLE_REF_COLUMNS[:3],
    *STABLE_REF_COLUMNS[3:],
    "Same_Organisation_REF",
    "Same_Incident_REF",
    "Evidence",
    "Reviewed_At",
    "Golden_Version",
]


def migrate(path: Path, output: Path) -> int:
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    items_by_id = {item.Item_ID: item for item in store.load_items()}
    migrated = [enrich_golden_row(row, items_by_id) for row in rows]

    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=BASE_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(migrated)
    return len(migrated)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--golden",
        default=str(ROOT / "data" / "golden" / "dedup_golden.csv"),
    )
    parser.add_argument("--output", default="")
    args = parser.parse_args()
    source = Path(args.golden)
    output = Path(args.output) if args.output else source
    count = migrate(source, output)
    print(f"DEDUP_GOLDEN_MIGRATED={count} output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
