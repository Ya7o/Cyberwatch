#!/usr/bin/env python3
"""Rapport lisible des performances des derniers runs Cyberwatch.

Le rapport exploite les métriques déjà persistées sans relancer de collecte.
Il sépare le temps cumulé des sources du résiduel global afin d'identifier les
runs où le coût se situe hors collecte (qualification, dédup, écritures, etc.).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store


def _number(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def format_duration(value) -> str:
    seconds = max(0.0, _number(value))
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    remainder = int(round(seconds % 60))
    if remainder == 60:
        minutes += 1
        remainder = 0
    return f"{minutes}m{remainder:02d}s"


def _source_rows_by_run() -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in store.load_run_sources():
        run_id = row.get("Run_ID", "")
        if run_id:
            grouped.setdefault(run_id, []).append(row)
    return grouped


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--last", type=int, default=5, help="Nombre de runs à afficher.")
    args = parser.parse_args(argv)

    logs = store.load_run_log()
    if not logs:
        print("RUN_PERF no_runs=1")
        return 0

    grouped = _source_rows_by_run()
    selected = logs[-max(1, args.last):]
    print(f"RUN_PERF runs={len(selected)}")

    for run in selected:
        run_id = run.get("Run_ID", "")
        total = _number(run.get("Duration_s"))
        sources = grouped.get(run_id, [])
        source_total = sum(_number(row.get("Duration_s")) for row in sources)
        residual = max(0.0, total - source_total)
        new_items = int(_number(run.get("New_Items")))
        new_incidents = int(_number(run.get("New_Incidents")))
        print(
            f"{run_id} mode={run.get('Mode','')} total={format_duration(total)} "
            f"sources={format_duration(source_total)} residual={format_duration(residual)} "
            f"new_items={new_items} new_incidents={new_incidents} "
            f"requests={int(_number(run.get('Requests')))}"
        )
        for row in sorted(sources, key=lambda item: _number(item.get("Duration_s")), reverse=True):
            print(
                f"  {row.get('Source_ID',''):24} total={format_duration(row.get('Duration_s')):>7} "
                f"collect={format_duration(row.get('Collect_Duration_s')):>7} "
                f"process={format_duration(row.get('Processing_Duration_s')):>7} "
                f"items={int(_number(row.get('Items_collected'))):4} "
                f"new={int(_number(row.get('New_items'))):3}"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
