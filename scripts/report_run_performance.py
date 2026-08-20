#!/usr/bin/env python3
"""Rapport lisible des performances et observation incrémentale des runs.

Par défaut le rapport exploite les métriques déjà persistées sans relancer de
collecte. Avec ``--observe``, il calcule après un run réussi le dirty-set du
snapshot courant et persiste uniquement deux jeux auxiliaires de mesure. Aucune
décision métier, aucun item et aucun incident n'est modifié.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import config, incremental, store

STATE_CSV = store.DATA_DIR / "item_processing_state.csv"
METRICS_CSV = store.DATA_DIR / "incremental_metrics.csv"


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


def observe_incremental_state() -> int:
    """Mesure NEW/DIRTY/UNCHANGED sur le snapshot publié, sans court-circuit."""
    run_log = store.load_run_log()
    if not run_log:
        print("INCREMENTAL_OBSERVER no_run=1")
        return 0

    last = run_log[-1]
    run_id = last.get("Run_ID", "")
    as_of = last.get("As_Of", "")
    mode = last.get("Mode", "")
    policy_version = last.get("Method_ID", "") or config.METHOD_ID

    items = store.load_items()
    facts_by_item: dict[str, list[dict]] = defaultdict(list)
    for row in store.load_source_facts():
        item_id = row.get("Item_ID", "")
        if item_id:
            facts_by_item[item_id].append(row)

    previous = incremental.fingerprints_from_state(store.read_csv(STATE_CSV))
    dirty_set = incremental.classify_items(
        items,
        previous,
        facts_by_item=facts_by_item,
        policy_version=policy_version,
    )

    store.write_csv(
        STATE_CSV,
        incremental.PROCESSING_STATE_COLUMNS,
        incremental.state_rows(
            dirty_set,
            policy_version=policy_version,
            run_id=run_id,
            as_of=as_of,
        ),
    )

    metrics = [
        row for row in store.read_csv(METRICS_CSV)
        if row.get("Run_ID") != run_id
    ]
    metrics.append(
        incremental.metric_row(
            dirty_set,
            run_id=run_id,
            as_of=as_of,
            mode=mode,
            policy_version=policy_version,
        )
    )
    store.write_csv(
        METRICS_CSV,
        incremental.INCREMENTAL_METRIC_COLUMNS,
        metrics,
    )

    print(
        "INCREMENTAL_OBSERVER "
        f"run={run_id} items={len(items)} "
        f"new={len(dirty_set.new)} dirty={len(dirty_set.dirty)} "
        f"unchanged={len(dirty_set.unchanged)} "
        f"reuse={dirty_set.reuse_ratio:.1%}"
    )
    return 0


def report(last_count: int) -> int:
    logs = store.load_run_log()
    if not logs:
        print("RUN_PERF no_runs=1")
        return 0

    grouped = _source_rows_by_run()
    incremental_metrics = {
        row.get("Run_ID", ""): row
        for row in store.read_csv(METRICS_CSV)
        if row.get("Run_ID")
    }
    selected = logs[-max(1, last_count):]
    print(f"RUN_PERF runs={len(selected)}")

    for run in selected:
        run_id = run.get("Run_ID", "")
        total = _number(run.get("Duration_s"))
        sources = grouped.get(run_id, [])
        source_total = sum(_number(row.get("Duration_s")) for row in sources)
        residual = max(0.0, total - source_total)
        new_items = int(_number(run.get("New_Items")))
        new_incidents = int(_number(run.get("New_Incidents")))
        metric = incremental_metrics.get(run_id, {})
        reuse = ""
        if metric:
            reuse = (
                f" dirty={metric.get('Dirty_Items','0')} "
                f"unchanged={metric.get('Unchanged_Items','0')} "
                f"reuse={_number(metric.get('Reuse_Rate')):.1%}"
            )
        print(
            f"{run_id} mode={run.get('Mode','')} total={format_duration(total)} "
            f"sources={format_duration(source_total)} residual={format_duration(residual)} "
            f"new_items={new_items} new_incidents={new_incidents} "
            f"requests={int(_number(run.get('Requests')))}{reuse}"
        )
        for row in sorted(
            sources,
            key=lambda item: _number(item.get("Duration_s")),
            reverse=True,
        ):
            print(
                f"  {row.get('Source_ID',''):24} "
                f"total={format_duration(row.get('Duration_s')):>7} "
                f"collect={format_duration(row.get('Collect_Duration_s')):>7} "
                f"process={format_duration(row.get('Processing_Duration_s')):>7} "
                f"items={int(_number(row.get('Items_collected'))):4} "
                f"new={int(_number(row.get('New_items'))):3}"
            )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--last", type=int, default=5, help="Nombre de runs à afficher.")
    parser.add_argument(
        "--observe",
        action="store_true",
        help="Persister l'état et les métriques incrémentales du dernier run.",
    )
    args = parser.parse_args(argv)
    if args.observe:
        return observe_incremental_state()
    return report(args.last)


if __name__ == "__main__":
    raise SystemExit(main())
