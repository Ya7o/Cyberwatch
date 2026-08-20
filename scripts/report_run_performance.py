#!/usr/bin/env python3
"""Rapport de performance et observation incrémentale sans mutation métier."""
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
    return f"{int(seconds // 60)}m{int(round(seconds % 60)):02d}s"


def observe_incremental_state() -> int:
    run_log = store.load_run_log()
    if not run_log:
        print("INCREMENTAL_OBSERVER no_run=1")
        return 0

    last = run_log[-1]
    run_id = last.get("Run_ID", "")
    policy_version = last.get("Method_ID", "") or config.METHOD_ID

    facts_by_item: dict[str, list[dict]] = defaultdict(list)
    for row in store.load_source_facts():
        if row.get("Item_ID"):
            facts_by_item[row["Item_ID"]].append(row)

    dirty_set = incremental.classify_items(
        store.load_items(),
        incremental.fingerprints_from_state(store.read_csv(STATE_CSV)),
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
            as_of=last.get("As_Of", ""),
        ),
    )
    metrics = [r for r in store.read_csv(METRICS_CSV) if r.get("Run_ID") != run_id]
    metrics.append(
        incremental.metric_row(
            dirty_set,
            run_id=run_id,
            as_of=last.get("As_Of", ""),
            mode=last.get("Mode", ""),
            policy_version=policy_version,
        )
    )
    store.write_csv(METRICS_CSV, incremental.INCREMENTAL_METRIC_COLUMNS, metrics)
    print(
        f"INCREMENTAL_OBSERVER run={run_id} "
        f"new={len(dirty_set.new)} dirty={len(dirty_set.dirty)} "
        f"unchanged={len(dirty_set.unchanged)} reuse={dirty_set.reuse_ratio:.1%}"
    )
    return 0


def report(last_count: int) -> int:
    logs = store.load_run_log()
    if not logs:
        print("RUN_PERF no_runs=1")
        return 0
    source_rows: dict[str, list[dict]] = defaultdict(list)
    for row in store.load_run_sources():
        source_rows[row.get("Run_ID", "")].append(row)
    metrics = {r.get("Run_ID", ""): r for r in store.read_csv(METRICS_CSV)}
    for run in logs[-max(1, last_count):]:
        run_id = run.get("Run_ID", "")
        total = _number(run.get("Duration_s"))
        sources = source_rows.get(run_id, [])
        source_total = sum(_number(r.get("Duration_s")) for r in sources)
        metric = metrics.get(run_id, {})
        reuse = ""
        if metric:
            reuse = (
                f" dirty={metric.get('Dirty_Items','0')} "
                f"unchanged={metric.get('Unchanged_Items','0')} "
                f"reuse={_number(metric.get('Reuse_Rate')):.1%}"
            )
        print(
            f"{run_id} mode={run.get('Mode','')} total={format_duration(total)} "
            f"sources={format_duration(source_total)} "
            f"residual={format_duration(max(0, total-source_total))}{reuse}"
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--last", type=int, default=5)
    parser.add_argument("--observe", action="store_true")
    args = parser.parse_args(argv)
    return observe_incremental_state() if args.observe else report(args.last)


if __name__ == "__main__":
    raise SystemExit(main())
