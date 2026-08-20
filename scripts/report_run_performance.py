#!/usr/bin/env python3
"""Rapport de performance et shadow validation de qualification.

L'observation reste post-qualification : elle ne court-circuite aucune règle
métier. Elle vérifie qu'un état déclaré stable reproduit exactement la même
sortie qualifiée et la même provenance d'un run au suivant.
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
SHADOW_CSV = store.DATA_DIR / "qualification_shadow_cache.csv"

QUALIFICATION_CODE_PATHS = tuple(
    ROOT / "cyberwatch" / name
    for name in (
        "qualification.py",
        "qualification_decision.py",
        "enrichment.py",
        "sector.py",
        "context_sector.py",
        "sector_registry.py",
        "sector_registry_safety.py",
        "source_llm_fallback.py",
        "sector_fallback_migration.py",
    )
)


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


def _qualification_dependency_digest() -> str:
    return incremental.dependency_digest(
        reference_rows=store.read_csv(store.ENRICHMENT_REFERENCE_CSV),
        org_cache_rows=store.load_org_enrichment_cache(),
        code_paths=QUALIFICATION_CODE_PATHS,
    )


def observe_incremental_state() -> int:
    run_log = store.load_run_log()
    if not run_log:
        print("INCREMENTAL_OBSERVER no_run=1")
        return 0

    last = run_log[-1]
    run_id = last.get("Run_ID", "")
    policy_version = last.get("Method_ID", "") or config.METHOD_ID
    dependency_digest_value = _qualification_dependency_digest()

    facts_by_item: dict[str, list[dict]] = defaultdict(list)
    for row in store.load_source_facts():
        if row.get("Item_ID"):
            facts_by_item[row["Item_ID"]].append(row)

    items = store.load_items()
    previous_state = store.read_csv(STATE_CSV)
    previous_shadow = store.read_csv(SHADOW_CSV)
    dirty_set = incremental.classify_items(
        items,
        incremental.fingerprints_from_state(previous_state),
        facts_by_item=facts_by_item,
        policy_version=policy_version,
        dependency_digest_value=dependency_digest_value,
    )

    current_shadow = incremental.shadow_cache_rows(
        items,
        dirty_set.fingerprints,
        store.load_qualification_provenance(),
        run_id=run_id,
        as_of=last.get("As_Of", ""),
    )
    shadow = incremental.compare_shadow_cache(
        previous_shadow,
        current_shadow,
        dirty_set.unchanged,
    )

    store.write_csv(
        STATE_CSV,
        incremental.PROCESSING_STATE_COLUMNS,
        incremental.state_rows(
            dirty_set,
            policy_version=policy_version,
            dependency_digest_value=dependency_digest_value,
            run_id=run_id,
            as_of=last.get("As_Of", ""),
        ),
    )
    store.write_csv(SHADOW_CSV, incremental.SHADOW_CACHE_COLUMNS, current_shadow)

    metrics = [r for r in store.read_csv(METRICS_CSV) if r.get("Run_ID") != run_id]
    metrics.append(
        incremental.metric_row(
            dirty_set,
            run_id=run_id,
            as_of=last.get("As_Of", ""),
            mode=last.get("Mode", ""),
            policy_version=policy_version,
            dependency_digest_value=dependency_digest_value,
            shadow=shadow,
        )
    )
    store.write_csv(METRICS_CSV, incremental.INCREMENTAL_METRIC_COLUMNS, metrics)

    print(
        f"INCREMENTAL_OBSERVER run={run_id} stage=post-qualification "
        f"new={len(dirty_set.new)} dirty={len(dirty_set.dirty)} "
        f"unchanged={len(dirty_set.unchanged)} stable={dirty_set.reuse_ratio:.1%} "
        f"shadow_checked={shadow.checked} shadow_mismatches={len(shadow.mismatches)}"
    )
    if shadow.mismatches:
        print("INCREMENTAL_SHADOW_MISMATCH items=" + ",".join(shadow.mismatches[:20]))
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
        observation = ""
        if metric:
            observation = (
                f" post_dirty={metric.get('Dirty_Items','0')} "
                f"post_stable={_number(metric.get('Reuse_Rate')):.1%} "
                f"shadow={metric.get('Shadow_Mismatches','0')}/{metric.get('Shadow_Checked','0')}"
            )
        print(
            f"{run_id} mode={run.get('Mode','')} total={format_duration(total)} "
            f"sources={format_duration(source_total)} "
            f"residual={format_duration(max(0, total-source_total))}{observation}"
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
