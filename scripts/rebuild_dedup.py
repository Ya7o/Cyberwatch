"""Reconstruction déterministe de la base après évolution des alias."""

from __future__ import annotations

import csv
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import identity, incident_dedup, store
from cyberwatch.dedup import build_incidents_with_registry
from cyberwatch.dedup_metrics import (
    append_run_history,
    summarize_dedup,
    write_review_queue_csv,
    write_weak_merges_csv,
)
from cyberwatch.normalize import organisation_key
from cyberwatch.site import incidents_payload


def _canonical_content(item) -> dict[str, str]:
    row = item.to_row()
    row.pop("Item_ID", None)
    row.pop("Collected_As_Of", None)
    return row


def main() -> int:
    started = perf_counter()
    run_at = datetime.now(timezone.utc).isoformat()
    items = store.load_items()
    before_incidents = store.load_incidents()
    before_hash = identity.incidents_hash(before_incidents)

    changed_keys = 0
    changed_item_ids = 0
    by_new_id = defaultdict(list)

    for item in items:
        old_id = item.Item_ID
        old_key = item.Organisation_Key
        new_key = organisation_key(item.Organisation_Raw)
        if new_key != old_key:
            item.Organisation_Key = new_key
            changed_keys += 1

        new_item_id = identity.item_id(
            item.Source_ID,
            item.Published_Date,
            item.Organisation_Key,
            item.URL,
            item.Source_Item_ID,
        )
        if new_item_id != old_id:
            changed_item_ids += 1
        by_new_id[new_item_id].append((old_id, item))

    rebuilt_items = []
    collapsed_items = 0
    for new_item_id in sorted(by_new_id):
        members = sorted(by_new_id[new_item_id], key=lambda pair: pair[0])
        if len(members) > 1:
            reference = _canonical_content(members[0][1])
            if any(_canonical_content(item) != reference for _, item in members[1:]):
                print("REBUILD_DEDUP_ABORT non-identical Item_ID collision " + new_item_id)
                for old_id, item in members:
                    print("COLLISION_ROW " + json.dumps(
                        {"old_id": old_id, **item.to_row()},
                        sort_keys=True,
                        ensure_ascii=False,
                    ))
                return 1
            collapsed_items += len(members) - 1

        chosen = members[0][1]
        chosen.Item_ID = new_item_id
        collected = sorted(item.Collected_As_Of for _, item in members if item.Collected_As_Of)
        chosen.Collected_As_Of = collected[0] if collected else ""
        rebuilt_items.append(chosen)

    items = identity.sort_items(rebuilt_items)
    incident_rows, incident_registry_problems = incident_dedup.merge_rows(
        store.load_incident_dedup_registry(),
        (),
        current_item_ids={item.Item_ID for item in items if item.Item_ID},
    )
    if incident_registry_problems:
        print("REBUILD_DEDUP_ABORT invalid incident dedup registry")
        for problem in incident_registry_problems:
            print("REGISTRY_PROBLEM " + problem)
        return 1
    incident_decisions = incident_dedup.decision_map(incident_rows)
    incidents, incident_id_rows = build_incidents_with_registry(
        items,
        store.load_incident_id_registry(),
        incident_rows,
    )
    after_hash = identity.incidents_hash(incidents)
    dedup_summary = summarize_dedup(items, incident_decisions)

    audit_dir = store.DATA_DIR / "audit"
    weak_merge_path = audit_dir / "dedup_weak_merges.csv"
    review_queue_path = audit_dir / "dedup_review_queue.csv"
    run_history_path = audit_dir / "dedup_runs.csv"
    weak_merge_count = write_weak_merges_csv(
        weak_merge_path, items, incident_decisions,
    )
    review_queue_count = write_review_queue_csv(review_queue_path, items)
    with review_queue_path.open(encoding="utf-8", newline="") as handle:
        review_rows = list(csv.DictReader(handle))
    possible_false_merges = sum(row["Risk_Type"] == "POSSIBLE_FALSE_MERGE" for row in review_rows)
    possible_missed_duplicates = sum(row["Risk_Type"] == "POSSIBLE_MISSED_DUPLICATE" for row in review_rows)

    store.save_items(items)
    store.save_incidents(incidents)
    store.save_incident_id_registry(incident_id_rows)
    store.save_incident_dedup_registry(incident_rows)
    store.write_json(store.SITE_DATA_DIR / "incidents.json", incidents_payload(incidents))

    runtime_seconds = perf_counter() - started
    append_run_history(
        run_history_path,
        run_at=run_at,
        summary=dedup_summary,
        runtime_seconds=runtime_seconds,
        incidents_hash=after_hash,
        possible_false_merges=possible_false_merges,
        possible_missed_duplicates=possible_missed_duplicates,
    )

    audit = {
        "items_before": sum(len(rows) for rows in by_new_id.values()),
        "items_after": len(items),
        "items_collapsed_exact_duplicates": collapsed_items,
        "incidents_before": len(before_incidents),
        "incidents_after": len(incidents),
        "incident_delta": len(incidents) - len(before_incidents),
        "organisation_keys_changed": changed_keys,
        "item_ids_changed": changed_item_ids,
        "incidents_hash_before": before_hash,
        "incidents_hash_after": after_hash,
        "runtime_seconds": round(runtime_seconds, 6),
        "dedup": dedup_summary,
        "weak_merges": weak_merge_count,
        "possible_false_merges": possible_false_merges,
        "possible_missed_duplicates": possible_missed_duplicates,
        "weak_merges_output": str(weak_merge_path.relative_to(ROOT)),
        "review_queue_output": str(review_queue_path.relative_to(ROOT)),
        "run_history_output": str(run_history_path.relative_to(ROOT)),
        "review_queue_rows": review_queue_count,
    }
    print("REBUILD_DEDUP_AUDIT " + json.dumps(audit, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
