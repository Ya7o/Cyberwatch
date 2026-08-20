import csv
import json

from cyberwatch.dedup_metrics import (
    append_run_history,
    candidate_pair_count,
    review_queue_rows,
    summarize_dedup,
    weak_merge_rows,
)


def test_summary_buckets_weak_merges_by_day(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-03", url="https://b"),
    ]
    summary = summarize_dedup(items)
    assert summary["items"] == 2
    assert summary["incidents"] == 1
    assert summary["merged_items"] == 1
    assert summary["candidate_pairs"] == 1
    assert summary["merge_reasons"] == {"INCIDENT_MERGE_CANONICAL_NAME_J2": 1}
    assert summary["decision_reasons"] == {"INCIDENT_MERGE_CANONICAL_NAME_J2": 1}


def test_candidate_pair_count_ignores_different_organisations(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-02", url="https://b"),
        make_item(source="C", org="Initech", published="2026-08-02", url="https://c"),
    ]
    assert candidate_pair_count(items) == 1


def test_summary_counts_conflicting_event_date_veto(make_item):
    items = [
        make_item(source="A", org="Globex", event="2026-08-01", published="2026-08-02", url="https://a"),
        make_item(source="B", org="Globex", event="2026-08-02", published="2026-08-02", url="https://b"),
    ]
    summary = summarize_dedup(items)
    assert summary["incidents"] == 2
    assert summary["strong_veto_reasons"] == {"INCIDENT_KEEP_CONFLICTING_EVENT_DATE": 1}


def test_weak_merge_export_contains_event_context(make_item):
    items = [
        make_item(source="A", org="Globex", event="2026-08-01", published="2026-08-02", threat="Ransomware", title="Globex attaqué", url="https://a"),
        make_item(source="B", org="Globex", event="2026-08-01", published="2026-08-03", threat="Intrusion", title="Incident chez Globex", url="https://b"),
    ]
    assert weak_merge_rows(items) == []

    weak_items = [
        make_item(source="A", org="Initech", published="2026-08-01", url="https://c"),
        make_item(source="B", org="Initech", published="2026-08-02", url="https://d"),
    ]
    rows = weak_merge_rows(weak_items)
    assert len(rows) == 1
    assert rows[0]["Days_Apart"] == "1"
    assert rows[0]["Reason_Code"] == "INCIDENT_MERGE_CANONICAL_NAME"


def test_review_queue_prioritizes_false_merges(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-03", url="https://b"),
    ]
    rows = review_queue_rows(items)
    assert rows
    assert rows[0]["Risk_Type"] == "POSSIBLE_FALSE_MERGE"
    assert int(rows[0]["Risk_Priority"]) >= 90


def test_run_history_is_append_only_and_json_structured(tmp_path, make_item):
    summary = summarize_dedup([
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-02", url="https://b"),
    ])
    path = tmp_path / "dedup_runs.csv"
    for index in range(2):
        append_run_history(
            path,
            run_at=f"2026-08-20T00:00:0{index}+00:00",
            summary=summary,
            runtime_seconds=1.25,
            incidents_hash="abc",
            possible_false_merges=1,
            possible_missed_duplicates=2,
        )
    with path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert len(rows) == 2
    assert rows[0]["Candidate_Pairs"] == "1"
    assert json.loads(rows[0]["Merge_Reasons_JSON"]) == {"INCIDENT_MERGE_CANONICAL_NAME_J1": 1}
