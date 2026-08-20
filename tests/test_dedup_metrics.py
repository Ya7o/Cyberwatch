from cyberwatch.dedup_metrics import summarize_dedup, weak_merge_rows


def test_summary_buckets_weak_merges_by_day(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-03", url="https://b"),
    ]

    summary = summarize_dedup(items)

    assert summary["items"] == 2
    assert summary["incidents"] == 1
    assert summary["merged_items"] == 1
    assert summary["merge_reasons"] == {"INCIDENT_MERGE_CANONICAL_NAME_J2": 1}


def test_summary_counts_conflicting_event_date_veto(make_item):
    items = [
        make_item(
            source="A",
            org="Globex",
            event="2026-08-01",
            published="2026-08-02",
            url="https://a",
        ),
        make_item(
            source="B",
            org="Globex",
            event="2026-08-02",
            published="2026-08-02",
            url="https://b",
        ),
    ]

    summary = summarize_dedup(items)

    assert summary["incidents"] == 2
    assert summary["strong_veto_reasons"] == {
        "INCIDENT_KEEP_CONFLICTING_EVENT_DATE": 1,
    }


def test_weak_merge_export_contains_event_context(make_item):
    items = [
        make_item(
            source="A",
            org="Globex",
            event="2026-08-01",
            published="2026-08-02",
            threat="Ransomware",
            title="Globex attaqué",
            url="https://a",
        ),
        make_item(
            source="B",
            org="Globex",
            event="2026-08-01",
            published="2026-08-03",
            threat="Intrusion",
            title="Incident chez Globex",
            url="https://b",
        ),
    ]

    # Une Event_Date commune est un merge fort et ne doit pas polluer l'audit faible.
    assert weak_merge_rows(items) == []

    weak_items = [
        make_item(source="A", org="Initech", published="2026-08-01", url="https://c"),
        make_item(source="B", org="Initech", published="2026-08-02", url="https://d"),
    ]
    rows = weak_merge_rows(weak_items)

    assert len(rows) == 1
    assert rows[0]["Days_Apart"] == "1"
    assert rows[0]["Reason_Code"] == "INCIDENT_MERGE_CANONICAL_NAME"
    assert rows[0]["Left_Source"] == "A"
    assert rows[0]["Right_Source"] == "B"
