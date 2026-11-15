from pathlib import Path

import pytest

from cyberwatch import dedup, incident_dedup, store


def _row(left="ITM-A", right="ITM-B", decision="SAME", **overrides):
    row = {
        "Pair_Key": incident_dedup.pair_key(left, right),
        "Left_Item_ID": left,
        "Right_Item_ID": right,
        "Decision": decision,
        "Confidence": "0.95",
    }
    row.update(overrides)
    return row


def test_pair_key_is_symmetric():
    assert incident_dedup.pair_key("ITM-B", "ITM-A") == "ITM-A|ITM-B"


def test_merge_rows_replaces_pair_and_preserves_first_seen():
    existing = [_row(First_Seen="2026-08-01", Last_Validated="2026-08-01")]
    proposal = _row(
        decision="DIFFERENT",
        First_Seen="2026-08-28",
        Last_Validated="2026-08-28",
    )

    rows, problems = incident_dedup.merge_rows(
        existing, [proposal], current_item_ids={"ITM-A", "ITM-B"}
    )

    assert problems == []
    assert rows[0]["Decision"] == "DIFFERENT"
    assert rows[0]["First_Seen"] == "2026-08-01"


def test_merge_rows_is_idempotent_for_same_cached_verdict():
    existing = [_row(First_Seen="2026-08-01", Last_Validated="2026-08-01")]
    repeated = _row(First_Seen="2026-08-28", Last_Validated="2026-08-28")

    rows, problems = incident_dedup.merge_rows(
        existing, [repeated], current_item_ids={"ITM-A", "ITM-B"}
    )

    assert problems == []
    assert rows[0]["First_Seen"] == "2026-08-01"
    assert rows[0]["Last_Validated"] == "2026-08-01"


def test_manual_audit_verdict_survives_stale_llm_proposal():
    existing = [_row(decision="DIFFERENT", Model="manual-audit",
                     Reason="Current source records describe separate events.")]
    stale = _row(decision="SAME", Model="gpt-5-mini")

    rows, problems = incident_dedup.merge_rows(existing, [stale])

    assert problems == []
    assert rows[0]["Decision"] == "DIFFERENT"
    assert rows[0]["Model"] == "manual-audit"


def test_merge_rows_prunes_orphaned_pairs():
    rows, problems = incident_dedup.merge_rows(
        [_row()], [], current_item_ids={"ITM-A"}
    )
    assert problems == []
    assert rows == []


def test_invalid_pair_is_rejected():
    rows, problems = incident_dedup.merge_rows(
        [_row(Pair_Key="wrong")], [], current_item_ids={"ITM-A", "ITM-B"}
    )
    assert rows == []
    assert problems


def test_validate_registry_reports_orphaned_item():
    problems = incident_dedup.validate_registry([_row()], {"ITM-A"})
    assert any("ITM-B" in problem for problem in problems)


def test_audited_corpus_groups_centre_val_de_loire_but_separates_maileva():
    if not (Path(__file__).resolve().parents[1] / "data" / "items.csv").exists():
        pytest.skip("corpus absent (base purgée)")
    items = store.load_items()
    by_id = {item.Item_ID: item for item in items}
    centre = ("ITM-a2ad91531bbc93f5", "ITM-a9b3731f84e8fcb3")
    maileva = ("ITM-8bc0bc42e5b16fca", "ITM-8d83a6975038d2a2")
    if not all(item_id in by_id for item_id in (*centre, *maileva)):
        pytest.skip("dossiers d'audit absents du corpus")
    decisions = incident_dedup.decision_map(store.load_incident_dedup_registry())
    grouped = {
        item.Item_ID: index
        for index, component in enumerate(dedup.group_components(items, decisions))
        for item in component
    }

    assert grouped[centre[0]] == grouped[centre[1]]
    assert decisions[incident_dedup.pair_key(*maileva)] == incident_dedup.DIFFERENT
    assert grouped[maileva[0]] != grouped[maileva[1]]
