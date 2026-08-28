from cyberwatch import incident_dedup


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
