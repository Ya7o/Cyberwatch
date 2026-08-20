import csv
from pathlib import Path

from cyberwatch import store
from cyberwatch.dedup_golden_refs import (
    LEFT_STABLE_REF_COLUMNS,
    RESOLVED,
    RIGHT_STABLE_REF_COLUMNS,
    has_stable_refs,
    resolve_golden_side,
)

GOLDEN = Path("data/golden/dedup_golden.csv")
REQUIRED_COLUMNS = {
    "Case_ID",
    "Left_Item_ID",
    "Right_Item_ID",
    *LEFT_STABLE_REF_COLUMNS,
    *RIGHT_STABLE_REF_COLUMNS,
    "Same_Organisation_REF",
    "Same_Incident_REF",
    "Evidence",
    "Reviewed_At",
    "Golden_Version",
}


def _rows():
    with GOLDEN.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def test_dedup_golden_references_only_existing_items():
    existing = {item.Item_ID for item in store.load_items()}
    missing = {
        row["Case_ID"]: sorted(
            item_id for item_id in (row["Left_Item_ID"], row["Right_Item_ID"])
            if item_id not in existing
        )
        for row in _rows()
        if row["Left_Item_ID"] not in existing or row["Right_Item_ID"] not in existing
    }
    assert missing == {}


def test_dedup_golden_rows_are_structurally_complete():
    rows = _rows()
    assert rows
    assert set(rows[0]) == REQUIRED_COLUMNS
    assert len({row["Case_ID"] for row in rows}) == len(rows)
    assert all(row["Evidence"].strip() and row["Reviewed_At"].strip() for row in rows)
    assert all(row["Left_Item_ID"] != row["Right_Item_ID"] for row in rows)
    assert all(has_stable_refs(row) for row in rows)


def test_all_materialized_stable_refs_resolve_deterministically():
    items = store.load_items()
    for row in _rows():
        assert resolve_golden_side(row, "Left", items).status == RESOLVED, row["Case_ID"]
        assert resolve_golden_side(row, "Right", items).status == RESOLVED, row["Case_ID"]
