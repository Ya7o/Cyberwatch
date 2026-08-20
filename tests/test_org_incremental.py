from pathlib import Path

from cyberwatch import org_incremental
from cyberwatch.model import Item


def _item(item_id, org_key, title="Incident"):
    return Item(
        Item_ID=item_id,
        Source_ID="SRC",
        Source_Item_ID=item_id,
        Published_Date="2026-08-20",
        Organisation_Raw=org_key,
        Organisation_Key=org_key,
        Threat_Raw="ransomware",
        Title=title,
        URL=f"https://example.test/{item_id}",
    )


def test_org_fingerprint_ignores_derived_outputs_but_tracks_real_inputs(tmp_path: Path):
    code = tmp_path / "sector.py"
    code.write_text("VERSION=1\n", encoding="utf-8")
    base_item = _item("I-1", "org-a")
    base = org_incremental.fingerprints(
        [base_item], [], [], [], policy_version="P1", code_paths=[code]
    )
    derived = _item("I-1", "org-a")
    derived.Sector = "Industrie"
    derived.Location = "France"
    derived.Threat = "Ransomware"
    same = org_incremental.fingerprints(
        [derived], [], [], [], policy_version="P1", code_paths=[code]
    )
    assert base == same

    changed = org_incremental.fingerprints(
        [_item("I-1", "org-a", title="Nouvelle preuve")],
        [], [], [], policy_version="P1", code_paths=[code]
    )
    assert base != changed


def test_org_classification_is_local_to_changed_organisation(tmp_path: Path):
    code = tmp_path / "sector.py"
    code.write_text("VERSION=1\n", encoding="utf-8")
    items = [_item("I-1", "org-a"), _item("I-2", "org-b")]
    previous = org_incremental.fingerprints(
        items, [], [], [], policy_version="P1", code_paths=[code]
    )
    current = org_incremental.fingerprints(
        [_item("I-1", "org-a", title="Changed"), _item("I-2", "org-b")],
        [], [], [], policy_version="P1", code_paths=[code]
    )
    new, dirty, unchanged = org_incremental.classify(current, previous)
    assert new == ()
    assert dirty == ("org-a",)
    assert unchanged == ("org-b",)


def test_org_metric_reports_reuse(tmp_path: Path):
    code = tmp_path / "sector.py"
    code.write_text("VERSION=1\n", encoding="utf-8")
    current = org_incremental.fingerprints(
        [_item("I-1", "org-a"), _item("I-2", "org-b")],
        [], [], [], policy_version="P1", code_paths=[code]
    )
    row = org_incremental.metric_row(
        current,
        dict(current),
        run_id="RUN-1",
        as_of="2026-08-20T08:00:00+04:00",
        mode="MAJ",
    )
    assert row["Dirty_Organisations"] == "0"
    assert row["Unchanged_Organisations"] == "2"
    assert row["Org_Reuse_Rate"] == "1.000000"
