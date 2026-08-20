from cyberwatch.incremental import (
    classify_items,
    fingerprints_from_state,
    metric_row,
    qualification_fingerprint,
    state_rows,
)
from cyberwatch.model import Item


def _item(**changes):
    values = dict(
        Item_ID="I-1",
        Source_ID="SRC",
        Source_Item_ID="42",
        Published_Date="2026-08-20",
        Event_Date="2026-08-19",
        Organisation_Raw="Example SA",
        Organisation_Key="example-sa",
        Threat_Raw="ransomware",
        Threat="Ransomware",
        Sector="Inconnu",
        Location="France",
        Title="Example SA victime d'un ransomware",
        URL="https://example.test/incident",
        Collected_As_Of="2026-08-20T07:00:00+04:00",
    )
    values.update(changes)
    return Item(**values)


def test_collected_as_of_does_not_invalidate_fingerprint():
    left = qualification_fingerprint(_item(), policy_version="P1")
    right = qualification_fingerprint(
        _item(Collected_As_Of="2026-08-21T07:00:00+04:00"), policy_version="P1"
    )
    assert left == right


def test_business_input_and_policy_changes_invalidate_fingerprint():
    item = _item()
    base = qualification_fingerprint(item, policy_version="P1")
    assert base != qualification_fingerprint(
        _item(Title="Example SA confirme une cyberattaque"), policy_version="P1"
    )
    assert base != qualification_fingerprint(item, policy_version="P2")


def test_source_fact_order_is_irrelevant_but_content_change_is_not():
    item = _item()
    facts = [
        {"Item_ID": item.Item_ID, "Activity_Description": "éditeur logiciel"},
        {"Item_ID": item.Item_ID, "Source_Sector_Raw": "Technology"},
    ]
    changed = [dict(facts[0]), dict(facts[1])]
    changed[0]["Activity_Description"] = "hôpital public"
    first = qualification_fingerprint(item, facts, policy_version="P1")
    assert first == qualification_fingerprint(item, reversed(facts), policy_version="P1")
    assert first != qualification_fingerprint(item, changed, policy_version="P1")


def test_classify_and_state_round_trip():
    unchanged = _item(Item_ID="I-1")
    dirty = _item(Item_ID="I-2", Title="ancienne valeur")
    new = _item(Item_ID="I-3")
    previous = {
        "I-1": qualification_fingerprint(unchanged, policy_version="P1"),
        "I-2": qualification_fingerprint(dirty, policy_version="P1"),
    }
    dirty.Title = "nouvelle valeur"
    result = classify_items([new, dirty, unchanged], previous, policy_version="P1")
    assert result.new == ("I-3",)
    assert result.dirty == ("I-2",)
    assert result.unchanged == ("I-1",)
    rows = state_rows(
        result, policy_version="P1", run_id="RUN-1", as_of="2026-08-20T08:00:00+04:00"
    )
    assert fingerprints_from_state(rows) == result.fingerprints


def test_metric_row_reports_reuse():
    item = _item()
    previous = {"I-1": qualification_fingerprint(item, policy_version="P1")}
    result = classify_items([item], previous, policy_version="P1")
    row = metric_row(
        result,
        run_id="RUN-2",
        as_of="2026-08-20T09:00:00+04:00",
        mode="MAJ",
        policy_version="P1",
    )
    assert row["Dirty_Items"] == "0"
    assert row["Unchanged_Items"] == "1"
    assert row["Reuse_Rate"] == "1.000000"
