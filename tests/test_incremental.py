from pathlib import Path

from cyberwatch.incremental import (
    PREQUAL_FINGERPRINT_VERSION,
    SHADOW_CACHE_VERSION,
    classify_items,
    classify_prequalification_items,
    compare_shadow_cache,
    dependency_digest,
    fingerprints_from_state,
    metric_row,
    prequalification_fingerprint,
    prequalification_state_rows,
    qualification_fingerprint,
    shadow_cache_rows,
    state_rows,
)
from cyberwatch.model import Item


def _item(**changes):
    values = dict(
        Item_ID="I-1", Source_ID="SRC", Source_Item_ID="42",
        Published_Date="2026-08-20", Event_Date="2026-08-19",
        Organisation_Raw="Example SA", Organisation_Key="example-sa",
        Threat_Raw="ransomware", Threat="Ransomware", Sector="Inconnu",
        Location="France", Title="Example SA victime d'un ransomware",
        URL="https://example.test/incident",
        Collected_As_Of="2026-08-20T07:00:00+04:00",
    )
    values.update(changes)
    return Item(**values)


def test_collected_as_of_does_not_invalidate_fingerprint():
    left = qualification_fingerprint(_item(), policy_version="P1")
    right = qualification_fingerprint(_item(Collected_As_Of="2026-08-21T07:00:00+04:00"), policy_version="P1")
    assert left == right


def test_prequalification_fingerprint_ignores_previous_derived_outputs():
    base = prequalification_fingerprint(_item(), policy_version="P1")
    previously_qualified = prequalification_fingerprint(
        _item(Threat="Autre", Sector="Industrie", Location="Réunion"), policy_version="P1"
    )
    assert PREQUAL_FINGERPRINT_VERSION == "PREQUAL-FP-1"
    assert base == previously_qualified


def test_prequalification_fingerprint_invalidates_real_inputs():
    item = _item()
    base = prequalification_fingerprint(item, policy_version="P1", dependency_digest_value="D1")
    assert base != prequalification_fingerprint(_item(Threat_Raw="phishing"), policy_version="P1", dependency_digest_value="D1")
    assert base != prequalification_fingerprint(_item(Title="nouvelle preuve"), policy_version="P1", dependency_digest_value="D1")
    assert base != prequalification_fingerprint(item, policy_version="P2", dependency_digest_value="D1")
    assert base != prequalification_fingerprint(item, policy_version="P1", dependency_digest_value="D2")


def test_business_input_policy_and_dependency_changes_invalidate_fingerprint():
    item = _item()
    base = qualification_fingerprint(item, policy_version="P1", dependency_digest_value="D1")
    assert base != qualification_fingerprint(_item(Title="Example SA confirme une cyberattaque"), policy_version="P1", dependency_digest_value="D1")
    assert base != qualification_fingerprint(item, policy_version="P2", dependency_digest_value="D1")
    assert base != qualification_fingerprint(item, policy_version="P1", dependency_digest_value="D2")


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
    pre = prequalification_fingerprint(item, facts, policy_version="P1")
    assert pre == prequalification_fingerprint(item, reversed(facts), policy_version="P1")
    assert pre != prequalification_fingerprint(item, changed, policy_version="P1")


def test_dependency_digest_tracks_reference_org_cache_and_code(tmp_path: Path):
    code = tmp_path / "sector.py"
    code.write_text("VERSION = 1\n", encoding="utf-8")
    base = dependency_digest(
        reference_rows=[{"Organisation_Key": "a", "Sector": "Industrie"}],
        org_cache_rows=[{"Organisation_Key": "a", "Validated_Sector": "Industrie"}],
        code_paths=[code],
    )
    reordered = dependency_digest(
        reference_rows=[{"Sector": "Industrie", "Organisation_Key": "a"}],
        org_cache_rows=[{"Validated_Sector": "Industrie", "Organisation_Key": "a"}],
        code_paths=[code],
    )
    assert base == reordered
    assert base != dependency_digest(
        reference_rows=[{"Organisation_Key": "a", "Sector": "Santé"}],
        org_cache_rows=[{"Organisation_Key": "a", "Validated_Sector": "Industrie"}], code_paths=[code],
    )
    code.write_text("VERSION = 2\n", encoding="utf-8")
    assert base != dependency_digest(
        reference_rows=[{"Organisation_Key": "a", "Sector": "Industrie"}],
        org_cache_rows=[{"Organisation_Key": "a", "Validated_Sector": "Industrie"}], code_paths=[code],
    )


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
    rows = state_rows(result, policy_version="P1", dependency_digest_value="D1", run_id="RUN-1", as_of="A1")
    assert fingerprints_from_state(rows) == result.fingerprints


def test_prequalification_classify_and_state_round_trip():
    unchanged = _item(Item_ID="I-1", Sector="Industrie")
    dirty = _item(Item_ID="I-2", Title="ancienne valeur")
    previous = {
        "I-1": prequalification_fingerprint(_item(Item_ID="I-1", Sector="Inconnu"), policy_version="P1"),
        "I-2": prequalification_fingerprint(dirty, policy_version="P1"),
    }
    dirty.Title = "nouvelle valeur"
    result = classify_prequalification_items([dirty, unchanged, _item(Item_ID="I-3")], previous, policy_version="P1")
    assert result.new == ("I-3",)
    assert result.dirty == ("I-2",)
    assert result.unchanged == ("I-1",)
    rows = prequalification_state_rows(result, policy_version="P1", dependency_digest_value="D1", run_id="RUN-2", as_of="A2")
    assert fingerprints_from_state(rows, column="Prequalification_Fingerprint") == result.fingerprints


def test_shadow_cache_accepts_identical_recalculation_and_detects_mismatch():
    item = _item(Sector="Industrie")
    fingerprint = qualification_fingerprint(item, policy_version="P1")
    provenance = [{"Item_ID": "I-1", "Field": "Sector", "Decision": "APPLIED", "Final_Value": "Industrie"}]
    previous = shadow_cache_rows([item], {"I-1": fingerprint}, provenance, run_id="RUN-1", as_of="A1")
    assert previous[0]["Cache_Version"] == SHADOW_CACHE_VERSION
    current = shadow_cache_rows([item], {"I-1": fingerprint}, provenance, run_id="RUN-2", as_of="A2")
    stable = compare_shadow_cache(previous, current, ["I-1"])
    assert stable.checked == 1
    assert stable.mismatches == ()
    changed = shadow_cache_rows([_item(Sector="Santé")], {"I-1": fingerprint}, provenance, run_id="RUN-3", as_of="A3")
    assert compare_shadow_cache(previous, changed, ["I-1"]).mismatches == ("I-1",)


def test_metric_row_reports_shadow_validation():
    item = _item()
    previous = {"I-1": qualification_fingerprint(item, policy_version="P1")}
    result = classify_items([item], previous, policy_version="P1")
    shadow_rows = shadow_cache_rows([item], result.fingerprints, [], run_id="RUN-1", as_of="A1")
    shadow = compare_shadow_cache(shadow_rows, shadow_rows, result.unchanged)
    row = metric_row(result, run_id="RUN-2", as_of="A2", mode="MAJ", policy_version="P1", dependency_digest_value="D1", shadow=shadow)
    assert row["Dirty_Items"] == "0"
    assert row["Unchanged_Items"] == "1"
    assert row["Reuse_Rate"] == "1.000000"
    assert row["Shadow_Checked"] == "1"
    assert row["Shadow_Mismatches"] == "0"
