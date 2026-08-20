from cyberwatch.dedup_golden_refs import (
    AMBIGUOUS,
    LEGACY,
    MISSING,
    RESOLVED,
    enrich_golden_row,
    has_stable_refs,
    resolve_golden_side,
)


def test_source_item_id_is_primary_stable_reference(make_item):
    current = make_item(source="CYBERATTAQUE_ORG", source_item_id="42", url="https://new", published="2026-08-01")
    current.Item_ID = "ITM-current"
    row = {
        "Left_Item_ID": "ITM-old",
        "Left_Source_ID": "CYBERATTAQUE_ORG",
        "Left_Source_Item_ID": "42",
        "Left_Stable_URL": "https://old",
    }
    result = resolve_golden_side(row, "Left", [current])
    assert result.status == RESOLVED
    assert result.item is current


def test_url_is_fallback_when_source_has_no_native_id(make_item):
    current = make_item(source="BONJOURLAFUITE", source_item_id="", url="https://stable", published="2026-08-01")
    current.Item_ID = "ITM-current"
    row = {
        "Left_Item_ID": "ITM-old",
        "Left_Source_ID": "BONJOURLAFUITE",
        "Left_Source_Item_ID": "",
        "Left_Stable_URL": "https://stable",
    }
    assert resolve_golden_side(row, "Left", [current]).status == RESOLVED


def test_legacy_item_id_is_supported_only_as_migration_fallback(make_item):
    current = make_item(url="https://a")
    current.Item_ID = "ITM-legacy"
    result = resolve_golden_side({"Left_Item_ID": "ITM-legacy"}, "Left", [current])
    assert result.status == LEGACY


def test_missing_and_ambiguous_are_explicit(make_item):
    one = make_item(source="A", source_item_id="same", url="https://a")
    two = make_item(source="A", source_item_id="same", url="https://b", published="2026-08-02")
    row = {
        "Left_Source_ID": "A",
        "Left_Source_Item_ID": "same",
        "Left_Stable_URL": "",
        "Left_Item_ID": "",
    }
    assert resolve_golden_side(row, "Left", [one, two]).status == AMBIGUOUS
    row["Left_Source_Item_ID"] = "missing"
    assert resolve_golden_side(row, "Left", [one, two]).status == MISSING


def test_enrichment_materializes_both_stable_sides(make_item):
    left = make_item(source="A", source_item_id="native", url="https://a")
    left.Item_ID = "L"
    right = make_item(source="B", source_item_id="", url="https://b")
    right.Item_ID = "R"
    row = {"Case_ID": "P001", "Left_Item_ID": "L", "Right_Item_ID": "R"}
    enriched = enrich_golden_row(row, {"L": left, "R": right})
    assert has_stable_refs(enriched)
    assert enriched["Left_Source_Item_ID"] == "native"
    assert enriched["Right_Stable_URL"] == "https://b"
