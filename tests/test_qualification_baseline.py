from cyberwatch import config
from cyberwatch.qualification_baseline import compare_reports, coverage_rows, golden_reference_by_anchor


def test_coverage_rows_global_and_source(make_item):
    items = [
        make_item(source="A", sector=config.SECTOR_UNKNOWN, threat=config.THREAT_RANSOMWARE, location=config.LOC_FRANCE),
        make_item(source="A", source_item_id="2", sector=config.SECTOR_HEALTH, threat=config.THREAT_UNKNOWN, location=config.LOC_INCONNU),
    ]
    rows = coverage_rows(items)
    by_key = {(row["Source_ID"], row["Field"]): row for row in rows}
    assert by_key[("ALL", "Sector")]["Known"] == 1
    assert by_key[("A", "Threat")]["Unknown"] == 1
    assert by_key[("A", "Location")]["Coverage_pct"] == 50.0


def test_golden_reference_uses_stable_anchor():
    golden = [{"Incident_ID_Snapshot": "INC-1", "Secteur_REF": "Santé", "Menace_REF": "Ransomware", "Localisation_REF": "France métropolitaine"}]
    registry = [{"Incident_ID": "INC-1", "Anchor_Item_ID": "ITM-1", "Redirect_To": ""}]
    refs = golden_reference_by_anchor(golden, registry)
    assert refs["ITM-1"]["Secteur_REF"] == "Santé"


def test_compare_reports_blocks_coverage_regression():
    before = {"coverage": [{"Source_ID":"ALL","Field":"Sector","Unknown":1,"Coverage_pct":90.0}], "quality_by_origin": []}
    after = {"coverage": [{"Source_ID":"ALL","Field":"Sector","Unknown":2,"Coverage_pct":80.0}], "quality_by_origin": []}
    failures = compare_reports(before, after)
    assert any("inconnus" in failure for failure in failures)
    assert any("couverture" in failure for failure in failures)


def test_compare_reports_blocks_measured_origin_regression():
    before = {"coverage": [], "quality_by_origin": [{"Origin":"STRUCTURED_SOURCE","Field":"Sector","Applied":10,"Precision_pct":100.0,"Regressions":0}]}
    after = {"coverage": [], "quality_by_origin": [{"Origin":"STRUCTURED_SOURCE","Field":"Sector","Applied":10,"Precision_pct":90.0,"Regressions":1}]}
    failures = compare_reports(before, after)
    assert any("précision" in failure for failure in failures)
    assert any("régressions" in failure for failure in failures)
