import json

from cyberwatch import config, editorial_corrections


def test_source_fact_correction_retires_un_fait_d_une_autre_victime():
    rows = [{
        "Item_ID": "ITM-x",
        "Data_Volume_Raw": "5,79 To",
        "Evidence_JSON": json.dumps({"Data_Volume_Raw": "5,79 To provenant de Berlin"}),
        "Source_Metadata_JSON": json.dumps({"rich_facts": {"data_volumes": [
            {"value": 5.79, "evidence": "5,79 To provenant de l’État de Berlin"},
            {"value": 200, "evidence": "200 Go attribués à la victime"},
        ]}}),
    }]
    corrections = {"source_facts": {"ITM-x": {
        "audit": "test",
        "reason": "autre victime",
        "clear": ["Data_Volume_Raw"],
        "rich_remove_evidence_contains": ["État de Berlin"],
    }}}
    changed = editorial_corrections.apply_source_facts(rows, corrections)
    assert changed == ["ITM-x"]
    assert rows[0]["Data_Volume_Raw"] == ""
    rich = json.loads(rows[0]["Source_Metadata_JSON"])["rich_facts"]
    assert [entry["value"] for entry in rich["data_volumes"]] == [200]


def test_item_correction_est_appliquee_apres_les_fallbacks(make_item):
    item = make_item(threat=config.THREAT_INTRUSION)
    item.Item_ID = "ITM-x"
    changed = editorial_corrections.apply_items([item], {
        "items": {"ITM-x": {"set": {"Threat": config.THREAT_LEAK}}}
    })
    assert changed == ["ITM-x"]
    assert item.Threat == config.THREAT_LEAK


def test_metadata_override_est_persiste():
    rows = [{"Item_ID": "ITM-x", "Source_Metadata_JSON": ""}]
    editorial_corrections.apply_source_facts(rows, {"source_facts": {"ITM-x": {
        "metadata_set": {"threat_override": {"value": config.THREAT_LEAK}},
    }}})
    assert json.loads(rows[0]["Source_Metadata_JSON"])["threat_override"]["value"] == config.THREAT_LEAK
