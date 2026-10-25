"""La fiche du Tampon conserve le contexte régional sans fusion forcée."""
import json

from cyberwatch import config, editorial_corrections, site, store, threat_resolution


def test_tampon_follow_up_is_documented_and_linked(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SITE_DATA_DIR", tmp_path)
    site.build()
    incidents = json.loads((tmp_path / "incidents.json").read_text(encoding="utf-8"))
    facts = json.loads((tmp_path / "facts.json").read_text(encoding="utf-8"))
    by_case = {(row["org"], row["date"]): row for row in incidents}
    follow_up = by_case["Commune Du Tampon", "2026-10-15"]
    original = by_case["Ville du Tampon", "2026-09-09"]

    follow_up_detail = facts[follow_up["id"]]
    original_detail = facts[original["id"]]
    assert follow_up["id"] != original["id"]
    assert "Qilin" in follow_up_detail["summary_paragraphs"][0]
    assert "pas confirmées" in follow_up_detail["summary_paragraphs"][0]
    assert follow_up_detail["related_cases"][0]["id"] == original["id"]
    assert original_detail["related_cases"][0]["id"] == follow_up["id"]
    qualification = original_detail["regional_watch"][0]
    assert "Services municipaux" in qualification["impact_connu"]
    assert "attribution non confirmée" in qualification["acteur"]


def test_recent_regional_snapshot_cases_have_context(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "SITE_DATA_DIR", tmp_path)
    site.build()
    incidents = json.loads((tmp_path / "incidents.json").read_text(encoding="utf-8"))
    facts = json.loads((tmp_path / "facts.json").read_text(encoding="utf-8"))
    examples = {
        ("Leader Price de Saint-André", "2026-10-12"),
        ("Police nationale / DTPN 974", "2026-09-30"),
        ("Lycée polyvalent Jean Joly", "2026-09-14"),
        ("Ville du Tampon", "2026-09-09"),
        ("MANU-PORT", "2026-08-31"),
        ("Bureau Vallée", "2026-08-09"),
    }
    selected = [row for row in incidents if (row["org"], row["date"]) in examples]
    assert len(selected) == len(examples)
    for row in selected:
        detail = facts[row["id"]]
        assert detail["summary_paragraphs"], row["org"]
        if "VEILLE_LLM" in row["sources"]:
            qualification = detail["regional_watch"][0]
            assert qualification["statut"] and qualification["impact_connu"]


def test_regional_editorial_qualification_prevents_unproven_threat_labels():
    ids = {"ITM-80cc8ab052423602", "ITM-fdc47ad9dffdbe4d"}
    items = [item for item in store.load_items() if item.Item_ID in ids]
    facts = [fact for fact in store.load_source_facts() if fact["Item_ID"] in ids]
    assert {item.Item_ID for item in items} == ids
    assert {fact["Item_ID"] for fact in facts} == ids

    editorial_corrections.apply_source_facts(facts)
    indexed = threat_resolution.index_source_facts(facts)
    for item in items:
        decision = threat_resolution.resolve_component([item], indexed)
        assert decision.value == config.THREAT_OTHER
        assert decision.reason == "THREAT_EDITORIAL_CORRECTION"
