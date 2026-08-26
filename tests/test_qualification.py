from cyberwatch import config, identity, organisation_sector_llm, qualification
from cyberwatch.qualification import qualify


def test_qualification_is_idempotent_and_keeps_item_identity(make_item):
    item = make_item(threat=config.THREAT_UNKNOWN, title="Fuite de données confirmée")
    before = item.Item_ID
    first = qualify([item])
    second = qualify(first.items)
    assert first.items_hash == second.items_hash
    assert first.incidents_hash == second.incidents_hash
    assert first.items[0].Item_ID == before


def test_structured_values_are_not_overwritten_by_qualification(make_item):
    item = make_item(sector="Santé", location="France", threat="Ransomware")
    result = qualify([item])
    assert (result.items[0].Sector, result.items[0].Location, result.items[0].Threat) == ("Santé", "France", "Ransomware")


def test_same_run_facts_reach_final_llm_and_its_decision_overwrites_stale_sector(make_item, monkeypatch):
    item = make_item(org="Acme Unique", sector=config.SECTOR_HEALTH)
    facts = [{
        "Item_ID": item.Item_ID,
        "Source_ID": item.Source_ID,
        "Activity_Description": "Acme Unique édite une plateforme SaaS.",
        "Activity_Sector_Match": config.SECTOR_TECH,
    }]

    def fake_enrich(items, **kwargs):
        assert kwargs["source_fact_rows"] is facts
        return organisation_sector_llm.EnrichmentReport(
            organisations_selected=1,
            candidates=1,
            cache_rows=[{
                "Organisation_Key": item.Organisation_Key,
                "Organisation": item.Organisation_Raw,
                "Input_Hash": "validated-by-fake",
                "Sector": config.SECTOR_TECH,
                "Confidence": "0.90",
                "Basis": "explicit_activity",
                "Reason": "L'activité SaaS est explicite.",
                "Model": "test-model",
                "Prompt_Version": "test-prompt",
                "Created_At": "2026-08-26T00:00:00Z",
            }],
        )

    monkeypatch.setattr(
        qualification.organisation_sector_llm,
        "enrich_unknown_organisation_sectors",
        fake_enrich,
    )
    result = qualification.qualify(
        [item], source_fact_rows=facts, org_cache_rows=[],
        allow_llm=True, persist_llm_cache=False,
    )

    assert result.items[0].Sector == config.SECTOR_TECH
    assert any(
        row["Evidence_Type"] == "source_activity" and row["Outcome"] == "PRODUCED"
        for row in result.organisation_sector_evidence
    )
