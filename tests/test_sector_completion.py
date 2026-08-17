from cyberwatch import config, org_enrichment, sector, source_facts
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.model import Item
from cyberwatch.sector_completion import (
    SECTOR_ASSOCIATIONS,
    SECTOR_CULTURE,
    SECTOR_HOSPITALITY,
)


def _item(source_id="VEILLE_LLM") -> Item:
    return Item(
        Item_ID="ITM-test",
        Source_ID=source_id,
        Published_Date="2026-08-17",
        Organisation_Raw="Organisation Test",
        Organisation_Key="organisation test",
        Threat="Fuite de données",
        Sector=config.SECTOR_UNKNOWN,
        Location=config.LOC_FRANCE,
        Title="Organisation Test",
        URL="https://example.test/inc",
        Collected_As_Of="2026-08-17T12:00:00+04:00",
    )


def _spec(source_id="VEILLE_LLM") -> SourceSpec:
    return SourceSpec(source_id=source_id, layer="test", zone="France")


def test_targeted_taxonomy_is_available_to_all_classifiers():
    assert SECTOR_HOSPITALITY in config.SECTORS
    assert SECTOR_CULTURE in config.SECTORS
    assert SECTOR_ASSOCIATIONS in config.SECTORS
    assert sector.classify_source_sector("Commerce") == config.SECTOR_RETAIL
    assert sector.classify_source_sector("Tourisme") == SECTOR_HOSPITALITY
    assert sector.classify_source_sector("Médias") == SECTOR_CULTURE
    assert sector.classify_source_sector("Associations") == SECTOR_ASSOCIATIONS


def test_source_fact_sector_promotes_unknown_item():
    item = _item()
    entry = RawEntry(
        title="Organisation Test",
        published="2026-08-17",
        organisation="Organisation Test",
        source_metadata={"secteur": "Commerce"},
    )

    fact = source_facts.extract_source_fact(item, entry, _spec())

    assert fact is not None
    assert fact["Source_Sector_Raw"] == "Commerce"
    assert item.Sector == config.SECTOR_RETAIL


def test_source_fact_new_taxonomy_promotes_unknown_item():
    item = _item()
    entry = RawEntry(
        title="Organisation Test",
        published="2026-08-17",
        organisation="Organisation Test",
        source_metadata={"secteur": "Tourisme"},
    )

    source_facts.extract_source_fact(item, entry, _spec())

    assert item.Sector == SECTOR_HOSPITALITY


def test_activity_rules_cover_only_explicit_business_descriptions():
    assert sector.classify_sector_activity("hôtel et résidence de tourisme") == SECTOR_HOSPITALITY
    assert sector.classify_sector_activity("association à but non lucratif") == SECTOR_ASSOCIATIONS
    assert sector.classify_sector_activity("production audiovisuelle et cinéma") == SECTOR_CULTURE
    assert sector.classify_sector_name("Tourisme Conseil") == config.SECTOR_UNKNOWN


def test_cached_naf_records_are_requalified_without_http(monkeypatch):
    rows = [
        {
            "Organisation_Key": "hotel test",
            "Query_Name": "Hotel Test",
            "Matched_Name": "HOTEL TEST",
            "Company_ID": "1",
            "Activity_Code": "56.10A",
            "Activity_Label": "Hébergement et restauration",
            "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr",
            "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "",
            "Validated_Via": "",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
        {
            "Organisation_Key": "federation test",
            "Query_Name": "Federation Test",
            "Matched_Name": "FEDERATION TEST",
            "Company_ID": "2",
            "Activity_Code": "93.12Z",
            "Activity_Label": "Arts, spectacles et activités récréatives",
            "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr",
            "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "",
            "Validated_Via": "llm_declined",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
        {
            "Organisation_Key": "culture test",
            "Query_Name": "Culture Test",
            "Matched_Name": "CULTURE TEST",
            "Company_ID": "3",
            "Activity_Code": "90.01Z",
            "Activity_Label": "Arts, spectacles et activités récréatives",
            "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr",
            "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "",
            "Validated_Via": "",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
        {
            "Organisation_Key": "politique test",
            "Query_Name": "Politique Test",
            "Matched_Name": "POLITIQUE TEST",
            "Company_ID": "4",
            "Activity_Code": "94.92Z",
            "Activity_Label": "Autres activités de services",
            "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr",
            "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "",
            "Validated_Via": "",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
    ]
    monkeypatch.setattr(org_enrichment.store, "load_org_enrichment_cache", lambda: rows)

    state = org_enrichment.start_state()

    assert state.cache["hotel test"]["Validated_Sector"] == SECTOR_HOSPITALITY
    assert state.cache["federation test"]["Validated_Sector"] == config.SECTOR_SPORT
    assert state.cache["culture test"]["Validated_Sector"] == SECTOR_CULTURE
    assert state.cache["politique test"]["Validated_Sector"] == SECTOR_ASSOCIATIONS
    assert all(row["Validated_Via"] == "naf_precise" for row in state.cache.values())


def test_old_broad_naf_code_is_not_forced_into_sport(monkeypatch):
    row = {
        "Organisation_Key": "homair",
        "Query_Name": "Homair",
        "Matched_Name": "HOMAIR",
        "Company_ID": "340061530",
        "Activity_Code": "93.0D",
        "Activity_Label": "Arts, spectacles et activités récréatives",
        "Headquarters_Department": "17",
        "Evidence_Source": "recherche-entreprises.api.gouv.fr",
        "Evidence_URL": "",
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": "2026-08-17T10:00:00+04:00",
        "Validated_Sector": "",
        "Validated_Via": "llm_declined",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }
    monkeypatch.setattr(org_enrichment.store, "load_org_enrichment_cache", lambda: [row])

    state = org_enrichment.start_state()

    assert state.cache["homair"]["Validated_Sector"] == ""
