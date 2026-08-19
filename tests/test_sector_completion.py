from cyberwatch import config, org_enrichment, sector, source_facts
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.model import Item
from cyberwatch.sector_completion import (
    SECTOR_ASSOCIATIONS,
    SECTOR_CULTURE,
    SECTOR_HOSPITALITY,
    _strong_activity_sector,
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


def test_targeted_taxonomy_stays_canonical():
    assert SECTOR_HOSPITALITY in config.SECTORS
    assert SECTOR_CULTURE in config.SECTORS
    assert SECTOR_ASSOCIATIONS not in config.SECTORS
    assert sector.classify_source_sector("Commerce") == config.SECTOR_RETAIL
    assert sector.classify_source_sector("Tourisme") == SECTOR_HOSPITALITY
    assert sector.classify_source_sector("Médias") == SECTOR_CULTURE
    assert sector.classify_source_sector("Associations") == config.SECTOR_UNKNOWN
    assert sector.classify_source_sector("politique") == config.SECTOR_UNKNOWN


def test_six_golden_business_patterns_are_general_not_name_exceptions():
    # Planity: logiciel/SaaS vertical, pas commerce beauté.
    assert _strong_activity_sector(
        "éditeur d'une solution SaaS et plateforme de prise de rendez-vous pour les professionnels de la beauté"
    ) == config.SECTOR_TECH
    # KeepCool: activité sportive, pas simple abonnement commercial.
    assert _strong_activity_sector(
        "réseau de salles de sport et clubs de fitness avec coaching"
    ) == config.SECTOR_SPORT
    # Télécom Saint-Étienne: école malgré un nom lexicalement technologique.
    assert _strong_activity_sector(
        "grande école d'ingénieurs et établissement d'enseignement supérieur"
    ) == config.SECTOR_EDUCATION
    # 1001Coques: vendeur de produits tech, donc commerce.
    assert _strong_activity_sector(
        "site e-commerce de vente en ligne de coques, chargeurs et accessoires téléphoniques"
    ) == config.SECTOR_RETAIL
    # Eiffage: constructeur d'infrastructures, pas transporteur.
    assert _strong_activity_sector(
        "groupe de construction, génie civil, travaux publics et infrastructures"
    ) == config.SECTOR_CONSTRUCTION
    # RN: aucune catégorie politique canonique.
    assert _strong_activity_sector(
        "parti politique et mouvement politique français"
    ) == config.SECTOR_UNKNOWN


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


def test_activity_rules_keep_noncanonical_associations_out():
    assert sector.classify_sector_activity("hôtel et résidence de tourisme") == SECTOR_HOSPITALITY
    assert sector.classify_sector_activity("association à but non lucratif") == config.SECTOR_UNKNOWN
    assert sector.classify_sector_activity("production audiovisuelle et cinéma") == SECTOR_CULTURE
    assert sector.classify_sector_name("Tourisme Conseil") == config.SECTOR_UNKNOWN


def test_public_health_institution_name_is_not_left_unknown():
    assert sector.classify_sector_name("Santé publique France") == config.SECTOR_HEALTH


def test_public_health_mission_beats_generic_administration_marker():
    assert sector.classify_sector_activity("agence nationale de santé publique") == config.SECTOR_HEALTH
    assert sector.classify_sector_activity(
        "établissement public chargé de la prévention sanitaire"
    ) == config.SECTOR_HEALTH


def test_generic_public_agency_without_health_mission_is_not_forced_to_health():
    assert sector.classify_sector_activity(
        "agence nationale de la cohésion des territoires"
    ) == config.SECTOR_ADMIN
    assert sector.classify_sector_name("Santé Conseil") == config.SECTOR_UNKNOWN


def test_cached_naf_records_are_requalified_without_http(monkeypatch):
    rows = [
        {
            "Organisation_Key": "hotel test", "Query_Name": "Hotel Test",
            "Matched_Name": "HOTEL TEST", "Company_ID": "1", "Activity_Code": "56.10A",
            "Activity_Label": "Hébergement et restauration", "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr", "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED, "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "", "Validated_Via": "",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
        {
            "Organisation_Key": "federation test", "Query_Name": "Federation Test",
            "Matched_Name": "FEDERATION TEST", "Company_ID": "2", "Activity_Code": "93.12Z",
            "Activity_Label": "Arts, spectacles et activités récréatives", "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr", "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED, "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "", "Validated_Via": "llm_declined",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
        {
            "Organisation_Key": "culture test", "Query_Name": "Culture Test",
            "Matched_Name": "CULTURE TEST", "Company_ID": "3", "Activity_Code": "90.01Z",
            "Activity_Label": "Arts, spectacles et activités récréatives", "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr", "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED, "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": "", "Validated_Via": "",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
        {
            "Organisation_Key": "politique test", "Query_Name": "Politique Test",
            "Matched_Name": "POLITIQUE TEST", "Company_ID": "4", "Activity_Code": "94.92Z",
            "Activity_Label": "Autres activités de services", "Headquarters_Department": "75",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr", "Evidence_URL": "",
            "Match_Status": org_enrichment.MATCHED, "Fetched_At": "2026-08-17T10:00:00+04:00",
            "Validated_Sector": SECTOR_ASSOCIATIONS, "Validated_Via": "naf_precise",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        },
    ]
    monkeypatch.setattr(org_enrichment.store, "load_org_enrichment_cache", lambda: rows)
    state = org_enrichment.start_state()
    assert state.cache["hotel test"]["Validated_Sector"] == SECTOR_HOSPITALITY
    assert state.cache["federation test"]["Validated_Sector"] == config.SECTOR_SPORT
    assert state.cache["culture test"]["Validated_Sector"] == SECTOR_CULTURE
    assert state.cache["politique test"]["Validated_Sector"] == ""
    assert state.cache["politique test"]["Validated_Via"] == ""


def test_old_broad_naf_code_is_not_forced_into_sport(monkeypatch):
    row = {
        "Organisation_Key": "homair", "Query_Name": "Homair", "Matched_Name": "HOMAIR",
        "Company_ID": "340061530", "Activity_Code": "93.0D",
        "Activity_Label": "Arts, spectacles et activités récréatives",
        "Headquarters_Department": "17", "Evidence_Source": "recherche-entreprises.api.gouv.fr",
        "Evidence_URL": "", "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": "2026-08-17T10:00:00+04:00", "Validated_Sector": "",
        "Validated_Via": "llm_declined", "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }
    monkeypatch.setattr(org_enrichment.store, "load_org_enrichment_cache", lambda: [row])
    state = org_enrichment.start_state()
    assert state.cache["homair"]["Validated_Sector"] == ""
