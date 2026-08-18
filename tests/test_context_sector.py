from cyberwatch import config, context_sector
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


def _item(item_id: str, organisation: str) -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID="CYBERATTAQUE_ORG",
        Organisation_Raw=organisation,
        Organisation_Key=organisation_key(organisation),
        Sector=config.SECTOR_UNKNOWN,
    )


def test_context_activity_examples_from_observed_long_tail():
    hospitality = getattr(config, "SECTOR_HOSPITALITY")
    assert context_sector.classify_context_activity(
        "Syndicat départemental d'énergie chargé de la distribution publique d'électricité et de gaz"
    ) == config.SECTOR_ENERGY
    assert context_sector.classify_context_activity(
        "Entreprise spécialisée dans la conception, la fabrication et la distribution d'outillage aéronautique"
    ) == config.SECTOR_INDUSTRY
    assert context_sector.classify_context_activity(
        "Site leader de la location de bateaux entre particuliers et professionnels"
    ) == hospitality
    assert context_sector.classify_context_activity(
        "Salle de réalité virtuelle dédiée à l'esport et aux compétitions"
    ) == config.SECTOR_SPORT
    assert context_sector.classify_context_activity(
        "Fournisseur de matériel agricole et vente de pièces"
    ) == config.SECTOR_RETAIL
    assert context_sector.classify_context_activity(
        "Rénovation de l'habitat, pose de fenêtres, volets et portes"
    ) == config.SECTOR_CONSTRUCTION
    assert context_sector.classify_context_activity(
        "Spécialiste de la manutention industrie et équipements industriels"
    ) == config.SECTOR_INDUSTRY


def test_context_resolver_propagates_activity_by_exact_org_key():
    items = [_item("I1", "Bija Industrie"), _item("I2", "Bija Industrie")]
    facts = [{
        "Item_ID": "I1",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Activity_Description": "conception et fabrication d'outillage aéronautique",
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors(items, facts, [])

    assert applied == 2
    assert conflicts == 0
    assert {item.Sector for item in items} == {config.SECTOR_INDUSTRY}
    assert len(provenance) == 2
    assert all(row["Origin"] == context_sector.ORIGIN for row in provenance)


def test_context_resolver_uses_existing_official_cache_without_network():
    item = _item("I1", "SamBoat")
    hospitality = getattr(config, "SECTOR_HOSPITALITY")
    cache = [{
        "Organisation_Key": organisation_key("SamBoat"),
        "Query_Name": "SamBoat",
        "Match_Status": "MATCHED",
        "Validated_Sector": hospitality,
        "Validated_Via": "official_subject_activity",
        "Activity_Label": "location de bateaux",
        "Evidence_URL": "https://www.samboat.fr/",
        "Evidence_Source": "official_site",
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], [], cache)

    assert applied == 1
    assert conflicts == 0
    assert item.Sector == hospitality
    assert "official_subject_activity" in provenance[0]["Evidence"]


def test_context_resolver_abstains_on_conflicting_strong_evidence():
    item = _item("I1", "Example")
    facts = [
        {"Item_ID": "I1", "Source_ID": "SRC1", "Activity_Description": "fabrication industrielle"},
        {"Item_ID": "I1", "Source_ID": "SRC2", "Activity_Description": "services informatiques et logiciels"},
    ]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], facts, [])

    assert applied == 0
    assert conflicts == 1
    assert provenance == []
    assert item.Sector == config.SECTOR_UNKNOWN


def test_leak_data_alone_never_classifies_sector():
    item = _item("I1", "Opaque Name")
    facts = [{
        "Item_ID": "I1",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": "4122 personnes ; IBAN / RIB ; données sensibles",
        "Data_Types_JSON": '["IBAN","RIB"]',
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], facts, [])

    assert applied == 0
    assert conflicts == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_UNKNOWN
