from cyberwatch import config, context_sector
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


def _item(item_id: str, organisation: str, *, title: str = "", url: str = "") -> Item:
    return Item(
        Item_ID=item_id,
        Source_ID="CYBERATTAQUE_ORG",
        Organisation_Raw=organisation,
        Organisation_Key=organisation_key(organisation),
        Sector=config.SECTOR_UNKNOWN,
        Title=title,
        URL=url,
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
    assert context_sector.classify_context_activity(
        "Spécialisé dans la vente d'accessoires et d'équipements pour camping-cars"
    ) == config.SECTOR_RETAIL


def test_source_title_context_resolves_samboat_without_external_search():
    item = _item(
        "I1",
        "SamBoat",
        title="SamBoat : la plateforme de location de bateaux frappée par une cyberattaque majeure",
        url="https://www.cyberattaque.org/samboat-la-plateforme-de-location-de-bateaux-frappee/",
    )
    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], [], [])
    assert applied == 1
    assert conflicts == 0
    assert item.Sector == getattr(config, "SECTOR_HOSPITALITY")
    assert "source_title_context" in provenance[0]["Evidence"]


def test_source_url_context_resolves_sde03_from_explicit_article_slug():
    item = _item(
        "I1",
        "SDE 03",
        title="SDE 03 piraté : 4 122 personnes en fuite",
        url="https://www.cyberattaque.org/syndicat-departemental-energie-de-lallier-cyberattaque/",
    )
    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], [], [])
    assert applied == 1
    assert conflicts == 0
    assert item.Sector == config.SECTOR_ENERGY
    assert "source_url_context" in provenance[0]["Evidence"]


def test_unrelated_title_activity_is_not_attributed_to_victim():
    item = _item(
        "I1",
        "Opaque Corp",
        title="Cyberattaque : une plateforme de location de bateaux mentionne Opaque Corp",
        url="https://www.cyberattaque.org/opaque-corp-cyberattaque/",
    )
    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], [], [])
    assert applied == 0
    assert conflicts == 0
    assert provenance == []


def test_incident_vocabulary_does_not_become_primary_activity():
    cases = [
        _item(
            "I1", "OpenAI",
            title="OpenAI : des données internes compromises après l’installation de la bibliothèque piégée TanStack",
            url="https://www.cyberattaque.org/openai-des-donnees-internes-compromises-apres-linstallation-de-la-bibliotheque-piegee-tanstack/",
        ),
        _item(
            "I2", "La Redoute",
            title="La Redoute : une base logistique de 96 000 clients liées aux livraisons en fuite",
            url="https://www.cyberattaque.org/la-redoute-une-base-logistique-de-96-000-clients-liees-aux-livraisons-en-fuite/",
        ),
        _item(
            "I3", "MesVaccins",
            title="MesVaccins : des données de santé et numéros de sécurité sociale exposés après une cyberattaque",
            url="https://www.cyberattaque.org/mesvaccins-des-donnees-de-sante-et-numeros-de-securite-sociale-exposes-apres-une-cyberattaque/",
        ),
        _item(
            "I4", "CFDT",
            title="CFDT : victime d'une cyberattaque",
            url="https://www.cfdt.fr/sinformer/communiques-de-presse/securite-informatique-la-cfdt-victime-d-une-cyberattaque",
        ),
        _item(
            "I5", "McDonald's France",
            title="McDonald's France victime d'une fuite de données",
            url="https://example.test/secteur/high-tech/mcdonald-s-france-victime-d-une-fuite-de-donnees",
        ),
    ]
    applied, provenance, conflicts = context_sector.resolve_contextual_sectors(cases, [], [])
    assert applied == 0
    assert conflicts == 0
    assert provenance == []
    assert all(item.Sector == config.SECTOR_UNKNOWN for item in cases)


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


def test_generic_editorial_activity_is_only_a_hint_not_auto_sector():
    item = _item("I1", "Opaque Corp")
    facts = [{
        "Item_ID": "I1",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Activity_Description": "services informatiques et développement de logiciels",
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], facts, [])

    assert applied == 0
    assert conflicts == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_UNKNOWN


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


def test_generic_official_activity_is_retained_as_evidence_but_not_auto_applied():
    item = _item("I1", "Opaque Tech")
    cache = [{
        "Organisation_Key": organisation_key("Opaque Tech"),
        "Query_Name": "Opaque Tech",
        "Match_Status": "MATCHED",
        "Validated_Sector": config.SECTOR_DIGITAL,
        "Validated_Via": "official_subject_activity",
        "Activity_Label": "services informatiques et développement de logiciels",
        "Evidence_URL": "https://opaque.example/",
        "Evidence_Source": "official_site",
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], [], cache)

    assert applied == 0
    assert conflicts == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_UNKNOWN


def test_context_resolver_rejects_cached_sector_if_activity_does_not_reproduce_it():
    item = _item("I1", "Example")
    cache = [{
        "Organisation_Key": organisation_key("Example"),
        "Match_Status": "MATCHED",
        "Validated_Sector": config.SECTOR_ENERGY,
        "Validated_Via": "official_subject_activity",
        "Activity_Label": "fournisseur de matériel agricole",
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], [], cache)

    assert applied == 0
    assert conflicts == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_UNKNOWN


def test_context_resolver_does_not_promote_raw_source_sector():
    item = _item("I1", "CNAOC")
    facts = [{
        "Item_ID": "I1",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Source_Sector_Raw": "Energy & Utilities",
    }]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], facts, [])

    assert applied == 0
    assert conflicts == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_UNKNOWN


def test_context_resolver_abstains_on_conflicting_strong_evidence():
    item = _item("I1", "Example")
    facts = [
        {"Item_ID": "I1", "Source_ID": "SRC1", "Activity_Description": "industrie manufacturière"},
        {"Item_ID": "I1", "Source_ID": "SRC2", "Activity_Description": "services informatiques et logiciel"},
    ]

    applied, provenance, conflicts = context_sector.resolve_contextual_sectors([item], facts, [])

    assert applied == 1
    assert conflicts == 0
    assert item.Sector == config.SECTOR_INDUSTRY
    assert len(provenance) == 1


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
