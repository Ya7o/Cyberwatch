"""Qualification Location minimale : priorité et enrichissement sans appel dédié."""

from cyberwatch import ai, config, enrichment, org_enrichment, sources, store
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from cyberwatch.normalize import classify_location, organisation_key


def _item(source: str, title: str, *, org: str = "Organisation Test Location", location: str = config.LOC_INCONNU) -> Item:
    return Item(
        Item_ID=f"{source}-{title}",
        Source_ID=source,
        Published_Date="2026-08-16",
        Organisation_Raw=org,
        Organisation_Key=organisation_key(org),
        Threat=config.THREAT_LEAK,
        Sector=config.SECTOR_UNKNOWN,
        Location=location,
        Title=title,
        URL="https://example.test/location",
        Collected_As_Of="2026-08-16T10:00:00+04:00",
    )


def test_reunion_strong_hint_beats_france_default():
    assert classify_location(
        "Une entreprise réunionnaise victime d'une fuite",
        default=config.LOC_FRANCE,
    ) == config.LOC_REUNION


def test_mayotte_strong_hint_beats_france_default():
    assert classify_location(
        "Une société basée à Mayotte victime d'une attaque",
        default=config.LOC_FRANCE,
    ) == config.LOC_MAYOTTE


def test_reunion_de_crise_is_not_reunion_territory():
    assert classify_location(
        "La réunion de crise confirme l'incident",
        default=config.LOC_FRANCE,
    ) == config.LOC_FRANCE


def test_proper_name_la_reunion_is_recognized():
    assert classify_location("Victime implantée à La Réunion") == config.LOC_REUNION


def test_ambiguous_person_or_city_does_not_guess_location():
    assert classify_location("Maurice Dupont confirme l'incident") == config.LOC_INCONNU
    assert classify_location("Communiqué publié à Paris") == config.LOC_INCONNU


def test_headquarters_department_mapping_is_minimal():
    assert org_enrichment.location_for_headquarters_department("974") == config.LOC_REUNION
    assert org_enrichment.location_for_headquarters_department("976") == config.LOC_MAYOTTE
    assert org_enrichment.location_for_headquarters_department("75") == config.LOC_FRANCE
    assert org_enrichment.location_for_headquarters_department("2A") == config.LOC_FRANCE
    assert org_enrichment.location_for_headquarters_department("971") == config.LOC_INCONNU
    assert org_enrichment.location_for_headquarters_department("") == config.LOC_INCONNU


def test_org_record_keeps_headquarters_department():
    record = org_enrichment._record_from_candidate(
        "org test", "Org Test",
        {
            "nom_raison_sociale": "Org Test",
            "siren": "123456789",
            "activite_principale": "63.11Z",
            "section_activite_principale": "J",
            "siege": {"departement": "974"},
        },
        "2026-08-16",
    )
    assert record.Headquarters_Department == "974"


def test_historical_french_source_gets_default_france(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("FRENCHBREACHES", "Fuite de données confirmée")
    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_FRANCE


def test_historical_french_source_keeps_explicit_reunion_before_default(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("BONJOURLAFUITE", "Entreprise réunionnaise : fuite de données")
    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_REUNION


def test_backfill_reuses_existing_api_cache_without_network(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org API Location")
    store.save_org_enrichment_cache([{
        "Organisation_Key": item.Organisation_Key,
        "Query_Name": item.Organisation_Raw,
        "Matched_Name": item.Organisation_Raw,
        "Company_ID": "123456789",
        "Activity_Code": "63.11Z",
        "Activity_Label": "Information et communication",
        "Headquarters_Department": "974",
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": "2026-08-16",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }])

    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_REUNION


def test_location_is_not_propagated_blindly_between_items(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    org = "Organisation Sans Cache 9F8A"
    direct = _item("FRENCHBREACHES", "Fuite confirmée", org=org, location=config.LOC_FRANCE)
    unknown = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org=org)

    enrichment.backfill_unknowns([direct, unknown], {})
    assert unknown.Location == config.LOC_INCONNU


def test_existing_sector_enrichment_cache_can_feed_location_before_llm(tmp_path, monkeypatch):
    """Le cache produit par le même enrichissement secteur suffit ; aucun appel dédié Location."""
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org.csv")
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Cache Live")
    store.save_org_enrichment_cache([{
        "Organisation_Key": item.Organisation_Key,
        "Query_Name": item.Organisation_Raw,
        "Matched_Name": item.Organisation_Raw,
        "Company_ID": "987654321",
        "Activity_Code": "63.11Z",
        "Activity_Label": "Information et communication",
        "Headquarters_Department": "976",
        "Match_Status": org_enrichment.MATCHED,
        "Fetched_At": "2026-08-16",
        "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    }])

    enrichment.backfill_unknowns([item], {})
    assert item.Location == config.LOC_MAYOTTE



def test_bare_974_976_are_not_geographic_evidence():
    assert classify_location("974 dossiers compromis") == config.LOC_INCONNU
    assert classify_location("976 comptes exposés") == config.LOC_INCONNU


def test_postal_codes_and_department_context_are_geographic_evidence():
    assert classify_location("Victime située au 97400 Saint-Denis") == config.LOC_REUNION
    assert classify_location("Entreprise du département 974") == config.LOC_REUNION
    assert classify_location("Victime située au 97600 Mamoudzou") == config.LOC_MAYOTTE
    assert classify_location("Entreprise du département 976") == config.LOC_MAYOTTE


def test_org_enrichment_can_resolve_location_when_sector_is_already_known(monkeypatch):
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Location Seule")
    item.Sector = config.SECTOR_TECH
    calls = []

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        calls.append((org_key, organisation_raw))
        return org_enrichment.OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Matched_Name=organisation_raw,
            Match_Status=org_enrichment.MATCHED,
            Headquarters_Department="974",
            Fetched_At=fetched_at,
        )

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec is not None
    entry = RawEntry(title=item.Title, published=item.Published_Date, summary="Incident confirmé.", url=item.URL)
    ai.qualify_item(item, entry, spec, state)
    assert len(calls) == 1
    assert item.Sector == config.SECTOR_TECH
    assert item.Location == config.LOC_REUNION


def test_one_org_enrichment_resolves_sector_and_location_together(monkeypatch):
    item = _item("CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Double Enrichissement")
    calls = []

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        calls.append((org_key, organisation_raw))
        return org_enrichment.OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Matched_Name=organisation_raw,
            Match_Status=org_enrichment.MATCHED,
            Activity_Label="Information et communication",
            Headquarters_Department="976",
            Fetched_At=fetched_at,
        )

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec is not None
    entry = RawEntry(title=item.Title, published=item.Published_Date, summary="Incident confirmé.", url=item.URL)
    ai.qualify_item(item, entry, spec, state)
    assert len(calls) == 1
    assert item.Sector == config.SECTOR_TECH
    assert item.Location == config.LOC_MAYOTTE


def test_org_enrichment_never_overwrites_known_location(monkeypatch):
    item = _item(
        "CYBERATTAQUE_ORG", "Cyberattaque confirmée", org="Org Location Connue", location=config.LOC_REUNION
    )

    def fake_resolve(org_key, organisation_raw, fetched_at, state):
        return org_enrichment.OrgEnrichmentRecord(
            Organisation_Key=org_key,
            Query_Name=organisation_raw,
            Matched_Name=organisation_raw,
            Match_Status=org_enrichment.MATCHED,
            Activity_Label="Information et communication",
            Headquarters_Department="75",
            Fetched_At=fetched_at,
        )

    monkeypatch.setattr(org_enrichment, "resolve", fake_resolve)
    state = ai.AiRunState(enabled=False, org_enrichment=org_enrichment.OrgEnrichmentState(enabled=True))
    spec = sources.by_id("CYBERATTAQUE_ORG")
    assert spec is not None
    entry = RawEntry(title=item.Title, published=item.Published_Date, summary="Incident confirmé.", url=item.URL)
    ai.qualify_item(item, entry, spec, state)
    assert item.Sector == config.SECTOR_TECH
    assert item.Location == config.LOC_REUNION
