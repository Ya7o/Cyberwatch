import csv

from cyberwatch import company_evidence, config
from sources.veillellm.deep_enrich_unknown_sectors import (
    apply_evidence,
    candidate_official_urls,
    classify_primary_activity,
    clear_sector_evidence,
    extract_primary_activity_description,
    incident_urls,
    is_target_row,
    research_official_evidence,
    strict_activity_evidence,
    strict_existing_evidence,
    target_unknown_urls,
    validate_official_candidate,
)


def test_target_unknown_urls_only_selects_unknown_sector_for_source(tmp_path):
    path = tmp_path / "items.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["Source_ID", "Sector", "URL"])
        writer.writeheader()
        writer.writerow({
            "Source_ID": "CYBERATTAQUE_ORG",
            "Sector": config.SECTOR_UNKNOWN,
            "URL": "https://www.cyberattaque.org/target/",
        })
        writer.writerow({
            "Source_ID": "CYBERATTAQUE_ORG",
            "Sector": config.SECTOR_TECH,
            "URL": "https://www.cyberattaque.org/already-known/",
        })
        writer.writerow({
            "Source_ID": "FRENCHBREACHES",
            "Sector": config.SECTOR_UNKNOWN,
            "URL": "https://frenchbreaches.com/other/",
        })

    assert target_unknown_urls("CYBERATTAQUE_ORG", path) == {
        "https://www.cyberattaque.org/target/"
    }


def test_target_row_matches_incident_url_and_reaudits_existing_evidence():
    plain = {"sources": ["https://www.cyberattaque.org/target/"]}
    existing = {
        "sources": ["https://www.cyberattaque.org/already-known/"],
        "sector_evidence_url": "https://example.com/about",
        "sector_evidence_text": "éditeur de logiciels",
    }
    assert incident_urls(plain) == ("https://www.cyberattaque.org/target/",)
    assert is_target_row(plain, {"https://www.cyberattaque.org/target/"})
    assert not is_target_row(plain, {"https://example.com/about"})
    assert is_target_row(existing, set())


def test_apply_evidence_keeps_incident_sources_separate():
    row = {
        "organisation": "Exemple",
        "secteur": config.SECTOR_UNKNOWN,
        "sources": ["https://www.cyberattaque.org/exemple/"],
        "evolution": "inchange",
    }
    evidence = company_evidence.CompanyEvidence(
        sector=config.SECTOR_TECH,
        evidence_url="https://www.exemple.fr/a-propos",
        evidence_text="éditeur de logiciels et services informatiques",
        evidence_source="exemple.fr",
        evidence_type="official_primary_activity",
    )

    before, after = apply_evidence(row, evidence)

    assert before == config.SECTOR_UNKNOWN
    assert after == config.SECTOR_TECH
    assert row["sources"] == ["https://www.cyberattaque.org/exemple/"]
    assert row["sector_evidence_url"] == "https://www.exemple.fr/a-propos"
    assert row["sector_evidence_text"] == "éditeur de logiciels et services informatiques"
    assert row["sector_evidence_source"] == "exemple.fr"
    assert row["sector_evidence_type"] == "official_primary_activity"
    assert row["evolution"] == "enrichi"


def test_clear_sector_evidence_neutralises_old_candidate():
    row = {
        "secteur": config.SECTOR_FINANCE,
        "sector_evidence_url": "https://lions-france.org/",
        "sector_evidence_text": "capital de 15 000 euros et banque d'images",
        "sector_evidence_source": "lions-france.org",
        "sector_evidence_type": "official_site",
    }
    clear_sector_evidence(row)
    assert row["secteur"] == config.SECTOR_UNKNOWN
    assert not any(key.startswith("sector_evidence_") for key in row)


def test_primary_activity_rejects_page_status_and_legal_noise():
    assert extract_primary_activity_description(
        "Cette page est en construction."
    ) == ""
    assert extract_primary_activity_description(
        "Capital social et banque d'images."
    ) == ""


def test_primary_activity_rejects_secondary_training_function():
    # Air Corsica / Optic 2000 / Exclusive Networks ont montré que ce groupe
    # nominal décrit souvent une fonction interne, pas le métier de la victime.
    assert extract_primary_activity_description("Notre centre de formation") == ""


def test_primary_activity_rejects_website_hosting_and_platform_boilerplate():
    assert extract_primary_activity_description(
        "fournisseur de l'hébergement du site www.exemple.fr"
    ) == ""
    assert extract_primary_activity_description(
        "Éditeur de la plateforme Directeur de la publication"
    ) == ""


def test_primary_activity_accepts_core_business_formulations():
    assert extract_primary_activity_description(
        "Fabricant de tissus techniques pour vêtements professionnels"
    ).lower().startswith("fabricant de")
    assert extract_primary_activity_description(
        "Spécialisée dans l'ensemble des métiers du bâtiment"
    ).lower().startswith("spécialisée dans")


def test_transition_energetique_beats_foncier_keyword():
    activity = (
        "acteur de la transition énergétique tout en optimisant l'exploitation "
        "de votre foncier"
    )
    assert classify_primary_activity(activity) == config.SECTOR_ENERGY


def test_strict_activity_accepts_and_reclassifies_primary_business_phrase():
    raw = company_evidence.CompanyEvidence(
        sector=config.SECTOR_SERVICES,
        evidence_url="https://www.engie-green.fr/",
        evidence_text=(
            "ENGIE Green est acteur de la transition énergétique tout en optimisant "
            "l'exploitation de votre foncier."
        ),
        evidence_source="engie-green.fr",
    )
    strict = strict_activity_evidence(raw)
    assert strict is not None
    assert strict.sector == config.SECTOR_ENERGY
    assert strict.evidence_type == "official_primary_activity"


def test_existing_evidence_is_reaudited_offline():
    valid = {
        "secteur": config.SECTOR_TECH,
        "sector_evidence_url": "https://adobe.com/about",
        "sector_evidence_text": "éditeur de logiciels de création numérique",
        "sector_evidence_source": "adobe.com",
        "sector_evidence_type": "official_explicit_activity",
    }
    secondary = {
        "secteur": config.SECTOR_EDUCATION,
        "sector_evidence_url": "https://www.aircorsica.com/la-compagnie/",
        "sector_evidence_text": "Centre de Formation",
        "sector_evidence_source": "aircorsica.com",
        "sector_evidence_type": "official_explicit_activity",
    }
    technical = {
        "secteur": config.SECTOR_SERVICES,
        "sector_evidence_url": "https://www.gites-de-france.com/mentions-legales",
        "sector_evidence_text": "fournisseur de l'hébergement du site www",
        "sector_evidence_source": "gites-de-france.com",
        "sector_evidence_type": "official_explicit_activity",
    }

    kept = strict_existing_evidence(valid)

    assert kept is not None
    assert kept.sector == config.SECTOR_TECH
    assert strict_existing_evidence(secondary) is None
    assert strict_existing_evidence(technical) is None


def test_candidate_urls_extract_explicit_domain_and_guess_common_domains():
    row = {
        "organisation": "France-Terrain.com",
        "impact_connu": "La société utilise son portail France-Terrain.com.",
        "synthese": "",
    }
    candidates = candidate_official_urls(row)
    assert candidates[0] == "https://france-terrain.com"
    assert any(url.endswith(".fr") for url in candidates)


def test_candidate_urls_can_probe_single_name_without_search_engine():
    candidates = candidate_official_urls({"organisation": "Adobe"})
    assert "https://adobe.fr" in candidates
    assert "https://adobe.com" in candidates


def test_validate_candidate_rejects_domain_unrelated_to_organisation(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (_ for _ in ()).throw(AssertionError("page ne doit pas être appelée")),
    )
    assert validate_official_candidate("Adobe", "https://unrelated-example.com") is None


def test_validate_candidate_requires_identity_and_primary_activity(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Adobe — création numérique",
            "Adobe est un éditeur de logiciels et fournit des services cloud.",
            [],
            "https://www.adobe.com/fr/",
        ),
    )
    evidence = validate_official_candidate("Adobe", "https://adobe.com")
    assert evidence is not None
    assert evidence.sector == config.SECTOR_TECH
    assert evidence.evidence_source == "adobe.com"
    assert "éditeur de" in evidence.evidence_text.lower()


def test_validate_candidate_rejects_secondary_activity_on_official_page(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Air Corsica — la compagnie",
            "Air Corsica dispose de son propre Centre de Formation.",
            [],
            "https://www.aircorsica.com/la-compagnie/",
        ),
    )
    assert validate_official_candidate(
        "Air Corsica", "https://aircorsica.com"
    ) is None


def test_research_stops_on_first_validated_candidate(monkeypatch):
    monkeypatch.setattr(
        "sources.veillellm.deep_enrich_unknown_sectors.candidate_official_urls",
        lambda row: ("https://exemple.fr", "https://exemple.com"),
    )
    calls = []

    def validate(org, url):
        calls.append(url)
        if url.endswith(".fr"):
            return company_evidence.CompanyEvidence(
                sector=config.SECTOR_SERVICES,
                evidence_url=url,
                evidence_text="spécialisé dans le conseil aux entreprises",
                evidence_source="exemple.fr",
                evidence_type="official_primary_activity",
            )
        return None

    monkeypatch.setattr(
        "sources.veillellm.deep_enrich_unknown_sectors.validate_official_candidate",
        validate,
    )
    evidence, tested = research_official_evidence({"organisation": "Exemple"})
    assert evidence is not None
    assert tested == 1
    assert calls == ["https://exemple.fr"]
