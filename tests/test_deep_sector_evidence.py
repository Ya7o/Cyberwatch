import csv

from cyberwatch import company_evidence, config
from sources.veillellm.deep_enrich_unknown_sectors import (
    apply_evidence,
    candidate_official_urls,
    clear_sector_evidence,
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
        writer = csv.DictWriter(
            handle,
            fieldnames=["Source_ID", "Sector", "URL"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "Source_ID": "CYBERATTAQUE_ORG",
                "Sector": config.SECTOR_UNKNOWN,
                "URL": "https://www.cyberattaque.org/target/",
            }
        )
        writer.writerow(
            {
                "Source_ID": "CYBERATTAQUE_ORG",
                "Sector": config.SECTOR_TECH,
                "URL": "https://www.cyberattaque.org/already-known/",
            }
        )
        writer.writerow(
            {
                "Source_ID": "FRENCHBREACHES",
                "Sector": config.SECTOR_UNKNOWN,
                "URL": "https://frenchbreaches.com/other/",
            }
        )

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
        evidence_type="official_explicit_activity",
    )

    before, after = apply_evidence(row, evidence)

    assert before == config.SECTOR_UNKNOWN
    assert after == config.SECTOR_TECH
    assert row["sources"] == ["https://www.cyberattaque.org/exemple/"]
    assert row["sector_evidence_url"] == "https://www.exemple.fr/a-propos"
    assert row["sector_evidence_text"] == "éditeur de logiciels et services informatiques"
    assert row["sector_evidence_source"] == "exemple.fr"
    assert row["sector_evidence_type"] == "official_explicit_activity"
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


def test_strict_activity_rejects_page_status_construction_false_positive():
    raw = company_evidence.CompanyEvidence(
        sector=config.SECTOR_CONSTRUCTION,
        evidence_url="https://actionpopulaire.org/en-construction/",
        evidence_text=(
            "En construction - Action Zéro Pauvreté. Cette page est en construction."
        ),
        evidence_source="actionpopulaire.org",
    )
    assert strict_activity_evidence(raw) is None


def test_strict_activity_rejects_legal_finance_false_positive():
    raw = company_evidence.CompanyEvidence(
        sector=config.SECTOR_FINANCE,
        evidence_url="https://lions-france.org/mentions-legales",
        evidence_text="Capital de 15 000 euros. Crédits photos et banque d'images.",
        evidence_source="lions-france.org",
    )
    assert strict_activity_evidence(raw) is None


def test_strict_activity_accepts_and_reclassifies_explicit_business_phrase():
    raw = company_evidence.CompanyEvidence(
        sector=config.SECTOR_SERVICES,
        evidence_url="https://www.engie-green.fr/",
        evidence_text="ENGIE Green est fournisseur de services d'énergie renouvelable.",
        evidence_source="engie-green.fr",
    )

    strict = strict_activity_evidence(raw)

    assert strict is not None
    assert strict.sector == config.SECTOR_ENERGY
    assert "fournisseur de" in strict.evidence_text.lower()


def test_existing_v3_evidence_is_reaudited_offline():
    valid = {
        "secteur": config.SECTOR_TECH,
        "sector_evidence_url": "https://adobe.com/about",
        "sector_evidence_text": "éditeur de logiciels de création numérique",
        "sector_evidence_source": "adobe.com",
        "sector_evidence_type": "official_site",
    }
    invalid = {
        "secteur": config.SECTOR_FINANCE,
        "sector_evidence_url": "https://clcv.org/",
        "sector_evidence_text": "Crédit immobilier et assurance : vos droits.",
        "sector_evidence_source": "clcv.org",
        "sector_evidence_type": "official_site",
    }

    kept = strict_existing_evidence(valid)

    assert kept is not None
    assert kept.sector == config.SECTOR_TECH
    assert strict_existing_evidence(invalid) is None


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


def test_validate_candidate_requires_identity_and_explicit_activity(monkeypatch):
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


def test_validate_candidate_rejects_generic_keyword_on_official_page(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Action Populaire",
            "Cette page est en construction. Merci de revenir prochainement.",
            [],
            "https://actionpopulaire.org/en-construction/",
        ),
    )

    assert (
        validate_official_candidate(
            "Action Populaire", "https://actionpopulaire.org/en-construction/"
        )
        is None
    )


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
                evidence_type="official_explicit_activity",
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
