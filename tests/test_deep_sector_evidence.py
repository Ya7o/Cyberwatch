import csv

from cyberwatch import company_evidence, config
from sources.veillellm.deep_enrich_unknown_sectors import (
    apply_evidence,
    candidate_official_urls,
    incident_urls,
    is_target_row,
    research_official_evidence,
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


def test_target_row_matches_incident_url_without_using_sector_evidence_url():
    row = {
        "sources": ["https://www.cyberattaque.org/target/"],
        "sector_evidence_url": "https://example.com/about",
    }
    assert incident_urls(row) == ("https://www.cyberattaque.org/target/",)
    assert is_target_row(row, {"https://www.cyberattaque.org/target/"})
    assert not is_target_row(row, {"https://example.com/about"})


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
        evidence_type="official_site",
    )

    before, after = apply_evidence(row, evidence)

    assert before == config.SECTOR_UNKNOWN
    assert after == config.SECTOR_TECH
    assert row["sources"] == ["https://www.cyberattaque.org/exemple/"]
    assert row["sector_evidence_url"] == "https://www.exemple.fr/a-propos"
    assert row["sector_evidence_text"] == "éditeur de logiciels et services informatiques"
    assert row["sector_evidence_source"] == "exemple.fr"
    assert row["sector_evidence_type"] == "official_site"
    assert row["evolution"] == "enrichi"


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


def test_validate_candidate_requires_identity_and_activity(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Adobe — logiciels de création",
            "Adobe est un éditeur de logiciels et fournit des services cloud.",
            [],
            "https://www.adobe.com/fr/",
        ),
    )

    evidence = validate_official_candidate("Adobe", "https://adobe.com")

    assert evidence is not None
    assert evidence.sector == config.SECTOR_TECH
    assert evidence.evidence_source == "adobe.com"


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
                evidence_text="cabinet de conseil",
                evidence_source="exemple.fr",
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
