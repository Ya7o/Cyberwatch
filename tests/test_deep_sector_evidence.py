import csv

from cyberwatch import company_evidence, config
from sources.veillellm.deep_enrich_unknown_sectors import (
    apply_evidence,
    incident_urls,
    is_target_row,
    target_unknown_urls,
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
