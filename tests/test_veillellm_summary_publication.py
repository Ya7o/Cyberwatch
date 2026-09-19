from cyberwatch import site
from cyberwatch.normalize import organisation_key


def test_regional_snapshot_summary_is_not_published_as_a_card_headline():
    regional = site._regional_admission_by_key()
    key = (organisation_key("EPF Réunion / VALGO"), "2026-02-19")

    assert key in regional
    assert regional[key]["admission"] == "ACCEPTED"
    assert regional[key]["summary"]

    row = {
        "id": "INC-EPF",
        "org": "EPF Réunion / VALGO",
        "date": "2026-02-19",
        "sources": ["VEILLE_LLM"],
    }
    site._decorate_admission([row])

    assert row["admission"] == "ACCEPTED"
    assert "summary" not in row
    assert "summary" not in site._public_fields(row, site._INCIDENT_PUBLIC_FIELDS)


def test_regional_snapshot_summary_is_published_for_candidate():
    regional = site._regional_admission_by_key()
    key = (organisation_key("Commune de Saint-Leu"), "2026-02-04")

    assert key in regional
    assert regional[key]["admission"] == "CANDIDATE"
    assert regional[key]["summary"]

    row = {
        "id": "INC-SAINT-LEU",
        "org": "Commune de Saint-Leu",
        "date": "2026-02-04",
        "sources": ["VEILLE_LLM"],
    }
    site._decorate_admission([row])

    assert row["admission"] == "CANDIDATE"
    assert "summary" not in row
    assert row["admission_reason"] == regional[key]["admission_reason"]
