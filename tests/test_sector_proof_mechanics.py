from cyberwatch import config, qualification, qualification_policy
from cyberwatch.model import Item
from cyberwatch.qualification_policy import QualificationCandidate


def _item(sector: str) -> Item:
    return Item(
        Item_ID="ITM-1",
        Source_ID="RANSOMWARE_LIVE",
        Organisation_Raw="Example Group",
        Organisation_Key="example group",
        Sector=sector,
    )


def _official_row(sector: str, *, via: str = "official_subject_activity", activity: str | None = None) -> dict:
    return {
        "Organisation_Key": "example group",
        "Query_Name": "Example Group",
        "Matched_Name": "Example Group",
        "Match_Status": "MATCHED",
        "Validated_Sector": sector,
        "Validated_Via": via,
        "Evidence_URL": "https://example.org/activities",
        "Activity_Label": activity or "Example Group est leader européen du BTP et des concessions.",
    }


def test_official_subject_activity_overrides_stale_structured_sector():
    item = _item(config.SECTOR_TRANSPORT)
    changed, provenance = qualification.apply_official_subject_activity_sectors(
        [item], [_official_row(config.SECTOR_CONSTRUCTION)]
    )
    assert changed == 1
    assert item.Sector == config.SECTOR_CONSTRUCTION
    assert provenance[0]["Origin"] == "OFFICIAL_SUBJECT_ACTIVITY"
    assert "https://example.org/activities" in provenance[0]["Evidence"]


def test_weak_official_text_does_not_override_even_if_cache_says_validated():
    item = _item(config.SECTOR_TRANSPORT)
    changed, provenance = qualification.apply_official_subject_activity_sectors(
        [item], [_official_row(config.SECTOR_CONSTRUCTION, activity="Example Group propose des services à ses clients.")]
    )
    assert changed == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_TRANSPORT


def test_invalid_or_non_official_cache_evidence_does_not_override():
    item = _item(config.SECTOR_TRANSPORT)
    changed, provenance = qualification.apply_official_subject_activity_sectors(
        [item], [_official_row(config.SECTOR_CONSTRUCTION, via="deterministic")]
    )
    assert changed == 0
    assert provenance == []
    assert item.Sector == config.SECTOR_TRANSPORT


def test_proof_precedence_is_manual_then_official_then_structured():
    candidates = [
        QualificationCandidate("ITM-1", "RANSOMWARE_LIVE", "Sector", config.SECTOR_TRANSPORT, "STRUCTURED_SOURCE"),
        QualificationCandidate("ITM-1", "RANSOMWARE_LIVE", "Sector", config.SECTOR_CONSTRUCTION, "OFFICIAL_SUBJECT_ACTIVITY"),
    ]
    assert qualification_policy.choose_winner(candidates).value == config.SECTOR_CONSTRUCTION

    candidates.append(
        QualificationCandidate("ITM-1", "RANSOMWARE_LIVE", "Sector", config.SECTOR_FINANCE, "MANUAL_REFERENCE")
    )
    assert qualification_policy.choose_winner(candidates).value == config.SECTOR_FINANCE
