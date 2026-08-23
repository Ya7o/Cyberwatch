from cyberwatch import config, qualification
from cyberwatch.model import Item
from cyberwatch.qualification import (
    backfill_structured_source_sectors,
    neutralize_sector_fallback,
)


def _item(**kwargs):
    values = dict(
        Item_ID="ITEM-1",
        Source_ID="CYBERATTAQUE_ORG",
        Published_Date="2026-06-01",
        Organisation_Raw="Exemple SA",
        Organisation_Key="exemple sa",
        Threat=config.THREAT_LEAK,
        Sector=config.SECTOR_HEALTH,
        Location=config.LOC_FRANCE,
        URL="https://www.cyberattaque.org/exemple/",
    )
    values.update(kwargs)
    return Item(**values)


def _sector_applied(**kwargs):
    values = {
        "Item_ID": "ITEM-1",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Field": "Sector",
        "Previous_Value": config.SECTOR_UNKNOWN,
        "Candidate_Value": config.SECTOR_HEALTH,
        "Final_Value": config.SECTOR_HEALTH,
        "Origin": "LLM_SOURCE_FALLBACK",
        "Confidence": "HIGH",
        "Evidence": "https://exemple.fr | acteur de santé publique",
        "Match_Strategy": "source_url",
        "Decision": "APPLIED",
    }
    values.update(kwargs)
    return values


def test_sector_application_is_neutralized_when_policy_disabled(monkeypatch):
    monkeypatch.setattr(qualification, "_SECTOR_FALLBACK_AUTO_APPLY", False)
    item = _item()
    provenance = [_sector_applied()]
    changes = {"llm_sector_fallback": 1, "llm_sector_rejected": 4}

    count = neutralize_sector_fallback([item], changes, provenance)

    assert count == 1
    assert item.Sector == config.SECTOR_UNKNOWN
    assert changes["llm_sector_fallback"] == 0
    assert changes["llm_sector_rejected"] == 5
    assert changes["llm_sector_policy_rejected"] == 1
    assert provenance[0]["Candidate_Value"] == config.SECTOR_HEALTH
    assert provenance[0]["Final_Value"] == config.SECTOR_UNKNOWN
    assert provenance[0]["Decision"] == "REJECTED_NO_STRONG_EVIDENCE"
    assert provenance[0]["Confidence"] == ""
    assert "acteur de santé publique" in provenance[0]["Evidence"]


def test_sector_application_is_kept_when_policy_enabled(monkeypatch):
    monkeypatch.setattr(qualification, "_SECTOR_FALLBACK_AUTO_APPLY", True)
    item = _item()
    provenance = [_sector_applied()]
    changes = {"llm_sector_fallback": 1, "llm_sector_rejected": 4}

    count = neutralize_sector_fallback([item], changes, provenance)

    assert count == 0
    assert item.Sector == config.SECTOR_HEALTH
    assert changes["llm_sector_fallback"] == 1
    assert changes["llm_sector_rejected"] == 4
    assert "llm_sector_policy_rejected" not in changes
    assert provenance[0]["Decision"] == "APPLIED"


def test_location_and_threat_applications_are_not_changed(monkeypatch):
    monkeypatch.setattr(qualification, "_SECTOR_FALLBACK_AUTO_APPLY", False)
    item = _item()
    rows = [
        {
            **_sector_applied(),
            "Field": "Location",
            "Previous_Value": config.LOC_INCONNU,
            "Candidate_Value": config.LOC_FRANCE,
            "Final_Value": config.LOC_FRANCE,
        },
        {
            **_sector_applied(),
            "Field": "Threat",
            "Previous_Value": config.THREAT_UNKNOWN,
            "Candidate_Value": config.THREAT_LEAK,
            "Final_Value": config.THREAT_LEAK,
        },
    ]
    changes = {"llm_sector_fallback": 0, "llm_sector_rejected": 0}

    assert neutralize_sector_fallback([item], changes, rows) == 0
    assert item.Sector == config.SECTOR_HEALTH
    assert all(row["Decision"] == "APPLIED" for row in rows)
    assert changes["llm_sector_policy_rejected"] == 0


def test_unexpected_later_sector_change_is_protected(monkeypatch):
    monkeypatch.setattr(qualification, "_SECTOR_FALLBACK_AUTO_APPLY", False)
    item = _item(Sector=config.SECTOR_TECH)
    row = _sector_applied(Final_Value=config.SECTOR_HEALTH)
    changes = {"llm_sector_fallback": 1, "llm_sector_rejected": 0}

    assert neutralize_sector_fallback([item], changes, [row]) == 0
    assert item.Sector == config.SECTOR_TECH
    assert row["Decision"] == "APPLIED"
    assert changes["llm_sector_fallback"] == 1
    assert changes["llm_sector_policy_rejected"] == 0


def test_structured_ransomware_sector_backfill_uses_closed_mapping():
    item = _item(
        Item_ID="RANSOM-1",
        Source_ID="RANSOMWARE_LIVE",
        Sector=config.SECTOR_UNKNOWN,
    )
    rows = [
        {
            "Item_ID": "RANSOM-1",
            "Source_ID": "RANSOMWARE_LIVE",
            "Source_Sector_Raw": "Manufacturing",
        }
    ]

    assert backfill_structured_source_sectors([item], rows) == 1
    assert item.Sector == config.SECTOR_INDUSTRY


def test_structured_ransomware_sector_backfill_never_overwrites_known_sector():
    item = _item(
        Item_ID="RANSOM-2",
        Source_ID="RANSOMWARE_LIVE",
        Sector=config.SECTOR_HEALTH,
    )
    rows = [
        {
            "Item_ID": "RANSOM-2",
            "Source_ID": "RANSOMWARE_LIVE",
            "Source_Sector_Raw": "Manufacturing",
        }
    ]

    assert backfill_structured_source_sectors([item], rows) == 0
    assert item.Sector == config.SECTOR_HEALTH


def test_structured_ransomware_sector_backfill_rejects_unmapped_and_ambiguous_raw_values():
    unmapped = _item(
        Item_ID="RANSOM-3",
        Source_ID="RANSOMWARE_LIVE",
        Sector=config.SECTOR_UNKNOWN,
    )
    ambiguous = _item(
        Item_ID="RANSOM-4",
        Source_ID="RANSOMWARE_LIVE",
        Sector=config.SECTOR_UNKNOWN,
    )
    rows = [
        {
            "Item_ID": "RANSOM-3",
            "Source_ID": "RANSOMWARE_LIVE",
            "Source_Sector_Raw": "Hospitality",
        },
        {
            "Item_ID": "RANSOM-4",
            "Source_ID": "RANSOMWARE_LIVE",
            "Source_Sector_Raw": "Manufacturing",
        },
        {
            "Item_ID": "RANSOM-4",
            "Source_ID": "RANSOMWARE_LIVE",
            "Source_Sector_Raw": "Healthcare",
        },
    ]

    assert backfill_structured_source_sectors([unmapped, ambiguous], rows) == 0
    assert unmapped.Sector == config.SECTOR_UNKNOWN
    assert ambiguous.Sector == config.SECTOR_UNKNOWN


def test_structured_ransomware_sector_backfill_ignores_other_sources():
    item = _item(
        Item_ID="OTHER-1",
        Source_ID="CYBERATTAQUE_ORG",
        Sector=config.SECTOR_UNKNOWN,
    )
    rows = [
        {
            "Item_ID": "OTHER-1",
            "Source_ID": "RANSOMWARE_LIVE",
            "Source_Sector_Raw": "Manufacturing",
        }
    ]

    assert backfill_structured_source_sectors([item], rows) == 0
    assert item.Sector == config.SECTOR_UNKNOWN
