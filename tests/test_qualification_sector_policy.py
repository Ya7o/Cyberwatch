from cyberwatch import config
from cyberwatch.model import Item
from cyberwatch.qualification import neutralize_sector_fallback


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


def test_sector_application_is_neutralized_and_kept_as_diagnostic():
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
    assert provenance[0]["Decision"] == "REJECTED_POLICY_DISABLED"
    assert provenance[0]["Confidence"] == ""
    assert "acteur de santé publique" in provenance[0]["Evidence"]


def test_location_and_threat_applications_are_not_changed():
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


def test_unexpected_later_sector_change_is_protected():
    item = _item(Sector=config.SECTOR_TECH)
    row = _sector_applied(Final_Value=config.SECTOR_HEALTH)
    changes = {"llm_sector_fallback": 1, "llm_sector_rejected": 0}

    assert neutralize_sector_fallback([item], changes, [row]) == 0
    assert item.Sector == config.SECTOR_TECH
    assert row["Decision"] == "APPLIED"
    assert changes["llm_sector_fallback"] == 1
    assert changes["llm_sector_policy_rejected"] == 0
