from cyberwatch import config
from cyberwatch.model import Item
from cyberwatch.qualification import backfill_structured_source_sectors


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
