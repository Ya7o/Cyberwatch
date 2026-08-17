from cyberwatch import config
from cyberwatch.model import Item
from cyberwatch.sector_fallback_migration import restore_legacy_sector_fallbacks


def _item(**kwargs):
    values = dict(
        Item_ID="ITEM-1",
        Source_ID="CYBERATTAQUE_ORG",
        Published_Date="2026-04-03",
        Organisation_Raw="Adobe",
        Organisation_Key="adobe",
        Threat=config.THREAT_LEAK,
        Sector=config.SECTOR_CONSTRUCTION,
        Location=config.LOC_INCONNU,
        URL="https://www.cyberattaque.org/adobe",
    )
    values.update(kwargs)
    return Item(**values)


def _row(**kwargs):
    values = dict(
        Item_ID="ITEM-1",
        Source_ID="CYBERATTAQUE_ORG",
        Field="Sector",
        Previous_Value=config.SECTOR_UNKNOWN,
        Candidate_Value=config.SECTOR_CONSTRUCTION,
        Final_Value=config.SECTOR_CONSTRUCTION,
        Origin="LLM_SOURCE_FALLBACK",
        Decision="APPLIED",
    )
    values.update(kwargs)
    return values


def test_restores_legacy_applied_sector_to_unknown():
    item = _item()
    assert restore_legacy_sector_fallbacks([item], [_row()]) == 1
    assert item.Sector == config.SECTOR_UNKNOWN


def test_restore_is_idempotent():
    item = _item()
    rows = [_row()]
    assert restore_legacy_sector_fallbacks([item], rows) == 1
    assert restore_legacy_sector_fallbacks([item], rows) == 0
    assert item.Sector == config.SECTOR_UNKNOWN


def test_later_different_correction_is_protected():
    item = _item(Sector=config.SECTOR_TECH)
    assert restore_legacy_sector_fallbacks([item], [_row()]) == 0
    assert item.Sector == config.SECTOR_TECH


def test_rejected_or_non_fallback_provenance_is_ignored():
    for row in (
        _row(Decision="REJECTED_NO_STRONG_EVIDENCE"),
        _row(Origin="MANUAL_REFERENCE"),
        _row(Field="Location"),
    ):
        item = _item()
        assert restore_legacy_sector_fallbacks([item], [row]) == 0
        assert item.Sector == config.SECTOR_CONSTRUCTION


def test_only_unknown_origin_values_are_eligible():
    item = _item()
    row = _row(Previous_Value=config.SECTOR_SERVICES)
    assert restore_legacy_sector_fallbacks([item], [row]) == 0
    assert item.Sector == config.SECTOR_CONSTRUCTION


def test_other_item_id_is_ignored():
    item = _item()
    assert restore_legacy_sector_fallbacks([item], [_row(Item_ID="ITEM-2")]) == 0
    assert item.Sector == config.SECTOR_CONSTRUCTION
