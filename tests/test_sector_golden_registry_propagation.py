from cyberwatch import config, sector_registry
from cyberwatch.model import Item
from scripts.enrich_sector_golden import _apply_authoritative_registry_rows


def _item(sector: str) -> Item:
    return Item(
        Item_ID="ITM-1",
        Source_ID="RANSOMWARE_LIVE",
        Organisation_Raw="Example Group",
        Organisation_Key="example group",
        Sector=sector,
    )


def _row(channel: str, sector: str, decision: str = sector_registry.DECISION_AUTO) -> dict:
    return {
        "Organisation_Key": "example group",
        "Sector": sector,
        "Decision": decision,
        "Evidence_Type": channel,
    }


def test_official_auto_overrides_stale_known_sector_for_targeted_closeout():
    item = _item(config.SECTOR_TRANSPORT)
    changed = _apply_authoritative_registry_rows(
        [item],
        [_row("official_subject_activity", config.SECTOR_CONSTRUCTION)],
        {"example group"},
    )
    assert changed == 1
    assert item.Sector == config.SECTOR_CONSTRUCTION


def test_manual_auto_overrides_stale_known_sector_for_targeted_closeout():
    item = _item(config.SECTOR_TRANSPORT)
    changed = _apply_authoritative_registry_rows(
        [item],
        [_row("manual_reference", config.SECTOR_CONSTRUCTION)],
        {"example group"},
    )
    assert changed == 1
    assert item.Sector == config.SECTOR_CONSTRUCTION


def test_structured_source_never_overrides_existing_known_sector_in_closeout_propagation():
    item = _item(config.SECTOR_CONSTRUCTION)
    changed = _apply_authoritative_registry_rows(
        [item],
        [_row("structured_source", config.SECTOR_TRANSPORT)],
        {"example group"},
    )
    assert changed == 0
    assert item.Sector == config.SECTOR_CONSTRUCTION


def test_non_auto_or_out_of_scope_rows_do_not_propagate():
    first = _item(config.SECTOR_TRANSPORT)
    second = Item(
        Item_ID="ITM-2",
        Source_ID="RANSOMWARE_LIVE",
        Organisation_Raw="Other Group",
        Organisation_Key="other group",
        Sector=config.SECTOR_TRANSPORT,
    )
    changed = _apply_authoritative_registry_rows(
        [first, second],
        [
            _row("official_subject_activity", config.SECTOR_CONSTRUCTION, sector_registry.DECISION_REVIEW),
            {
                "Organisation_Key": "other group",
                "Sector": config.SECTOR_CONSTRUCTION,
                "Decision": sector_registry.DECISION_AUTO,
                "Evidence_Type": "official_subject_activity",
            },
        ],
        {"example group"},
    )
    assert changed == 0
    assert first.Sector == config.SECTOR_TRANSPORT
    assert second.Sector == config.SECTOR_TRANSPORT
