from cyberwatch import ai, config
from cyberwatch.model import Item
from cyberwatch.rebuild_cache import reapply_cached_qualifications


def _row(**overrides):
    row = {
        "Item_ID": "ITM-1",
        "Source_ID": "FRENCHBREACHES",
        "Model": ai.DEFAULT_MODEL,
        "Prompt_Version": ai.PROMPT_VERSION,
        "Threat": "",
        "Threat_Confidence": "",
        "Sector": "Santé",
        "Sector_Confidence": "0.91",
        "Location": "",
        "Location_Confidence": "",
    }
    row.update(overrides)
    return row


def _item(**overrides):
    item = Item(
        Item_ID="ITM-1",
        Source_ID="FRENCHBREACHES",
        Threat=config.THREAT_LEAK,
        Sector=config.SECTOR_UNKNOWN,
        Location="France métropolitaine",
    )
    for key, value in overrides.items():
        setattr(item, key, value)
    return item


def test_rebuild_reuses_compatible_sector_cache_without_context_hash():
    item = _item()
    stats = reapply_cached_qualifications([item], [_row()])
    assert item.Sector == "Santé"
    assert stats["sector_restored"] == 1
    assert stats["cache_item_hits"] == 1


def test_rebuild_rejects_incompatible_prompt_version():
    item = _item()
    stats = reapply_cached_qualifications(
        [item], [_row(Prompt_Version="old-prompt")]
    )
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["sector_restored"] == 0
    assert stats["cache_item_misses"] == 1


def test_rebuild_never_overwrites_known_value():
    item = _item(Sector="Sport")
    stats = reapply_cached_qualifications([item], [_row(Sector="Santé")])
    assert item.Sector == "Sport"
    assert stats["sector_restored"] == 0


def test_rebuild_rejects_low_confidence_cache():
    item = _item()
    stats = reapply_cached_qualifications([item], [_row(Sector_Confidence="0.2")])
    assert item.Sector == config.SECTOR_UNKNOWN
    assert stats["sector_restored"] == 0
