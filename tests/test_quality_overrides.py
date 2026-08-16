from cyberwatch import config, normalize, qualification, quality_overrides
from cyberwatch.dedup import MERGE, build_incidents, decide_merge


def _override(**values):
    row = {
        "Threat": "",
        "Sector": "",
        "Location": "",
        "Reason": "audit ChatGPT",
        "Evidence_URL": "https://example.test/evidence",
    }
    row.update(values)
    return row


def test_load_overrides_rejects_unknown_taxonomy_value(tmp_path):
    path = tmp_path / "quality_overrides.csv"
    path.write_text(
        "Item_ID,Threat,Sector,Location,Reason,Evidence_URL\n"
        "ITEM-1,,Secteur inventé,,audit,https://example.test\n",
        encoding="utf-8",
    )

    try:
        quality_overrides.load_overrides(path)
    except ValueError as exc:
        assert "Sector" in str(exc)
    else:
        raise AssertionError("une valeur hors taxonomie doit être refusée")


def test_load_overrides_rejects_duplicate_item_id(tmp_path):
    path = tmp_path / "quality_overrides.csv"
    path.write_text(
        "Item_ID,Threat,Sector,Location,Reason,Evidence_URL\n"
        f"ITEM-1,,{config.SECTOR_HEALTH},,audit,\n"
        f"ITEM-1,,{config.SECTOR_FINANCE},,audit,\n",
        encoding="utf-8",
    )

    try:
        quality_overrides.load_overrides(path)
    except ValueError as exc:
        assert "dupliqué" in str(exc)
    else:
        raise AssertionError("un Item_ID dupliqué doit être refusé")


def test_apply_overrides_changes_only_non_empty_fields(make_item):
    item = make_item(
        threat=config.THREAT_LEAK,
        sector=config.SECTOR_HEALTH,
        location=config.LOC_REUNION,
    )
    item_id = item.Item_ID

    changes = quality_overrides.apply_overrides(
        [item],
        {
            item.Item_ID: _override(
                Sector=config.SECTOR_FINANCE,
                Location=config.LOC_FRANCE,
            )
        },
    )

    assert item.Item_ID == item_id
    assert item.Threat == config.THREAT_LEAK
    assert item.Sector == config.SECTOR_FINANCE
    assert item.Location == config.LOC_FRANCE
    assert changes["quality_override_items"] == 1
    assert changes["quality_override_threat"] == 0
    assert changes["quality_override_sector"] == 1
    assert changes["quality_override_location"] == 1


def test_qualify_applies_override_after_source_stabilization(monkeypatch, make_item):
    item = make_item(source="FRENCHBREACHES", threat=config.THREAT_INTRUSION)
    item_id = item.Item_ID
    overrides = {
        item.Item_ID: _override(Threat=config.THREAT_PHISHING)
    }
    monkeypatch.setattr(quality_overrides, "load_overrides", lambda path=None: overrides)

    report = qualification.qualify([item])

    assert report.items[0].Item_ID == item_id
    assert report.items[0].Threat == config.THREAT_PHISHING
    assert report.incidents[0].Menace == config.THREAT_PHISHING
    assert report.changes["quality_override_threat"] == 1


def test_orphan_override_does_not_block_snapshot(make_item):
    item = make_item()
    before = item.to_row()

    changes = quality_overrides.apply_overrides(
        [item],
        {"ITEM-ABSENT": _override(Sector=config.SECTOR_FINANCE)},
    )

    assert item.to_row() == before
    assert changes["quality_override_items"] == 0


def test_new_alias_deduplicates_historical_items_without_changing_item_ids(
    monkeypatch, make_item
):
    left = make_item(
        source="SOURCE_A",
        org="Alpha Group",
        published="2026-03-01",
        url="https://a.test/1",
    )
    right = make_item(
        source="SOURCE_B",
        org="Alpha France",
        published="2026-03-02",
        url="https://b.test/1",
    )
    left_id, right_id = left.Item_ID, right.Item_ID
    assert left.Organisation_Key != right.Organisation_Key

    monkeypatch.setitem(normalize.ORGANISATION_ALIASES, "alpha france", "alpha group")

    decision = decide_merge(left, right)
    incidents = build_incidents([left, right])

    assert decision.action == MERGE
    assert decision.reason_code == "INCIDENT_MERGE_ALIAS"
    assert len(incidents) == 1
    assert incidents[0].Items_Count == 2
    assert left.Item_ID == left_id
    assert right.Item_ID == right_id
