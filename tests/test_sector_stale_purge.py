from scripts import enrich_sector_queue
from cyberwatch import config, store


def test_golden_purge_invalidates_only_mismatching_sector_and_cache(tmp_path, monkeypatch, make_item):
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")
    monkeypatch.setattr(
        enrich_sector_queue,
        "_golden_expected_sector_by_key",
        lambda: {"planity": config.SECTOR_TECH, "keep cool": config.SECTOR_SPORT},
    )
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    monkeypatch.setenv("SECTOR_PURGE_GOLDEN_MISMATCHES", "1")

    planity = make_item(org="Planity", sector=config.SECTOR_RETAIL)
    keepcool = make_item(org="Keep Cool", sector=config.SECTOR_SPORT)
    cache = {
        planity.Organisation_Key: {
            "Organisation_Key": planity.Organisation_Key,
            "Validated_Sector": config.SECTOR_RETAIL,
            "Validated_Via": "deterministic",
            "Activity_Label": "Commerce ; réparation d'automobiles et de motocycles",
            "Fetched_At": "2026-08-19T12:00:00+00:00",
            "Match_Status": "MATCHED",
        },
        keepcool.Organisation_Key: {
            "Organisation_Key": keepcool.Organisation_Key,
            "Validated_Sector": config.SECTOR_SPORT,
            "Validated_Via": "official_subject_activity",
            "Activity_Label": "salle de sport",
            "Fetched_At": "2026-08-19T12:00:00+00:00",
            "Match_Status": "MATCHED",
        },
    }

    keys, stats = enrich_sector_queue._purge_golden_mismatches(
        [planity, keepcool], cache, "golden-only"
    )

    assert keys == {planity.Organisation_Key}
    assert planity.Sector == config.SECTOR_UNKNOWN
    assert keepcool.Sector == config.SECTOR_SPORT
    assert cache[planity.Organisation_Key]["Validated_Sector"] == ""
    assert cache[planity.Organisation_Key]["Validated_Via"] == ""
    assert cache[planity.Organisation_Key]["Activity_Label"] == ""
    assert cache[planity.Organisation_Key]["Fetched_At"] == ""
    assert stats == {
        "purged_organisations": 1,
        "purged_items": 1,
        "purged_cache_rows": 1,
    }


def test_sector_only_never_purges_known_values(tmp_path, monkeypatch, make_item):
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")
    monkeypatch.setattr(
        enrich_sector_queue,
        "_golden_expected_sector_by_key",
        lambda: {"planity": config.SECTOR_TECH},
    )
    item = make_item(org="Planity", sector=config.SECTOR_RETAIL)

    keys, stats = enrich_sector_queue._purge_golden_mismatches([item], {}, "sector-only")

    assert keys == set()
    assert item.Sector == config.SECTOR_RETAIL
    assert stats["purged_items"] == 0


def test_explicit_target_limits_purge_scope(tmp_path, monkeypatch, make_item):
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")
    monkeypatch.setattr(
        enrich_sector_queue,
        "_golden_expected_sector_by_key",
        lambda: {"planity": config.SECTOR_TECH, "1001coques": config.SECTOR_RETAIL},
    )
    monkeypatch.setenv("SECTOR_ENRICHMENT_TARGET_KEYS", "planity")
    planity = make_item(org="Planity", sector=config.SECTOR_RETAIL)
    coques = make_item(org="1001Coques", sector=config.SECTOR_TECH)

    keys, _stats = enrich_sector_queue._purge_golden_mismatches(
        [planity, coques], {}, "golden-only"
    )

    assert keys == {planity.Organisation_Key}
    assert planity.Sector == config.SECTOR_UNKNOWN
    assert coques.Sector == config.SECTOR_TECH


def test_known_golden_target_is_added_even_when_absent_from_unknown_queue(make_item):
    item = make_item(org="Eiffage", sector=config.SECTOR_TRANSPORT)
    rows = enrich_sector_queue._augment_queue_with_targets([], [item], {item.Organisation_Key})

    assert len(rows) == 1
    assert rows[0]["Organisation_Key"] == item.Organisation_Key
    assert rows[0]["Organisation"] == "Eiffage"
    assert rows[0]["Category"] == "GOLDEN_REEVALUATION"
