from scripts import enrich_sector_golden, enrich_sector_queue
from cyberwatch import config, org_enrichment, store


def test_current_mismatch_keys_only_returns_wrong_golden_items(monkeypatch, make_item):
    monkeypatch.setattr(
        enrich_sector_queue,
        "_golden_expected_sector_by_key",
        lambda: {"planity": config.SECTOR_TECH, "keep cool": config.SECTOR_SPORT},
    )
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    planity = make_item(org="Planity", sector=config.SECTOR_RETAIL)
    keepcool = make_item(org="Keep Cool", sector=config.SECTOR_SPORT)

    assert enrich_sector_golden._current_mismatch_keys([planity, keepcool]) == {
        planity.Organisation_Key
    }


def test_golden_runner_purges_persists_and_forces_exact_targets(tmp_path, monkeypatch, make_item):
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")
    monkeypatch.setattr(store, "ORG_ENRICHMENT_CACHE_CSV", tmp_path / "org_enrichment_cache.csv")
    monkeypatch.setattr(
        enrich_sector_queue,
        "_golden_expected_sector_by_key",
        lambda: {"planity": config.SECTOR_TECH},
    )
    monkeypatch.delenv("SECTOR_ENRICHMENT_TARGET_KEYS", raising=False)
    monkeypatch.setenv("SECTOR_PURGE_GOLDEN_MISMATCHES", "1")

    planity = make_item(org="Planity", sector=config.SECTOR_RETAIL)
    store.save_items([planity])
    store.save_org_enrichment_cache([
        {
            "Organisation_Key": planity.Organisation_Key,
            "Query_Name": "Planity",
            "Matched_Name": "PLANITY",
            "Company_ID": "821511128",
            "Activity_Code": "47.91A",
            "Activity_Label": "Commerce ; réparation d'automobiles et de motocycles",
            "Evidence_Source": "recherche-entreprises.api.gouv.fr",
            "Evidence_URL": "https://recherche-entreprises.api.gouv.fr/search?q=821511128",
            "Match_Status": org_enrichment.MATCHED,
            "Fetched_At": "2026-08-19T12:00:00+00:00",
            "Validated_Sector": config.SECTOR_RETAIL,
            "Validated_Via": "deterministic",
            "Cache_Version": org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
        }
    ])

    observed = {}

    def fake_main():
        observed["mode"] = __import__("os").environ.get("SECTOR_ENRICHMENT_MODE")
        observed["targets"] = __import__("os").environ.get("SECTOR_ENRICHMENT_TARGET_KEYS")
        observed["purge"] = __import__("os").environ.get("SECTOR_PURGE_GOLDEN_MISMATCHES")
        return 0

    monkeypatch.setattr(enrich_sector_queue, "main", fake_main)

    assert enrich_sector_golden.main() == 0
    assert observed == {
        "mode": "golden-only",
        "targets": planity.Organisation_Key,
        "purge": "0",
    }

    saved_item = store.load_items()[0]
    assert saved_item.Sector == config.SECTOR_UNKNOWN
    cache = store.load_org_enrichment_cache()[0]
    assert cache["Company_ID"] == "821511128"
    assert cache["Matched_Name"] == "PLANITY"
    assert cache["Validated_Sector"] == ""
    assert cache["Validated_Via"] == ""
    assert cache["Fetched_At"] == ""
