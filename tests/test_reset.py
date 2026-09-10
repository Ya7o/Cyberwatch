"""Cycle PURGE -> MAJ isolé : aucune collecte réseau ni écriture en production."""

import json
from pathlib import Path

import pytest
import requests

from cyberwatch import cli, config, llm_runtime, reset, runner, source_facts_ai_runtime, status, store


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    original_data = store.DATA_DIR
    data = tmp_path / "data"
    data.mkdir()
    for name, value in vars(store).copy().items():
        if isinstance(value, Path) and value.parent == original_data:
            monkeypatch.setattr(store, name, data / value.name)
    monkeypatch.setattr(store, "DATA_DIR", data)
    monkeypatch.setattr(store, "SITE_DATA_DIR", tmp_path / "assets" / "data")
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(data / "source_facts_retry_queue.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(data / "source_facts_ai_cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(data / "source_facts_ai_usage.json"))
    monkeypatch.setenv("LLM_USAGE_PATH", str(data / "llm_usage.json"))
    monkeypatch.setenv("CYBERWATCH_PERFORMANCE_LOG_PATH", str(data / "performance_runs.json"))
    monkeypatch.setenv("CYBERATTAQUE_SEMANTIC_CACHE_PATH", str(data / "cyberattaque_semantic_cache.json"))
    monkeypatch.setattr(source_facts_ai_runtime, "_RUNTIME", None)
    monkeypatch.setattr(llm_runtime, "_RUNTIME", llm_runtime.LlmRuntime())
    # Échec immédiat si un test tente réellement de collecter.
    monkeypatch.setattr(requests.Session, "request", lambda *a, **k: pytest.fail("Accès réseau interdit"))
    return data


def test_purge_clears_generated_state_and_dashboard(isolated_store, make_item):
    preserved = {
        name: f"reference:{name}" for name in (
            "sources.csv", "enrichment_reference.csv", "organisation_aliases.csv",
            "territorial_identities.csv", "editorial_corrections.json", "personal-notes.txt",
        )
    }
    for name, content in preserved.items():
        (isolated_store / name).write_text(content)
    for name in reset.GENERATED_FILES:
        (isolated_store / name).write_text("ancien état")
    archive = isolated_store / "llm_runs" / "OLD"
    archive.mkdir(parents=True)
    (archive / "trace.json").write_text('{"old_incident":true}')
    store.save_items([make_item()])
    store.write_json(store.SITE_DATA_DIR / "facts.json", {"OLD": "ancien incident"})

    assert cli.main(["PURGE"]) == 0
    assert store.snapshot_state() == (store.BASE_VALID, [])
    assert store.load_items() == store.load_incidents() == []
    assert store.load_source_facts() == store.load_run_log() == []
    assert store.load_snapshot()["Operation"] == "PURGE"
    for name in reset.GENERATED_FILES:
        if name not in {"items.csv", "incidents.csv", "snapshot.json"}:
            assert not (isolated_store / name).exists(), name
    assert not archive.parent.exists()
    for name, content in preserved.items():
        assert (isolated_store / name).read_text() == content
    for name, expected in (("incidents", []), ("latest", []), ("facts", {})):
        assert json.loads((store.SITE_DATA_DIR / f"{name}.json").read_text()) == expected
    payload = json.loads((store.SITE_DATA_DIR / "status.json").read_text())
    assert payload["initialized"] is False
    assert payload["history"] == payload["entities"] == []
    assert "Base vidée" in payload["message"]
    assert "<item>" not in (store.SITE_DATA_DIR / "reunion-mayotte.xml").read_text()
    assert cli.main(["check"]) == 0
    assert cli.main(["purge"]) == 0


def test_maj_after_purge_filters_old_entries_and_preserves_new_stock(
    isolated_store, monkeypatch, make_item,
):
    store.save_items([make_item(org="Ancienne victime")])
    assert cli.main(["purge"]) == 0
    spec = runner.sources.by_id("FRENCHBREACHES")
    monkeypatch.setattr(runner.sources, "active_sources", lambda layers: [spec])
    monkeypatch.setattr(runner, "_apply_daily_dedup", lambda *a, **k: None)
    old = make_item(published="2026-09-08", org="Article trop ancien")
    yesterday = make_item(published="2026-09-09", org="Victime de la veille")
    today = make_item(published="2026-09-10", org="Victime du jour")
    future = make_item(published="2026-09-11", org="Article futur")
    entries = [old, yesterday, today, future]

    def collect(*args):
        return status.SourceOutcome(
            spec.source_id, config.LAYER_CORE, status.OK, 100,
        ), list(entries), []

    monkeypatch.setattr(runner, "run_source", collect)
    assert cli.main(["MAJ", "--as-of", "2026-09-10T11:00:00+04:00"]) == 0
    assert {item.Item_ID for item in store.load_items()} == {yesterday.Item_ID, today.Item_ID}
    assert store.snapshot_state() == (store.BASE_VALID, [])
    assert store.load_snapshot()["Operation"] == "MAJ"
    entries.clear()
    assert cli.main(["maj", "--as-of", "2026-09-11T11:00:00+04:00"]) == 0
    assert {item.Item_ID for item in store.load_items()} == {yesterday.Item_ID, today.Item_ID}
    assert cli.main(["PURGE"]) == 0
    source_facts_ai_runtime._flush_runtime()
    llm_runtime._write_stats()
    assert store.load_items() == []
    assert not (isolated_store / "source_facts_ai_cache.json").exists()
    assert not (isolated_store / "llm_usage.json").exists()
    assert not (isolated_store / "llm_runs").exists()


def test_purge_rejects_external_symlink_before_deleting_anything(isolated_store, tmp_path):
    external = tmp_path / "outside.json"
    external.write_text("conserver")
    (isolated_store / "source_facts_ai_cache.json").symlink_to(external)
    store.save_items([])
    with pytest.raises(ValueError, match="hors de data"):
        reset.purge()
    assert external.read_text() == "conserver"
    assert store.ITEMS_CSV.exists()
