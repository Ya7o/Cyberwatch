import json
from types import SimpleNamespace

from cyberwatch import incremental_performance, source_facts, source_facts_ai, store
from cyberwatch.model import Item


def _entry(content="same content"):
    return SimpleNamespace(title="Incident", summary="Résumé", content=content)


def _item():
    return Item(Item_ID="ITEM-1", Source_ID="FRENCHBREACHES", Sector="Inconnu")


def _spec():
    return SimpleNamespace(source_id="FRENCHBREACHES")


def _cached_row(entry, *, version=None):
    return {
        "Item_ID": "ITEM-1",
        "Source_ID": "FRENCHBREACHES",
        "Extraction_Version": version or source_facts.SOURCE_FACTS_VERSION,
        "Summary": "Résumé déjà extrait",
        "Source_Metadata_JSON": json.dumps({
            "_source_facts_content_hash": source_facts_ai.content_hash(entry),
        }),
    }


def test_reuses_source_fact_when_content_and_extraction_version_are_unchanged(monkeypatch):
    entry = _entry()
    monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(entry)])
    incremental_performance.reset_for_tests()

    reused = incremental_performance._reusable_fact(_item(), entry, _spec())

    assert reused is not None
    assert reused["Summary"] == "Résumé déjà extrait"


def test_does_not_reuse_source_fact_when_content_changed(monkeypatch):
    old_entry = _entry("old content")
    new_entry = _entry("new content")
    monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(old_entry)])
    incremental_performance.reset_for_tests()

    assert incremental_performance._reusable_fact(_item(), new_entry, _spec()) is None


def test_does_not_reuse_source_fact_when_extraction_version_changed(monkeypatch):
    entry = _entry()
    monkeypatch.setattr(
        store,
        "load_source_facts",
        lambda: [_cached_row(entry, version="legacy-version")],
    )
    incremental_performance.reset_for_tests()

    assert incremental_performance._reusable_fact(_item(), entry, _spec()) is None


def test_fast_path_can_be_disabled(monkeypatch):
    entry = _entry()
    monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(entry)])
    monkeypatch.setenv("CYBERWATCH_INCREMENTAL_SOURCE_FACTS", "0")
    incremental_performance.reset_for_tests()

    assert incremental_performance._reusable_fact(_item(), entry, _spec()) is None
