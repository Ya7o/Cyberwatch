import json
from types import SimpleNamespace

from cyberwatch import incremental_performance, source_facts, source_facts_ai, store
from cyberwatch.collectors import feed
from cyberwatch.model import Item


def _entry(content="same content", url="https://example.test/item"):
    return SimpleNamespace(title="Incident", summary="Résumé", content=content, url=url, published="2026-08-20")


def _item():
    return Item(Item_ID="ITEM-1", Source_ID="FRENCHBREACHES", Sector="Inconnu")


def _spec():
    return SimpleNamespace(source_id="FRENCHBREACHES")


def _cached_row(entry, *, version=None):
    return {"Item_ID":"ITEM-1","Source_ID":"FRENCHBREACHES","Extraction_Version":version or source_facts.SOURCE_FACTS_VERSION,"Summary":"Résumé déjà extrait","Source_Metadata_JSON":json.dumps({"_source_facts_content_hash": source_facts_ai.content_hash(entry)})}


def test_reuses_source_fact_when_content_and_extraction_version_are_unchanged(monkeypatch):
    entry = _entry(); monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(entry)]); incremental_performance.reset_for_tests()
    reused = incremental_performance._reusable_fact(_item(), entry, _spec())
    assert reused is not None and reused["Summary"] == "Résumé déjà extrait"


def test_does_not_reuse_source_fact_when_content_changed(monkeypatch):
    old_entry = _entry("old content"); new_entry = _entry("new content")
    monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(old_entry)]); incremental_performance.reset_for_tests()
    assert incremental_performance._reusable_fact(_item(), new_entry, _spec()) is None


def test_does_not_reuse_source_fact_when_extraction_version_changed(monkeypatch):
    entry = _entry(); monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(entry, version="legacy-version")]); incremental_performance.reset_for_tests()
    assert incremental_performance._reusable_fact(_item(), entry, _spec()) is None


def test_fast_path_can_be_disabled(monkeypatch):
    entry = _entry(); monkeypatch.setattr(store, "load_source_facts", lambda: [_cached_row(entry)]); monkeypatch.setenv("CYBERWATCH_INCREMENTAL_SOURCE_FACTS", "0"); incremental_performance.reset_for_tests()
    assert incremental_performance._reusable_fact(_item(), entry, _spec()) is None


def test_frenchbreaches_detail_cache_avoids_second_network_fetch(monkeypatch, tmp_path):
    cache_path = tmp_path / "details.json"; monkeypatch.setenv("CYBERWATCH_FRENCHBREACHES_DETAIL_CACHE", "1"); monkeypatch.setenv("FRENCHBREACHES_DETAIL_CACHE_PATH", str(cache_path)); monkeypatch.setenv("FRENCHBREACHES_DETAIL_CACHE_TTL_DAYS", "7"); incremental_performance.reset_for_tests()
    class Budget: exhausted=False; requests_made=0
    class Response: ok=True; text="<article>Texte détaillé stable</article>"
    class Client:
        def __init__(self): self.calls=0
        def fetch(self, url, budget): self.calls += 1; budget.requests_made += 1; return Response()
    client=Client(); first=_entry(content=""); assert feed._hydrate_frenchbreaches_details(client,[first],Budget()) == (1,1); assert client.calls == 1 and first.content
    second=_entry(content=""); assert feed._hydrate_frenchbreaches_details(client,[second],Budget()) == (1,1); assert client.calls == 1 and second.content == first.content
    assert incremental_performance.stats()["french_detail_cache_hits"] == 1


def test_frenchbreaches_detail_cache_invalidates_when_feed_identity_changes(monkeypatch, tmp_path):
    cache_path = tmp_path / "details.json"; monkeypatch.setenv("CYBERWATCH_FRENCHBREACHES_DETAIL_CACHE", "1"); monkeypatch.setenv("FRENCHBREACHES_DETAIL_CACHE_PATH", str(cache_path)); incremental_performance.reset_for_tests()
    class Budget: exhausted=False; requests_made=0
    class Response: ok=True; text="<article>Texte détaillé stable</article>"
    class Client:
        def __init__(self): self.calls=0
        def fetch(self, url, budget): self.calls += 1; return Response()
    client=Client(); feed._hydrate_frenchbreaches_details(client,[_entry(content="")],Budget()); changed=_entry(content=""); changed.summary="Résumé modifié"; feed._hydrate_frenchbreaches_details(client,[changed],Budget()); assert client.calls == 2


def test_performance_history_is_bounded_and_replaces_same_run(monkeypatch, tmp_path):
    path = tmp_path / "performance.json"; monkeypatch.setenv("CYBERWATCH_PERFORMANCE_LOG_PATH", str(path))
    incremental_performance._save_performance_row({"run_id":"R1","duration_s":10}); incremental_performance._save_performance_row({"run_id":"R1","duration_s":8})
    assert incremental_performance._load_performance_history() == [{"run_id":"R1","duration_s":8}]
