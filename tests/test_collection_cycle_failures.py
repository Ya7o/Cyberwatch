"""Pannes et reprises du cycle quotidien, sans collecte réseau ni modèle."""
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberwatch import (
    config, runner, runner_dedup, runner_source_facts, sector, source_facts,
    source_facts_ai, source_facts_retry, sources, status, store,
)
from cyberwatch.collectors.base import CollectResult, RawEntry


@pytest.fixture
def isolated_store(tmp_path, monkeypatch):
    for name, path in vars(store).copy().items():
        if isinstance(path, Path) and name.endswith(("_CSV", "_JSON")):
            monkeypatch.setattr(store, name, tmp_path / path.name)
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    monkeypatch.setenv("LLM_USAGE_PATH", str(tmp_path / "usage.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "facts-usage.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_TRACE_PATH", str(tmp_path / "trace.json"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(runner_source_facts, "resolve_activities", lambda *args, **kwargs: (None, []))
    return tmp_path


def test_processing_failure_discards_source_batch_and_continues_diagnostics(monkeypatch, make_item):
    spec = sources.by_id("FRENCHBREACHES")
    entries = [RawEntry(title="first"), RawEntry(title="second")]
    result = CollectResult(entries=entries, calls=2, reached_boundary=True)
    monkeypatch.setattr(runner, "get_collector", lambda _: SimpleNamespace(collect=lambda *args: result))
    monkeypatch.setattr(runner, "entry_to_item", lambda *args: make_item(title=args[0].title))

    def extract(item, *args):
        if item.Title == "second":
            raise ValueError("qualification failure")
        return {"Item_ID": item.Item_ID, "Summary": "first fact"}

    monkeypatch.setattr(runner, "_extract_source_fact_for_entry", extract)
    facts = [{"Item_ID": "previous-source"}]
    outcome, items, watches = runner.run_source(
        None, spec, runner.make_run_context(runner.MODE_MAJ), {}, {}, fact_rows=facts,
    )
    assert (outcome.status, outcome.coverage, outcome.calls) == (status.FAIL, 0, 2)
    assert "processing: ValueError" in outcome.comment
    assert items == watches == []
    assert facts == [{"Item_ID": "previous-source"}]


@pytest.mark.parametrize("offline", [False, True])
def test_broken_run_preserves_snapshot_and_retry_work(isolated_store, monkeypatch, make_item, offline):
    original = make_item()
    store.save_items([original])
    store.save_incidents(runner.build_incidents([original]))
    store.save_snapshot({"Run_ID": "PREVIOUS"})
    store.save_source_facts([{"Item_ID": original.Item_ID, "Source_ID": original.Source_ID}])
    source_facts_retry.enqueue(original, RawEntry(title="pending"), {"summary"}, "ERROR")
    paths = [store.ITEMS_CSV, store.INCIDENTS_CSV, store.SNAPSHOT_JSON,
             store.SOURCE_FACTS_CSV, source_facts_retry.queue_path()]
    before = {path: path.read_bytes() for path in paths}
    monkeypatch.setattr(runner, "pre_export_checks", lambda *args: ["injected export failure"])
    monkeypatch.setattr(runner, "_apply_daily_dedup", lambda *args, **kwargs: None)

    def collect(report, *args):
        report.items = [replace(original, Title="unpublished title")]
        report.source_facts = [{"Item_ID": original.Item_ID, "Summary": "unpublished summary"}]
        report.outcomes = [status.SourceOutcome(original.Source_ID, config.LAYER_CORE)]
        return [], []

    monkeypatch.setattr(runner, "_collect_for_run", collect)
    report = runner.execute(runner.make_run_context(runner.MODE_MAJ), offline=offline)
    assert report.overall == status.BROKEN
    assert {path: path.read_bytes() for path in paths} == before
    if not offline:
        assert store.load_run_log()[-1]["Overall_Status"] == status.BROKEN
        assert store.load_production_metrics()[-1]["Published"] == "false"


def test_unchanged_replacement_snapshot_does_not_regenerate_daily_candidates(make_item):
    item = make_item(source="VEILLE_LLM", collected="2026-10-03T10:00:00+04:00")
    refreshed = replace(item, Collected_As_Of="2026-10-04T10:00:00+04:00")
    fact = {"Item_ID": item.Item_ID, "Summary": "public evidence"}
    assert runner_dedup.changed_items([refreshed], [fact], [item], [fact]) == []
    revised = {**fact, "Summary": "new public evidence"}
    assert runner_dedup.changed_items([refreshed], [revised], [item], [fact]) == [refreshed]
    assert runner_dedup.changed_items([replace(refreshed, Event_Date="2026-09-01")],
                                     [fact], [item], [fact])


def test_rich_fact_change_is_included_even_without_new_item(make_item):
    item = make_item()
    fact = {"Item_ID": item.Item_ID, "Source_Metadata_JSON": json.dumps({
        "rich_facts": {"affected_counts": [{"value": 100, "unit": "people"}]},
    })}
    assert runner_dedup.changed_items([item], [fact], [item], []) == [item]


def test_replacement_keeps_first_collection_and_still_removes_absent_records(
    isolated_store, monkeypatch, make_item,
):
    spec = sources.by_id("VEILLE_LLM")
    original = make_item(source="VEILLE_LLM", org="Original", url="https://a/old",
                         collected="2026-09-01T10:00:00+04:00")
    removed = make_item(source="VEILLE_LLM", org="Removed", url="https://a/removed")
    refreshed = replace(original, Collected_As_Of="2026-10-07T18:00:00+04:00",
                        Title="Enriched article")
    added = make_item(source="VEILLE_LLM", org="Added", url="https://a/new",
                     collected="2026-10-07T18:00:00+04:00")
    monkeypatch.setattr(sources, "active_sources", lambda _: [spec])
    monkeypatch.setattr(runner, "run_source", lambda *args: (
        status.SourceOutcome(spec.source_id, spec.layer), [refreshed, added], [],
    ))
    context = runner.make_run_context(runner.MODE_MAJ)
    report = runner.RunReport(context)
    runner._collect_for_run(report, context, [original, removed],
                            {original.Item_ID, removed.Item_ID})
    by_id = {item.Item_ID: item for item in report.items}
    assert set(by_id) == {original.Item_ID, added.Item_ID}
    assert by_id[original.Item_ID].Collected_As_Of == original.Collected_As_Of
    assert by_id[original.Item_ID].Title == "Enriched article"
    assert by_id[added.Item_ID].Collected_As_Of == "2026-10-07T18:00:00+04:00"
    assert report.new_items == 1


def test_superseded_retry_context_cannot_overwrite_updated_article(make_item):
    item = make_item(source="CYBERATTAQUE_ORG")
    old = RawEntry(title="old article")
    current = RawEntry(title="revised article")
    pending = {"key": "old-context", "item": item.to_row(), "entry": old.__dict__}
    facts = [{"Item_ID": item.Item_ID, "Source_Metadata_JSON": json.dumps({
        "_source_facts_content_hash": source_facts_ai.content_hash(current),
    })}]
    assert runner_source_facts.current_retry_contexts([pending], facts) == []
    assert runner_source_facts.current_retry_contexts([pending], []) == [pending]


def test_retry_slots_rotate_after_a_failed_attempt(tmp_path, monkeypatch, make_item):
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    monkeypatch.setenv("SOURCE_FACTS_RETRY_MAX_PER_RUN", "1")
    first = make_item(source="CYBERATTAQUE_ORG", org="First", sector=config.SECTOR_UNKNOWN)
    second = make_item(source="CYBERATTAQUE_ORG", org="Second", sector=config.SECTOR_UNKNOWN)
    for item in [first, second]:
        source_facts_retry.enqueue(item, RawEntry(title=item.Title), {"summary"}, "ERROR")
    monkeypatch.setattr(source_facts_ai, "_runtime", lambda: SimpleNamespace(
        enabled=True, record_event=lambda **kwargs: None,
    ))
    seen = []

    def fail(item, *args, **kwargs):
        seen.append(item.Item_ID)
        raise ValueError("persistent failure")

    monkeypatch.setattr(runner_source_facts, "extract", fail)
    for _ in range(2):
        runner_source_facts.retry_pending(source_facts_retry.load())
    assert set(seen) == {first.Item_ID, second.Item_ID}


def test_ldlc_business_evidence_describes_retail():
    assert sector.classify_sector_activity(
        "Le groupe LDLC est un acteur français spécialisé dans la vente de matériel "
        "informatique, high-tech et équipements électroniques."
    ) == config.SECTOR_RETAIL


def test_prior_attack_date_is_removed_from_facts_and_persisted_item(make_item):
    proof = "Le **10 octobre 2025**, le système avait été victime d'une attaque par rançongiciel."
    context = "Une nouvelle affaire après la cyberattaque d'octobre 2025\n" + proof
    fact = {"Item_ID": "historical-date", "Attack_Date": "2025-10-10",
            "Evidence_JSON": json.dumps({"Attack_Date": proof}),
            "Source_Metadata_JSON": json.dumps({"editorial_context": context, "rich_facts": {
                "timeline": [{"date": "2025-10-10", "evidence": proof}],
            }})}
    item = make_item(source="FRENCHBREACHES", published="2026-10-03", event="2025-10-10")
    item.Item_ID = fact["Item_ID"]
    source_facts.sanitize_source_facts([fact])
    assert fact["Attack_Date"] == ""
    assert source_facts.apply_event_dates([item], [fact]) == [item.Item_ID]
    assert item.Event_Date == ""
    source_facts.sanitize_source_facts([fact])
    assert fact["Attack_Date"] == ""
    assert json.loads(fact["Source_Metadata_JSON"])["rejected_attack_date"]["value"] == "2025-10-10"


def test_an_old_attack_without_comparative_context_keeps_its_date():
    proof = "La cyberattaque a eu lieu le 10 octobre 2025."
    fact = {"Item_ID": "legitimate-date", "Source_Metadata_JSON": json.dumps({"rich_facts": {
        "timeline": [{"date": "2025-10-10", "evidence": proof}],
    }})}
    source_facts.sanitize_source_facts([fact])
    assert fact["Attack_Date"] == "2025-10-10"


def test_offline_repair_preserves_ids_and_original_collection_freshness(
    isolated_store, monkeypatch, make_item,
):
    from scripts import repair_qualifications

    item = make_item(published="2026-10-03", event="2025-10-10")
    proof = "La précédente attaque a eu lieu le 10 octobre 2025."
    fact = {"Item_ID": item.Item_ID, "Source_ID": item.Source_ID, "Attack_Date": item.Event_Date,
            "Evidence_JSON": json.dumps({"Attack_Date": proof})}
    incidents, registry = runner.build_incidents_with_registry([item], [], [], [fact])
    store.save_items([item])
    store.save_incidents(incidents)
    store.save_incident_id_registry(registry)
    store.save_source_facts([fact])
    store.save_snapshot({"Run_ID": "LAST-COLLECTION", "As_Of": "2026-10-04T16:54:04+04:00"})
    original = store.ITEMS_CSV.read_bytes()
    monkeypatch.setattr("sys.argv", ["repair_qualifications.py"])
    assert repair_qualifications.main() == 0
    assert store.ITEMS_CSV.read_bytes() == original
    monkeypatch.setattr("sys.argv", ["repair_qualifications.py", "--write"])
    assert repair_qualifications.main() == 0
    assert store.load_items()[0].Item_ID == item.Item_ID
    assert store.load_items()[0].Event_Date == ""
    assert store.load_incidents()[0].Incident_ID == incidents[0].Incident_ID
    assert store.load_incidents()[0].Date == "2026-10-03"
    assert store.load_snapshot()["As_Of"] == "2026-10-04T16:54:04+04:00"
    assert store.load_source_facts()[0]["Attack_Date"] == ""
