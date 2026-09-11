"""Régressions de l'élagage : publication, reprise et couches actives."""
import json
from pathlib import Path

import pytest

from cyberwatch import config, dedup, identity, runner, site, sources, status, store
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.source_facts_ai_contract import RETIRED_LLM_FIELDS


def test_build_compact_conserve_les_informations_affichees(tmp_path, monkeypatch, make_item):
    for name, value in vars(store).copy().items():
        if isinstance(value, Path) and value.parent == store.DATA_DIR:
            monkeypatch.setattr(store, name, tmp_path / value.name)
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(store, "SITE_DATA_DIR", tmp_path / "public")
    item = make_item(org="Exemple", sector=config.SECTOR_UNKNOWN,
                     url="https://frenchbreaches.com/alertes/exemple",
                     published="2026-09-09", collected="2026-09-10T08:00:00+04:00")
    incidents = dedup.build_incidents([item])
    store.save_items([item])
    store.save_incidents(incidents)
    store.save_source_facts([{
        "Item_ID": item.Item_ID, "Source_ID": item.Source_ID,
        "Summary": "Exemple signale une fuite de données.",
        "Data_Types_JSON": json.dumps(["adresses e-mail"]),
        "Source_Metadata_JSON": json.dumps({"rich_facts": {
            "incident_summary": [{"value": "Exemple signale une fuite de données.",
                                  "evidence": "Exemple signale une fuite de données."}],
        }}),
    }])
    store.save_snapshot({
        "Run_ID": "RUN-TEST", "Items_Count": 1, "Incidents_Count": 1,
        "Items_Hash": identity.items_hash([item]),
        "Incidents_Hash": identity.incidents_hash(incidents),
    })
    store.append_run_log({"Run_ID": "RUN-TEST", "As_Of": item.Collected_As_Of,
                          "Sources_FAIL": 1, "Overall_Status": "FAIL"})
    store.append_run_sources([{"Run_ID": "RUN-TEST", "Source_ID": item.Source_ID,
                               "Status": "FAIL", "Reason": "Timeout explicite"}])
    canonical = store.SOURCE_FACTS_CSV.read_bytes()
    site.build()

    def published(name):
        return json.loads((store.SITE_DATA_DIR / f"{name}.json").read_text())

    row = published("incidents")[0]
    assert published("latest") == [row]
    assert row["org"] == "Exemple"
    assert row["summary"] == "Exemple signale une fuite de données."
    assert row["source_links"] == [{"source": item.Source_ID, "url": item.URL}]
    assert row["sector_status"]["status"] == "unknown"
    assert row["personal_data_exposed"] is True
    detail = published("facts")[row["id"]]
    assert detail == {"version": 3, "display_summary": row["summary"],
                      "summary_paragraphs": [row["summary"]]}
    assert not {"facts", "quality_alerts", "data_exposure", "urls"} & row.keys()
    health = published("status")
    assert health["counts"]["fail"] == 1
    failed = next(row for row in health["sources"] if row["id"] == item.Source_ID)
    assert failed["status"] == "FAIL" and failed["reason"] == "Timeout explicite"
    assert "qualification" in health and "integrity" in health
    assert health["analytics"]["quality"]["incidents"] == 1
    assert not {"entities", "coverage_groups", "blind_spots", "initialized"} & health.keys()
    assert "exposure" not in health["analytics"]
    assert store.SOURCE_FACTS_CSV.read_bytes() == canonical


def test_la_reprise_retire_les_champs_abandonnes_sans_effacer_les_pannes(tmp_path, monkeypatch, make_item):
    from cyberwatch import source_facts_retry as retry, runner_source_facts, source_facts_ai
    from types import SimpleNamespace

    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "queue.json"))
    item = make_item(org="Exemple", sector=config.SECTOR_UNKNOWN)
    entry = RawEntry(title="Exemple", content="Un article sans activité établie.")
    retry.enqueue(item, entry, {"impact", "summary"}, "TECHNICAL_FAILURE")
    other = make_item(org="Autre", sector=config.SECTOR_UNKNOWN)
    retry.enqueue(other, entry, {"affected_counts"}, "TECHNICAL_FAILURE")
    monkeypatch.setattr(source_facts_ai, "_runtime", lambda: SimpleNamespace(enabled=False))
    queued = retry.load()
    runner_source_facts.retry_pending(queued)
    remaining = retry.load()
    assert len(remaining) == 1
    assert remaining[0]["pending_fields"] == ["summary"]
    assert remaining[0]["reason"] == "TECHNICAL_FAILURE"
    assert RETIRED_LLM_FIELDS.isdisjoint(remaining[0]["pending_fields"])


@pytest.mark.parametrize("watch_active", [False, True])
def test_journal_et_fichier_de_veille_suivent_les_sources_actives(tmp_path, monkeypatch, watch_active):
    from cyberwatch import runner_support, production

    monkeypatch.setattr(sources, "ALL_SOURCES", [
        SourceSpec(source_id="CORE_TEST", zone="France", layer=config.LAYER_CORE, active=True),
        SourceSpec(source_id="WATCH_TEST", zone="La Réunion", layer=config.LAYER_ENTITY_WATCH, active=watch_active),
    ])
    report = runner.RunReport(context=runner.make_run_context(runner.MODE_MAJ,
                                as_of="2026-09-10T08:00:00+04:00"))
    report.outcomes = [status.SourceOutcome(source_id="CORE_TEST", layer=config.LAYER_CORE)]
    row = runner_support.run_log_row(report, {})
    assert row["Layers"].split(",") == ([config.LAYER_CORE, config.LAYER_ENTITY_WATCH]
                                        if watch_active else [config.LAYER_CORE])
    writes = []
    monkeypatch.setattr(store, "save_entity_watch", lambda rows: writes.append(rows))
    monkeypatch.setattr(store, "load_entity_watch", lambda: [])
    monkeypatch.setattr(runner, "build_entity_watch", lambda *args: [{"entity": "Témoin"}])
    for name in ("save_sources", "append_run_sources", "append_run_log", "upsert_production_metric"):
        monkeypatch.setattr(store, name, lambda *args, **kwargs: None)
    monkeypatch.setattr(production, "metric_row", lambda **kwargs: {})
    monkeypatch.setattr(runner, "save_canonical_snapshot", lambda *args, **kwargs: None)
    runner._persist(report, [], persist_snapshot=True)
    assert bool(writes) is watch_active
