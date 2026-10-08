"""Collecte → qualification → déduplication → publication, puis confirmation."""
import json
from dataclasses import replace
from pathlib import Path

import pytest

from cyberwatch import dedup, identity, runner, site, site_regional_watch, sources, store
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.base import Window
from cyberwatch.source_facts_handlers import extract_source_fact


def test_candidate_publication_and_confirmation_preserve_identity(tmp_path, monkeypatch):
    original_spec = sources.by_id("VEILLE_LLM")
    snapshot = json.loads((store.ROOT / original_spec.params["path"]).read_text())
    record = next(row for row in snapshot["records"] if row["admission"] == "CANDIDATE")
    record.update(organisation="Signal régional de test", date="2026-10-06",
                  secteur="Inconnu", sources=["https://press.example/signal"],
                  score_cyberattaque=0)
    snapshot["records"] = [record]
    snapshot["metadata"].update(record_count=1, accepted_count=0, candidate_count=1)
    data_dir = store.DATA_DIR
    for name, value in vars(store).copy().items():
        if isinstance(value, Path) and value.parent == data_dir:
            monkeypatch.setattr(store, name, tmp_path / "data" / value.name)
    monkeypatch.setattr(store, "DATA_DIR", tmp_path / "data")
    monkeypatch.setattr(store, "ROOT", tmp_path)
    monkeypatch.setattr(store, "SITE_DATA_DIR", tmp_path / "public")
    spec = replace(original_spec, params={**original_spec.params, "path": "watch.json"})
    original_by_id = sources.by_id
    monkeypatch.setattr(sources, "by_id", lambda value: spec if value == "VEILLE_LLM" else original_by_id(value))
    path = tmp_path / "watch.json"

    def collect(as_of):
        path.write_text(json.dumps(snapshot))
        entry = get_collector("veillellm").collect(None, spec, Window("2026-10-07", "2026-10-08")).entries[0]
        item = runner.entry_to_item(entry, spec, as_of, {}, {})
        assert item is not None
        fact = extract_source_fact(item, entry, spec)
        assert fact is not None
        return item, fact

    def publish(items, facts, registry):
        incidents, updated = dedup.build_incidents_with_registry(items, registry, source_facts_rows=facts)
        store.save_items(items)
        store.save_incidents(incidents)
        store.save_incident_id_registry(updated)
        store.save_source_facts(facts)
        store.save_snapshot({"Run_ID": "RUN-TEST", "Items_Count": len(items), "Incidents_Count": len(incidents),
                             "Items_Hash": identity.items_hash(items), "Incidents_Hash": identity.incidents_hash(incidents)})
        site.build()
        return updated

    def public(name):
        return json.loads((store.SITE_DATA_DIR / f"{name}.json").read_text())

    item, fact = collect("2026-10-07T07:00:00Z")
    store.append_run_log({"Run_ID": "RUN-TEST", "As_Of": "2026-10-08T07:00:00Z", "Overall_Status": "OK"})
    registry = publish([item], [fact], [])
    candidate = public("incidents")[0]
    incident_id = candidate["id"]
    assert candidate["admission"] == "CANDIDATE"
    assert candidate["admission_reason"] == record["admission_reason"]
    assert public("latest") == [candidate]
    qualification = public("facts")[incident_id]["regional_watch"][0]
    assert qualification["score"] == 0
    assert qualification["statut"] == record["statut"]
    assert qualification["admission_reason"] == record["admission_reason"]
    assert qualification["score_definition"] == snapshot["metadata"]["score_definition"]
    assert [link["url"] for link in candidate["source_links"]] == record["sources"]
    assert public("status")["analytics"]["quality"]["incidents"] == 0
    assert public("status")["analytics"]["scopes"]["focus"]["all"]["incidents"] == 0

    record.update(admission="ACCEPTED", admission_reason="Origine cyber confirmée.",
                  type_menace="Intrusion", statut="Intrusion confirmée", score_cyberattaque=100)
    record["sources"].insert(0, "https://press.example/confirmation")
    snapshot["metadata"].update(accepted_count=1, candidate_count=0)
    confirmed, confirmed_fact = collect("2026-10-08T07:00:00Z")
    assert confirmed.Item_ID == item.Item_ID
    items, new_count = dedup.merge_items([item], [confirmed])
    assert new_count == 0 and len(items) == 1
    assert items[0].Collected_As_Of == item.Collected_As_Of
    publish(items, [confirmed_fact], registry)
    assert len(public("incidents")) == 1
    admitted = public("incidents")[0]
    assert admitted["id"] == incident_id and admitted["admission"] == "ACCEPTED"
    assert {link["url"] for link in admitted["source_links"]} == set(record["sources"])
    assert public("facts")[incident_id]["regional_watch"][0]["score"] == 100
    assert public("status")["analytics"]["quality"]["incidents"] == 1
    assert public("status")["analytics"]["scopes"]["focus"]["all"]["incidents"] == 1


@pytest.mark.parametrize("score", [False, True, -1, 101, "100", None])
def test_invalid_scores_are_not_published(score):
    qualification = site_regional_watch.qualification({
        "Source_ID": "VEILLE_LLM", "Source_Metadata_JSON": json.dumps({"score_cyberattaque": score}),
    })
    assert "score" not in qualification
