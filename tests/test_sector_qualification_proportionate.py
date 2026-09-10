"""Un secteur étayé ne dépend pas d'une description métier complète."""
import json

import pytest

from cyberwatch import (
    config, enrichment, qualification, sector_resolution, source_facts,
    source_facts_ai, source_facts_retry, runner_source_facts, sources, store,
)
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from cyberwatch.sector_activity import ACTIVITY_FIELDS, activity_from_text


def item(name="Acme", source="FRENCHBREACHES", **kwargs):
    return Item(Item_ID="ITM-test", Organisation_Raw=name, Source_ID=source,
                URL="https://example.test/article", **kwargs)


def decision(sector=config.SECTOR_RETAIL, reason="SOURCE_SECTOR_RAW"):
    return {"Item_ID": "ITM-test", "Resolved_Sector": sector, "Reason": reason}


def run(rows, pending=None):
    return qualification.QualificationRun(
        run_id="RUN-test", documented=True, deferred_source="archive",
        sectors=sector_resolution.qualification_summary(rows),
        extraction={"items_would_call": 1, "calls_attempted": 1,
                    "activity_pairs": {"requested": 1, "rejected": {"total": 1}}},
        deferred=[{"item": {"Item_ID": "ITM-test"},
                   "pending_fields": list(ACTIVITY_FIELDS) + list(pending or [])}],
    )


@pytest.mark.parametrize("name", ["Citadium", "Printemps", "Le Tampon", "Ville du Tampon"])
def test_known_sector_does_not_request_activity(monkeypatch, name):
    # Référence minimale sourcée : indépendante des données locales.
    reference = enrichment.Enrichment(
        organisation="Enseigne", sector=config.SECTOR_RETAIL, location="", scope="", reason="Enseigne",
        validation_url="https://example.test/reference",
    )
    monkeypatch.setattr(enrichment, "load_reference", lambda: {
        "citadium": reference, "printemps": reference,
    })
    entry = RawEntry(organisation=name, content=f"{name} est victime d'une cyberattaque. " * 5)
    fields = source_facts_ai.fields_needed_for_ai(item(name), entry)
    assert not fields & ACTIVITY_FIELDS
    assert "summary" in fields


def test_uncertain_legacy_sector_still_requests_activity(monkeypatch):
    monkeypatch.setattr(enrichment, "load_reference", lambda: {})
    entry = RawEntry(content="Acme annonce un incident informatique. " * 5)
    fields = source_facts_ai.fields_needed_for_ai(item(Sector=config.SECTOR_RETAIL), entry)
    assert ACTIVITY_FIELDS <= fields


@pytest.mark.parametrize("label,sector", [
    ("Commerce", config.SECTOR_RETAIL), ("public", config.SECTOR_ADMIN),
])
def test_source_heading_qualifies_without_activity(monkeypatch, label, sector):
    monkeypatch.setattr(enrichment, "load_reference", lambda: {})
    entry = RawEntry(organisation="Acme", content=(
        f"Par Auteur, rédacteur FrenchBreaches\nPublié le 10/09/2026\n— Secteur {label}\n"
        "Acme annonce un incident. " * 3
    ))
    victim = item()
    assert not source_facts_ai.fields_needed_for_ai(victim, entry) & ACTIVITY_FIELDS
    semantic = source_facts_ai.SemanticExtraction(
        item_id=victim.Item_ID, content_hash=source_facts_ai.content_hash(entry), fields={}, statuses={},
    )
    fact = source_facts.extract_source_fact(victim, entry, sources.by_id("FRENCHBREACHES"), semantic=semantic)
    assert fact["Source_Sector_Raw"] == label
    result = sector_resolution.resolve_item(victim, fact, {})
    assert (result.sector, result.status, result.reason) == (sector, "reported", "SOURCE_SECTOR_RAW")
    assert not fact["Activity_Description"]


def test_related_article_heading_cannot_qualify_victim(monkeypatch):
    monkeypatch.setattr(enrichment, "load_reference", lambda: {})
    entry = RawEntry(content=(
        "À lire aussi\n— Secteur Commerce\nShipup gère les livraisons.\nLire l’alerte liée\n"
        "Par Auteur, rédacteur FrenchBreaches\n" + "Acme annonce un incident. " * 3
    ))
    assert sector_resolution.entry_sector_decision(item(), entry) is None


@pytest.mark.parametrize("reason", ["REFERENCE_EXACT", "ORGANISATION_NAME_RULE", "SOURCE_SECTOR_RAW", "ACTIVITY_RULE"])
def test_resolved_sector_rejects_are_informational(reason):
    verdict = qualification.evaluate(run([decision(reason=reason)]))
    assert verdict["state"] == "COMPLETE"
    assert verdict["pending_fields"] == 2  # l'historique n'est pas effacé
    assert verdict["pending_required_fields"] == 0
    assert verdict["extraction"]["pairs"]["rejected"]["total"] == 1
    assert not verdict["reasons"]


def test_other_qualification_problems_are_not_silenced():
    verdict = qualification.evaluate(run([decision()], ["initial_access"]))
    assert verdict["state"] == "PARTIAL"
    assert verdict["pending_required_fields"] == 1
    assert verdict["reasons"] == ["1 champ(s) d'extraction différé(s)"]


@pytest.mark.parametrize("reason", ["NO_ACTIVITY_EVIDENCE", "ACTIVITY_SECTOR_CONFLICT"])
def test_unknown_or_conflicting_sector_still_alerts(reason):
    verdict = qualification.evaluate(run([decision(config.SECTOR_UNKNOWN, reason)]))
    assert verdict["state"] == "PARTIAL"
    assert any("secteur inconnu" in reason for reason in verdict["reasons"])


def test_retry_removes_only_resolved_sector_fields(monkeypatch, tmp_path):
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    victim = item("Ville du Tampon")
    entry = RawEntry(organisation=victim.Organisation_Raw, content="La mairie annonce un incident.")
    source_facts_retry.enqueue(victim, entry, ACTIVITY_FIELDS | {"initial_access"}, "SEMANTIC_REJECTED")
    source_facts_retry.mark_exhausted(victim, entry, ACTIVITY_FIELDS)
    source_facts_retry.resolve(victim, entry, ACTIVITY_FIELDS)
    row = source_facts_retry.load()[0]
    assert row["pending_fields"] == ["initial_access"]
    assert row["exhausted_fields"] == {}


def test_sector_only_retry_does_not_consume_a_slot(monkeypatch, tmp_path):
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    source_facts_retry.enqueue(item("Ville du Tampon"), RawEntry(content="Un incident."), ACTIVITY_FIELDS, "SEMANTIC_REJECTED")
    monkeypatch.setattr(runner_source_facts, "extract", lambda *a, **k: pytest.fail("appel inutile"))
    rows, summary = runner_source_facts.retry_pending(source_facts_retry.load())
    assert rows == []
    assert summary["attempted"] == summary["queued_after"] == 0


def test_archived_sector_verdict_does_not_use_current_corpus(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "DATA_DIR", tmp_path)
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    directory = tmp_path / "llm_runs" / "RUN-test"
    directory.mkdir(parents=True)
    (directory / "source_facts_ai_usage.json").write_text(json.dumps({"items_would_call": 1, "calls_attempted": 1}))
    source_facts_retry.archive("RUN-test", sector_qualification=sector_resolution.qualification_summary([decision()]))
    loaded = qualification.load_run("RUN-test", tmp_path)
    assert loaded.sectors["resolved"] == 1
    assert qualification.evaluate(loaded)["state"] == "COMPLETE"


def test_incident_description_is_not_an_activity():
    text = "La Ville du Tampon est victime d’une cyberattaque qui perturbe fortement ses services municipaux."
    assert activity_from_text("Ville du Tampon", text) == ("", "")


def test_existing_bad_activity_is_removed_without_losing_its_trace():
    text = "La Ville du Tampon est victime d’une cyberattaque qui perturbe ses services municipaux."
    facts, changed = source_facts.sanitize_source_facts([{
        "Item_ID": "ITM-test", "Activity_Description": text,
        "Evidence_JSON": json.dumps({"Activity_Description": text}),
    }])
    assert "ITM-test" in changed
    assert not facts[0]["Activity_Description"]
    assert json.loads(facts[0]["Source_Metadata_JSON"])["rejected_activity_description"]["value"] == text
