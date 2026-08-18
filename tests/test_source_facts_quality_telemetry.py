from __future__ import annotations

import json

from cyberwatch import source_facts as sf
from cyberwatch import source_facts_ai as sfa
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.model import Item


def _item(source_id: str = "CYBERATTAQUE_ORG") -> Item:
    return Item(
        Item_ID="ITM-quality-telemetry",
        Source_ID=source_id,
        Organisation_Raw="Exemple SA",
        Published_Date="2026-08-18",
    )


def test_bonjourlafuite_claimed_summary_keeps_claim_semantics():
    item = _item("BONJOURLAFUITE")
    spec = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France")
    entry = RawEntry(
        title="Exemple SA",
        source_metadata={
            "claim_status_raw": "🟠",
            "data_types": ["Nom et prénom", "Adresse e-mail", "Téléphone"],
        },
    )
    fact = sf.extract_source_fact(item, entry, spec)
    assert fact is not None
    assert fact["Claim_Status"] == "claimed"
    assert fact["Summary"].startswith("Données revendiquées selon BonjourLaFuite :")


def test_bonjourlafuite_unconfirmed_summary_is_not_affirmative():
    item = _item("BONJOURLAFUITE")
    spec = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France")
    entry = RawEntry(
        title="Exemple SA",
        source_metadata={
            "claim_status_raw": "🔴",
            "data_types": ["Nom et prénom", "Adresse e-mail", "Téléphone"],
        },
    )
    fact = sf.extract_source_fact(item, entry, spec)
    assert fact is not None
    assert fact["Claim_Status"] == "unconfirmed"
    assert fact["Summary"].startswith("Données signalées mais non confirmées :")


def _row(content_hash: str, *, summary: str = "", impact: str = "", statuses=None) -> dict:
    metadata = {"_source_facts_content_hash": content_hash}
    if statuses is not None:
        metadata["_source_facts_semantic_status"] = statuses
    return {
        "Item_ID": "ITM-merge-quality",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": summary,
        "Impact": impact,
        "Source_Metadata_JSON": json.dumps(metadata),
        "Evidence_JSON": json.dumps({
            **({"Summary": "preuve synthèse"} if summary else {}),
            **({"Impact": "preuve impact"} if impact else {}),
        }),
    }


def test_changed_content_clears_only_confirmed_abstention():
    old = _row("old", summary="Ancienne synthèse.", impact="Ancien impact.")
    new = _row(
        "new",
        statuses={"summary": "abstained", "impact": "miss"},
    )
    merged = sf.merge_source_facts([old], [new])[0]
    assert merged["Summary"] == ""
    assert merged["Impact"] == "Ancien impact."
    evidence = json.loads(merged["Evidence_JSON"])
    assert "Summary" not in evidence
    assert evidence["Impact"] == "preuve impact"


def test_same_content_or_first_miss_never_erases_valid_fact():
    old = _row("same", summary="Synthèse valide.")
    same = _row("same", statuses={"summary": "abstained"})
    assert sf.merge_source_facts([old], [same])[0]["Summary"] == "Synthèse valide."

    changed_first_miss = _row("changed", statuses={"summary": "miss"})
    assert sf.merge_source_facts([old], [changed_first_miss])[0]["Summary"] == "Synthèse valide."


def _configure_runtime(monkeypatch, tmp_path):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    sfa.reset_runtime_for_tests()
    return sfa._runtime()


def test_cache_telemetry_separates_values_and_abstentions(monkeypatch, tmp_path):
    runtime = _configure_runtime(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="Un contenu suffisamment long pour le test de cache sémantique.")
    key = sfa._cache_item_key(item, entry, runtime)
    runtime.cache[key] = {
        "fields": {
            "summary": {"version": sfa.FIELD_VERSIONS["summary"], "status": "accepted", "misses": 0, "value": {"value": "Résumé", "confidence": 0.9, "evidence": "preuve"}},
            "impact": {"version": sfa.FIELD_VERSIONS["impact"], "status": "abstained", "misses": 2, "value": None},
        }
    }
    values, satisfied = sfa._read_field_cache(runtime, key, {"summary", "impact"})
    assert "summary" in values
    assert satisfied == {"summary", "impact"}
    stats = runtime.stats()
    assert stats["accepted_field_cache_hits"] == 1
    assert stats["abstained_field_cache_hits"] == 1
    assert stats["field_cache_hits"] == 2


def test_retry_telemetry_tracks_recovery_and_new_abstention(monkeypatch, tmp_path):
    runtime = _configure_runtime(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="Contexte de test")
    key = sfa._cache_item_key(item, entry, runtime)

    sfa._store_field_cache(runtime, key, item, entry, {"summary"}, {})
    assert runtime.semantic_first_misses == 1
    sfa._store_field_cache(
        runtime,
        key,
        item,
        entry,
        {"summary"},
        {"summary": {"value": "Résumé", "confidence": 0.9, "evidence": "preuve"}},
    )
    assert runtime.semantic_retries == 1
    assert runtime.semantic_recovered_on_retry == 1

    sfa._store_field_cache(runtime, key, item, entry, {"impact"}, {})
    sfa._store_field_cache(runtime, key, item, entry, {"impact"}, {})
    assert runtime.semantic_retries == 2
    assert runtime.semantic_new_abstentions == 1
