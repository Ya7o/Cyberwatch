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
    assert fact["Summary"].startswith("BonjourLaFuite signale une revendication de fuite de données")


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
    assert fact["Summary"].startswith("BonjourLaFuite signale une fuite de données non confirmée")


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


def test_changed_content_without_semantic_status_preserves_valid_fact():
    old = _row("old", summary="Synthèse valide.")
    # Un nouveau hash sans statut sémantique représente notamment un appel IA
    # ayant échoué avant toute mise à jour du cache : aucune donnée valide ne
    # doit être supprimée dans ce cas.
    technical_failure = _row("new")
    merged = sf.merge_source_facts([old], [technical_failure])[0]
    assert merged["Summary"] == "Synthèse valide."
    assert json.loads(merged["Evidence_JSON"])["Summary"] == "preuve synthèse"


def test_legacy_row_without_content_hash_is_never_destructively_migrated():
    old = {
        "Item_ID": "ITM-merge-quality",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": "Synthèse historique valide.",
        "Source_Metadata_JSON": "",
        "Evidence_JSON": json.dumps({"Summary": "preuve historique"}),
    }
    new = _row("new", statuses={"summary": "abstained"})
    merged = sf.merge_source_facts([old], [new])[0]
    assert merged["Summary"] == "Synthèse historique valide."
    assert json.loads(merged["Evidence_JSON"])["Summary"] == "preuve historique"


def test_changed_article_without_llm_result_preserves_published_summary():
    item = Item(Item_ID="ITM-maileva", Source_ID="FRENCHBREACHES",
                Organisation_Raw="Maileva")
    entry = RawEntry(title="Maileva", content=(
        "La cyberattaque chez Maileva concerne les données de 22 millions de personnes."
    ))
    semantic = sfa.SemanticExtraction(
        item_id=item.Item_ID, content_hash=sfa.content_hash(entry), fields={}, statuses={},
    )
    new = sf.extract_source_fact(
        item, entry, SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France"),
        semantic=semantic,
    )
    assert new is not None
    assert new["Summary"] == ""
    assert json.loads(new["Source_Metadata_JSON"])["_source_facts_summary_status"] == "deferred"
    old = {**_row("old", summary="Maileva a interrompu ses services après une intrusion.",
                 statuses={"summary": "accepted"}), "Item_ID": item.Item_ID}
    merged = sf.merge_source_facts([old], [new])[0]
    assert merged["Summary"] == old["Summary"]
    assert json.loads(merged["Evidence_JSON"])["Summary"] == "preuve synthèse"
    assert sf.semantic_materialization_gaps([merged]) == []


def test_unpublishable_accepted_summary_records_quality_rejection():
    item = _item()
    entry = RawEntry(title="Exemple SA", content="Exemple SA confirme une cyberattaque.")
    semantic = sfa.SemanticExtraction(
        item_id=item.Item_ID, content_hash=sfa.content_hash(entry),
        fields={"summary": {"value": "Exemple SA", "evidence": "Exemple SA"}},
        statuses={"summary": "accepted"},
    )
    new = sf.extract_source_fact(
        item, entry, SourceSpec(source_id=item.Source_ID, layer="core", zone="France"),
        semantic=semantic,
    )
    assert new is not None
    old = {**_row("old", summary="Ancienne synthèse.", statuses={"summary": "accepted"}),
           "Item_ID": item.Item_ID}
    merged = sf.merge_source_facts([old], [new])[0]
    assert merged["Summary"] == ""
    assert json.loads(merged["Source_Metadata_JSON"])["_source_facts_semantic_status"]["summary"] == "rejected_quality"
    assert sf.semantic_materialization_gaps([merged]) == []


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
