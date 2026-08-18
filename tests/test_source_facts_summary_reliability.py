"""Régressions ciblées sur la fiabilité des synthèses SourceFacts."""
from __future__ import annotations

import json
import logging

from cyberwatch import source_facts as sf
from cyberwatch import source_facts_ai as sfa
from cyberwatch.collectors.base import RawEntry, SourceSpec
from cyberwatch.model import Item


def _item(source_id: str = "CYBERATTAQUE_ORG") -> Item:
    return Item(
        Item_ID="ITM-summary-reliability",
        Source_ID=source_id,
        Organisation_Raw="Exemple SA",
        Published_Date="2026-08-18",
    )


def _configure_ai(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    sfa.reset_runtime_for_tests()


def _empty_output(body: dict) -> dict:
    result = {}
    properties = body["text"]["format"]["schema"]["properties"]
    for field in properties:
        if field in {"attack_flow", "data_types"}:
            result[field] = []
        else:
            result[field] = {"value": "", "confidence": 0.0, "evidence": ""}
    return result


def _payload(output: dict) -> dict:
    return {
        "output_text": json.dumps(output, ensure_ascii=False),
        "usage": {"input_tokens": 20, "output_tokens": 10},
    }


def test_ai_field_miss_is_retried_once_then_abstains(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    calls = []

    def fake_post(body, _runtime):
        calls.append(set(body["text"]["format"]["schema"]["properties"]))
        return _payload(_empty_output(body))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    item = _item()
    entry = RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")

    sfa.enrich(item, entry)
    runtime = sfa._runtime()
    key = sfa._cache_item_key(item, entry, runtime)
    assert runtime.cache[key]["fields"]["summary"]["status"] == "miss"
    assert runtime.cache[key]["fields"]["summary"]["misses"] == 1

    sfa.enrich(item, entry)
    assert runtime.cache[key]["fields"]["summary"]["status"] == "abstained"
    assert runtime.cache[key]["fields"]["summary"]["misses"] == 2

    sfa.enrich(item, entry)
    assert len(calls) == 2


def test_ai_field_can_recover_on_second_attempt(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        output = _empty_output(body)
        if len(calls) == 2:
            if "summary" in output:
                output["summary"] = {
                    "value": "L'attaque est attribuée à LockBit.",
                    "confidence": 0.95,
                    "evidence": "L'attaque est attribuée à LockBit.",
                }
            if "threat_actor" in output:
                output["threat_actor"] = {
                    "value": "LockBit",
                    "confidence": 0.95,
                    "evidence": "L'attaque est attribuée à LockBit.",
                }
        return _payload(output)

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    item = _item()
    entry = RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")

    assert sfa.enrich(item, entry) is None
    recovered = sfa.enrich(item, entry) or {}
    assert recovered["summary"]["value"] == "L'attaque est attribuée à LockBit."

    sfa.enrich(item, entry)
    assert len(calls) == 2
    runtime = sfa._runtime()
    key = sfa._cache_item_key(item, entry, runtime)
    assert runtime.cache[key]["fields"]["summary"]["status"] == "accepted"


def test_api_error_does_not_consume_semantic_retry(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    calls = []

    def fake_post(_body, _runtime):
        calls.append(1)
        raise sfa.SourceFactsAiError("HTTP_500")

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    item = _item()
    entry = RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")

    sfa.enrich(item, entry)
    sfa.enrich(item, entry)
    assert len(calls) == 2

    runtime = sfa._runtime()
    key = sfa._cache_item_key(item, entry, runtime)
    assert key not in runtime.cache or "summary" not in runtime.cache[key].get("fields", {})


def _seed_legacy_null(runtime, item, entry):
    key = sfa._cache_item_key(item, entry, runtime)
    runtime.cache[key] = {
        "item_id": item.Item_ID,
        "source_id": item.Source_ID,
        "content_hash": sfa._content_hash(entry),
        "model": runtime.model,
        "fields": {
            "summary": {"version": sfa.FIELD_VERSIONS["summary"], "value": None},
        },
    }
    return key


def test_legacy_null_field_cache_is_skipped_in_normal_rebuild(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")
    runtime = sfa._runtime()
    key = _seed_legacy_null(runtime, item, entry)

    values, satisfied = sfa._read_field_cache(
        runtime, key, {"summary"}, sfa._full_context(entry)
    )
    assert values == {}
    assert satisfied == {"summary"}
    assert runtime.legacy_null_skips == 1
    assert runtime.legacy_null_migrations == 0
    assert "status" not in runtime.cache[key]["fields"]["summary"]


def test_explicit_backfill_mode_can_migrate_legacy_null_to_retryable_miss(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    item = _item()
    entry = RawEntry(title="Exemple", content="L'attaque est attribuée à LockBit.")
    runtime = sfa._runtime()
    runtime.retry_legacy_nulls = True
    key = _seed_legacy_null(runtime, item, entry)

    values, satisfied = sfa._read_field_cache(
        runtime, key, {"summary"}, sfa._full_context(entry)
    )
    assert values == {}
    assert satisfied == set()
    cached = runtime.cache[key]["fields"]["summary"]
    assert cached["status"] == "miss"
    assert cached["misses"] == 1
    assert runtime.legacy_null_migrations == 1
    assert runtime.legacy_null_skips == 0


def test_merge_does_not_erase_valid_semantic_fields_or_evidence():
    old = {
        "Item_ID": "ITM-merge",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": "Ancienne synthèse valide.",
        "Impact": "Impact validé.",
        "Evidence_JSON": sf._dumps_json({
            "Summary": "preuve synthèse",
            "Impact": "preuve impact",
        }),
    }
    new = {
        "Item_ID": "ITM-merge",
        "Source_ID": "CYBERATTAQUE_ORG",
        "Summary": "",
        "Impact": "",
        "Evidence_JSON": sf._dumps_json({"Claim_Status": "confirmée"}),
    }

    merged = sf.merge_source_facts([old], [new])[0]
    assert merged["Summary"] == "Ancienne synthèse valide."
    assert merged["Impact"] == "Impact validé."
    evidence = json.loads(merged["Evidence_JSON"])
    assert evidence["Summary"] == "preuve synthèse"
    assert evidence["Impact"] == "preuve impact"
    assert evidence["Claim_Status"] == "confirmée"


def test_bonjourlafuite_derives_summary_from_rich_structured_data():
    item = _item("BONJOURLAFUITE")
    spec = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France")
    entry = RawEntry(
        title="Exemple SA",
        source_metadata={
            "claim_status_raw": "🟠",
            "data_types": ["Nom et prénom", "Adresse e-mail", "Numéro de téléphone"],
            "source_urls": ["https://example.test/preuve"],
        },
    )

    fact = sf.extract_source_fact(item, entry, spec)
    assert fact is not None
    assert fact["Summary"].startswith("Données revendiquées selon BonjourLaFuite :")
    assert "Adresse e-mail" in fact["Summary"]


def test_bonjourlafuite_keeps_abstention_for_one_weak_data_type():
    item = _item("BONJOURLAFUITE")
    spec = SourceSpec(source_id="BONJOURLAFUITE", layer="core", zone="France")
    entry = RawEntry(
        title="Exemple SA",
        source_metadata={
            "claim_status_raw": "🟠",
            "data_types": ["Adresse e-mail"],
        },
    )

    fact = sf.extract_source_fact(item, entry, spec)
    assert fact is not None
    assert fact["Summary"] == ""


def test_extractor_failure_is_logged_without_breaking_collection(monkeypatch, caplog):
    def boom(*_args):
        raise RuntimeError("boom")

    monkeypatch.setitem(sf._EXTRACTORS, "FRENCHBREACHES", boom)
    item = _item("FRENCHBREACHES")
    spec = SourceSpec(source_id="FRENCHBREACHES", layer="core", zone="France")

    with caplog.at_level(logging.WARNING, logger="cyberwatch.source_facts"):
        assert sf.extract_source_fact(item, RawEntry(title="Exemple"), spec) is None

    assert "source_fact_extraction_failed" in caplog.text
    assert item.Item_ID in caplog.text
