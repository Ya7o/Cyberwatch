from __future__ import annotations

import json

from cyberwatch import source_facts_ai as sfa
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from scripts import backfill_source_fact_summaries as backfill


def _item() -> Item:
    return Item(
        Item_ID="ITM-retry-abstained",
        Source_ID="CYBERATTAQUE_ORG",
        Organisation_Raw="Exemple SA",
        Published_Date="2026-08-18",
    )


def _entry() -> RawEntry:
    return RawEntry(
        title="Exemple SA : cyberattaque",
        content=(
            "Une intrusion a permis un accès non autorisé au système. "
            "Le groupe Qilin revendique ensuite la publication de documents internes."
        ),
        organisation="Exemple SA",
    )


def _configure_ai(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    sfa.reset_runtime_for_tests()


def _seed_abstained_summary(item: Item, entry: RawEntry) -> tuple[object, dict]:
    runtime = sfa._runtime()
    cache_entry = {
        "item_id": item.Item_ID,
        "source_id": item.Source_ID,
        "content_hash": sfa.content_hash(entry),
        "model": runtime.model,
        "fields": {
            "summary": {
                "version": sfa.FIELD_VERSIONS["summary"],
                "status": "abstained",
                "misses": sfa.MAX_FIELD_MISSES,
                "value": None,
            },
        },
    }
    runtime.cache["historical"] = cache_entry
    return runtime, cache_entry


def _empty_output(body: dict) -> dict:
    output = {}
    for field in body["text"]["format"]["schema"]["properties"]:
        if field in {"attack_flow", "data_types"}:
            output[field] = []
        else:
            output[field] = {"value": "", "confidence": 0.0, "evidence": ""}
    return output


def test_reopen_abstained_semantic_field_is_one_retry(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    item = _item()
    entry = _entry()
    _runtime, cache_entry = _seed_abstained_summary(item, entry)

    previous = backfill.reopen_abstained_semantic_fields(item, entry)

    assert set(previous) == {"summary"}
    assert previous["summary"]["status"] == "abstained"
    reopened = cache_entry["fields"]["summary"]
    assert reopened["status"] == "miss"
    assert reopened["misses"] == sfa.MAX_FIELD_MISSES - 1
    assert reopened["value"] is None


def test_reopened_summary_can_recover_and_become_accepted(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    item = _item()
    entry = _entry()
    runtime, cache_entry = _seed_abstained_summary(item, entry)
    backfill.reopen_abstained_semantic_fields(item, entry)
    calls = []

    def fake_post(body, _runtime):
        calls.append(1)
        output = _empty_output(body)
        output["summary"] = {
            "value": "Une intrusion a permis un accès non autorisé au système.",
            "confidence": 0.95,
            "evidence": "Une intrusion a permis un accès non autorisé au système.",
        }
        return {
            "output_text": json.dumps(output, ensure_ascii=False),
            "usage": {"input_tokens": 20, "output_tokens": 10},
        }

    monkeypatch.setattr(sfa, "_post_openai", fake_post)

    result = sfa.enrich(item, entry) or {}

    assert len(calls) == 1
    assert result["summary"]["value"].startswith("Une intrusion")
    summary_cache = cache_entry["fields"]["summary"]
    assert summary_cache["status"] == "accepted"
    assert summary_cache["misses"] == 0
    assert runtime.semantic_recovered_on_retry >= 1


def test_restore_reopened_field_preserves_terminal_abstention(monkeypatch, tmp_path):
    _configure_ai(monkeypatch, tmp_path)
    item = _item()
    entry = _entry()
    _runtime, cache_entry = _seed_abstained_summary(item, entry)

    previous = backfill.reopen_abstained_semantic_fields(item, entry)
    backfill.restore_reopened_semantic_fields(item, entry, previous)

    restored = cache_entry["fields"]["summary"]
    assert restored["status"] == "abstained"
    assert restored["misses"] == sfa.MAX_FIELD_MISSES
    assert restored["value"] is None
