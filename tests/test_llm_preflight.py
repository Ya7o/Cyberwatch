from __future__ import annotations

import csv
import json

from cyberwatch import ai, llm_preflight


def test_preflight_routes_expected_models(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("SOURCE_FACTS_MODEL", raising=False)
    monkeypatch.delenv("CYBERATTAQUE_SEMANTIC_MODEL", raising=False)
    monkeypatch.setattr(llm_preflight, "ROOT", tmp_path)
    monkeypatch.setattr(llm_preflight, "DATA", tmp_path / "data")
    (tmp_path / "data").mkdir()

    payload = llm_preflight.summary()
    assert payload["offline"] is True
    assert payload["routing"]["qualification"] == "gpt-5-nano"
    assert payload["routing"]["source_facts"] == "gpt-4o-mini"
    assert payload["routing"]["cyberattaque_semantic"] == "gpt-4o-mini"
    assert payload["routing"]["dedup"] == "gpt-4o-mini"


def test_qualification_cache_compatibility_uses_latest_row(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    path = data / "ai_qualifications.csv"
    fields = ["Item_ID", "Input_Hash", "Model", "Prompt_Version"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerow({
            "Item_ID": "ITM-1",
            "Input_Hash": "hash-1",
            "Model": "gpt-4o-mini",
            "Prompt_Version": ai.PROMPT_VERSION,
        })
        writer.writerow({
            "Item_ID": "ITM-1",
            "Input_Hash": "hash-1",
            "Model": "gpt-5-nano",
            "Prompt_Version": ai.PROMPT_VERSION,
        })
        writer.writerow({
            "Item_ID": "ITM-2",
            "Input_Hash": "hash-2",
            "Model": "gpt-4o-mini",
            "Prompt_Version": ai.PROMPT_VERSION,
        })
    monkeypatch.setattr(llm_preflight, "ROOT", tmp_path)
    monkeypatch.setattr(llm_preflight, "DATA", data)
    report = llm_preflight.qualification_report()
    assert report.entries == 2
    assert report.compatible == 1
    assert report.incompatible == 1
    assert report.effective_model == "gpt-5-nano"


def test_json_cache_model_inventory_supports_entries_wrapper(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    path = data / "source_facts_ai_cache.json"
    path.write_text(
        json.dumps({
            "_format": "source-facts-ai-field-cache-v1",
            "entries": {
                "a": {"model": "gpt-4o-mini"},
                "b": {"model": "gpt-5-nano"},
                "c": {"value": "legacy"},
            },
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(llm_preflight, "ROOT", tmp_path)
    report = llm_preflight._json_cache_report("source_facts", path, "source_facts")
    assert report.entries == 3
    assert report.compatible == 1
    assert report.incompatible == 1
    assert report.unknown_model == 1
    assert report.hit_rate == 33.3


def test_json_cache_model_inventory_supports_flat_cache(monkeypatch, tmp_path):
    path = tmp_path / "semantic.json"
    path.write_text(
        json.dumps({
            "_format": "metadata",
            "a": {"model": "gpt-4o-mini"},
            "b": {"model": "gpt-5-nano"},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(llm_preflight, "ROOT", tmp_path)
    report = llm_preflight._json_cache_report(
        "cyberattaque_semantic", path, "cyberattaque_semantic"
    )
    assert report.entries == 2
    assert report.compatible == 1
    assert report.incompatible == 1
