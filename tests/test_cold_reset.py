from __future__ import annotations

import csv
import json
from pathlib import Path

from cyberwatch import cold_reset, llm_runtime, source_facts_ai
from cyberwatch.llm_legacy_bridge import normalize_legacy_request


def test_source_facts_legacy_request_uses_rich_model_without_reasoning(monkeypatch):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("SOURCE_FACTS_MODEL", raising=False)
    body = normalize_legacy_request(
        "source_facts",
        {"model": "gpt-5-nano", "reasoning": {"effort": "minimal"}},
    )
    assert body["model"] == "gpt-4o-mini"
    assert "reasoning" not in body


def test_source_facts_runtime_and_cache_model_are_aligned(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_MODEL", "gpt-4o-mini")
    source_facts_ai.reset_runtime_for_tests()
    runtime = source_facts_ai._runtime()
    assert runtime.model == llm_runtime.model_for_task("source_facts") == "gpt-4o-mini"


def test_compare_reports_identity_churn(tmp_path):
    before = tmp_path / "before.csv"
    after = tmp_path / "after.csv"
    for path, values in ((before, ["A", "B"]), (after, ["B", "C"])):
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=["Item_ID"])
            writer.writeheader()
            for value in values:
                writer.writerow({"Item_ID": value})
    result = cold_reset.compare(before, after, "Item_ID")
    assert result["lost"] == ["A"]
    assert result["added"] == ["C"]
    assert result["churn_count"] == 2


def test_preflight_fails_when_identity_registry_missing(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(cold_reset, "ROOT", tmp_path)
    monkeypatch.setattr(cold_reset, "DATA", data)
    monkeypatch.setattr(cold_reset.llm_preflight, "ROOT", tmp_path)
    monkeypatch.setattr(cold_reset.llm_preflight, "DATA", data)
    payload = cold_reset.preflight()
    assert payload["verdict"] == "NO-GO"
    assert any("protégés absents" in reason for reason in payload["reasons"])


def test_manifest_is_json_serializable(monkeypatch, tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    for name in cold_reset.PROTECTED_FILES:
        path = data / name
        if path.suffix == ".csv":
            path.write_text("x\n", encoding="utf-8")
        else:
            path.write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(cold_reset, "ROOT", tmp_path)
    monkeypatch.setattr(cold_reset, "DATA", data)
    monkeypatch.setattr(cold_reset.llm_preflight, "ROOT", tmp_path)
    monkeypatch.setattr(cold_reset.llm_preflight, "DATA", data)
    payload = cold_reset.manifest()
    assert payload["schema"] == "cyberwatch-cold-reset-manifest-v1"
    json.dumps(payload)
