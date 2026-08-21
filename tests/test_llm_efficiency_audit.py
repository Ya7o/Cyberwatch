from __future__ import annotations

import csv
import importlib.util
import json
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_llm_efficiency.py"
spec = importlib.util.spec_from_file_location("audit_llm_efficiency", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


def test_build_report_aggregates_cost_cache_and_retry_yield(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "llm_usage.json").write_text(json.dumps({
        "calls_attempted": 4,
        "calls_succeeded": 3,
        "calls_failed": 1,
        "estimated_cost_usd": 0.02,
        "duration_seconds": 8.0,
        "by_task": {"source_facts": {"calls_attempted": 4}},
    }), encoding="utf-8")
    (data / "source_facts_ai_usage.json").write_text(json.dumps({
        "calls_attempted": 4,
        "estimated_cost_usd": 0.01,
        "total_duration_seconds": 8,
        "items_fully_cached": 2,
        "items_partially_cached": 1,
        "items_eligible": 6,
        "semantic_retries": 2,
        "semantic_recovered_on_retry": 1,
    }), encoding="utf-8")
    with (data / "ai_usage.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=[
            "Calls_Attempted", "Estimated_Cost_USD", "Duration_s", "Cache_Hits",
            "Candidates", "Threat_Qualified", "Sector_Qualified", "Location_Qualified",
        ])
        writer.writeheader()
        writer.writerow({
            "Calls_Attempted": 2,
            "Estimated_Cost_USD": 0.004,
            "Duration_s": 5,
            "Cache_Hits": 4,
            "Candidates": 8,
            "Threat_Qualified": 0,
            "Sector_Qualified": 1,
            "Location_Qualified": 1,
        })

    report = module.build_report(tmp_path)

    assert report["shared_runtime"]["calls_attempted"] == 4
    assert report["source_facts"]["cache_reuse_rate"] == 0.5
    assert report["source_facts"]["semantic_retry_recovery_rate"] == 0.5
    assert report["qualification"]["candidate_cache_hit_rate"] == 0.5
    assert report["qualification"]["cost_per_qualified_field_usd"] == 0.002
    assert report["warnings"] == []


def test_report_flags_zero_yield_semantic_retries(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "source_facts_ai_usage.json").write_text(json.dumps({
        "calls_attempted": 4,
        "items_eligible": 4,
        "semantic_retries": 3,
        "semantic_recovered_on_retry": 0,
    }), encoding="utf-8")

    report = module.build_report(tmp_path)

    assert any("zero observed recovery" in warning for warning in report["warnings"])
