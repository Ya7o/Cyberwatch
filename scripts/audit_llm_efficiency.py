"""Audit offline du rendement LLM à partir des métriques déjà versionnées.

Aucun appel API n'est effectué. Le script produit une vue commune qui permet de
comparer coût, latence, cache et rendement sans confondre volume d'appels et
qualité utile.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _csv_last(path: Path) -> dict[str, str]:
    try:
        with path.open(encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))
    except OSError:
        return {}
    return rows[-1] if rows else {}


def _num(value: object) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _ratio(num: float, den: float) -> float:
    return round(num / den, 4) if den else 0.0


def build_report(root: Path = ROOT) -> dict[str, Any]:
    shared = _json(root / "data" / "llm_usage.json")
    source_facts = _json(root / "data" / "source_facts_ai_usage.json")
    qualification = _csv_last(root / "data" / "ai_usage.csv")

    sf_calls = _num(source_facts.get("calls_attempted"))
    sf_cost = _num(source_facts.get("estimated_cost_usd"))
    sf_duration = _num(source_facts.get("total_duration_seconds"))
    sf_cache = _num(source_facts.get("items_fully_cached")) + _num(source_facts.get("items_partially_cached"))
    sf_eligible = _num(source_facts.get("items_eligible"))
    sf_recovered = _num(source_facts.get("semantic_recovered_on_retry"))
    sf_retries = _num(source_facts.get("semantic_retries"))

    q_calls = _num(qualification.get("Calls_Attempted"))
    q_cost = _num(qualification.get("Estimated_Cost_USD"))
    q_duration = _num(qualification.get("Duration_s"))
    q_cache = _num(qualification.get("Cache_Hits"))
    q_candidates = _num(qualification.get("Candidates"))
    q_qualified = sum(
        _num(qualification.get(name))
        for name in ("Threat_Qualified", "Sector_Qualified", "Location_Qualified")
    )

    warnings: list[str] = []
    if sf_retries and not sf_recovered:
        warnings.append("source_facts semantic retries have zero observed recovery")
    if sf_eligible and _ratio(sf_cache, sf_eligible) < 0.25:
        warnings.append("source_facts cache reuse is below 25% on the recorded run")
    if q_calls and q_qualified == 0:
        warnings.append("qualification spent calls without qualifying any tracked field")

    return {
        "shared_runtime": {
            "calls_attempted": int(_num(shared.get("calls_attempted"))),
            "calls_succeeded": int(_num(shared.get("calls_succeeded"))),
            "calls_failed": int(_num(shared.get("calls_failed"))),
            "calls_budget_blocked": int(_num(shared.get("calls_budget_blocked"))),
            "estimated_cost_usd": round(_num(shared.get("estimated_cost_usd")), 6),
            "duration_seconds": round(_num(shared.get("duration_seconds")), 3),
            "by_task": shared.get("by_task") if isinstance(shared.get("by_task"), dict) else {},
        },
        "source_facts": {
            "calls": int(sf_calls),
            "estimated_cost_usd": round(sf_cost, 6),
            "duration_seconds": round(sf_duration, 3),
            "cache_reuse_rate": _ratio(sf_cache, sf_eligible),
            "semantic_retry_recovery_rate": _ratio(sf_recovered, sf_retries),
            "cost_per_call_usd": round(_ratio(sf_cost, sf_calls), 6),
            "duration_per_call_seconds": round(_ratio(sf_duration, sf_calls), 3),
        },
        "qualification": {
            "calls": int(q_calls),
            "estimated_cost_usd": round(q_cost, 6),
            "run_duration_seconds": round(q_duration, 3),
            "candidate_cache_hit_rate": _ratio(q_cache, q_candidates),
            "qualified_fields": int(q_qualified),
            "cost_per_qualified_field_usd": round(_ratio(q_cost, q_qualified), 6),
        },
        "warnings": warnings,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--json", action="store_true", dest="as_json")
    args = parser.parse_args()
    report = build_report(args.root)
    if args.as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 0

    print("LLM efficiency audit")
    for section in ("shared_runtime", "source_facts", "qualification"):
        print(f"\n[{section}]")
        for key, value in report[section].items():
            if key != "by_task":
                print(f"{key}: {value}")
    if report["warnings"]:
        print("\n[warnings]")
        for warning in report["warnings"]:
            print(f"- {warning}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
