"""Baseline et audit offline du reset total.

Ce module ne fait aucun appel réseau et ne modifie aucune donnée métier. Il
mesure un snapshot reconstruit, compare deux états et peut figer la baseline
post-reset officielle dans un JSON dédié.
"""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA = ROOT / "data"
UNKNOWN = {"", "inconnu", "unknown", "n/a", "na", "none", "null"}


def _rows(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _int(value: Any) -> int:
    try:
        return int(float(value or 0))
    except (TypeError, ValueError):
        return 0


def _known(value: Any) -> bool:
    return str(value or "").strip().lower() not in UNKNOWN


def _coverage(rows: list[dict[str, str]], column: str) -> dict[str, Any]:
    total = len(rows)
    known = sum(1 for row in rows if _known(row.get(column)))
    unknown = total - known
    return {
        "known": known,
        "unknown": unknown,
        "known_pct": round((known / total * 100) if total else 0.0, 2),
        "unknown_pct": round((unknown / total * 100) if total else 0.0, 2),
    }


def _duplicate_count(rows: list[dict[str, str]], column: str) -> int:
    values = [str(row.get(column) or "").strip() for row in rows if row.get(column)]
    counts = Counter(values)
    return sum(count - 1 for count in counts.values() if count > 1)


def _latest_run(run_log: list[dict[str, str]]) -> dict[str, str]:
    return run_log[-1] if run_log else {}


def _latest_source_rows(run_sources: list[dict[str, str]], run_id: str) -> list[dict[str, str]]:
    if run_id:
        matched = [row for row in run_sources if row.get("Run_ID") == run_id]
        if matched:
            return matched
    if not run_sources:
        return []
    latest = run_sources[-1].get("Run_ID", "")
    return [row for row in run_sources if row.get("Run_ID") == latest]


def _latest_usage(rows: list[dict[str, str]], run_id: str) -> dict[str, str]:
    """Return usage for the audited run, never a stale previous run."""
    if run_id:
        matched = [row for row in rows if row.get("Run_ID") == run_id]
        if matched:
            return matched[-1]
    return {}


def _facts_quality(data_dir: Path, incident_count: int) -> dict[str, Any]:
    path = data_dir / "source_facts_backfill_report.json"
    if not path.exists():
        return {
            "report_available": False,
            "incidents_reported": 0,
            "summary_accepted": 0,
            "summary_accepted_pct": 0.0,
            "promotion_gaps": 0,
        }
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        payload = {}
    rows = payload.get("incidents") if isinstance(payload, dict) else []
    rows = rows if isinstance(rows, list) else []
    accepted = sum(
        1 for row in rows
        if isinstance(row, dict) and row.get("summary_status") == "accepted"
    )
    gaps = sum(
        len(row.get("promotion_gaps") or [])
        for row in rows if isinstance(row, dict)
    )
    return {
        "report_available": True,
        "incidents_reported": len(rows),
        "incident_coverage_pct": round((len(rows) / incident_count * 100) if incident_count else 0.0, 2),
        "summary_accepted": accepted,
        "summary_accepted_pct": round((accepted / incident_count * 100) if incident_count else 0.0, 2),
        "promotion_gaps": gaps,
    }


def _llm_usage(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "llm_usage.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        "calls_attempted": _int(payload.get("calls_attempted")),
        "calls_succeeded": _int(payload.get("calls_succeeded")),
        "calls_failed": _int(payload.get("calls_failed")),
        "estimated_cost_usd": round(_float(payload.get("estimated_cost_usd")), 6),
        "duration_seconds": round(_float(payload.get("duration_seconds")), 3),
        "total_tokens": _int(payload.get("total_tokens")),
        "by_task": payload.get("by_task") or {},
    }


def build_baseline(data_dir: Path = DEFAULT_DATA) -> dict[str, Any]:
    items = _rows(data_dir / "items.csv")
    incidents = _rows(data_dir / "incidents.csv")
    run_log = _rows(data_dir / "run_log.csv")
    run_sources = _rows(data_dir / "run_sources.csv")
    latest = _latest_run(run_log)
    latest_run_id = latest.get("Run_ID", "")
    source_rows = _latest_source_rows(run_sources, latest_run_id)
    qualification_usage = _latest_usage(_rows(data_dir / "ai_usage.csv"), latest_run_id)
    dedup_usage = _latest_usage(_rows(data_dir / "dedup_ai_daily_usage.csv"), latest_run_id)

    item_sources = Counter(row.get("Source_ID", "") for row in items if row.get("Source_ID"))
    sources: dict[str, Any] = {}
    for row in source_rows:
        source_id = row.get("Source_ID", "")
        if not source_id:
            continue
        sources[source_id] = {
            "status": row.get("Status", ""),
            "coverage": row.get("Coverage", ""),
            "items": item_sources.get(source_id, 0),
            "items_collected": _int(row.get("Items_collected")),
            "new_items": _int(row.get("New_items")),
            "duration_seconds": round(_float(row.get("Duration_s")), 3),
            "collect_duration_seconds": round(_float(row.get("Collect_Duration_s")), 3),
            "processing_duration_seconds": round(_float(row.get("Processing_Duration_s")), 3),
        }

    item_count = len(items)
    incident_count = len(incidents)
    return {
        "schema": "cyberwatch-post-reset-baseline-v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "latest_run": {
            "run_id": latest_run_id,
            "as_of": latest.get("As_Of", ""),
            "mode": latest.get("Mode", ""),
            "target_start": latest.get("Target_Start", ""),
            "target_end": latest.get("Target_End", ""),
            "overall_status": latest.get("Overall_Status", ""),
            "duration_seconds": round(_float(latest.get("Duration_s")), 3),
            "requests": _int(latest.get("Requests")),
        },
        "volume": {
            "items": item_count,
            "incidents": incident_count,
            "items_per_incident": round((item_count / incident_count) if incident_count else 0.0, 3),
            "duplicate_item_ids": _duplicate_count(items, "Item_ID"),
            "duplicate_incident_ids": _duplicate_count(incidents, "Incident_ID"),
        },
        "item_coverage": {
            "threat": _coverage(items, "Threat"),
            "sector": _coverage(items, "Sector"),
            "location": _coverage(items, "Location"),
        },
        "incident_coverage": {
            "threat": _coverage(incidents, "Menace"),
            "sector": _coverage(incidents, "Secteur"),
            "location": _coverage(incidents, "Localisation"),
        },
        "sources": sources,
        "qualification_ai": {
            "status": qualification_usage.get("Status", "MISSING"),
            "calls_attempted": _int(qualification_usage.get("Calls_Attempted")),
            "calls_succeeded": _int(qualification_usage.get("Calls_Succeeded")),
            "still_unknown": _int(qualification_usage.get("Still_Unknown")),
            "sector_remaining_unknown": _int(qualification_usage.get("Sector_Remaining_Unknown")),
        },
        "dedup_ai": {
            "status": dedup_usage.get("Status", "MISSING"),
            "candidates_generated": _int(dedup_usage.get("Candidates_Generated")),
            "candidates_selected": _int(dedup_usage.get("Candidates_Selected")),
            "llm_calls": _int(dedup_usage.get("LLM_Calls")),
            "review_required": _int(dedup_usage.get("Review_Required")),
        },
        "facts_quality": _facts_quality(data_dir, incident_count),
        "llm": _llm_usage(data_dir),
    }


def audit(
    after: dict[str, Any],
    before: dict[str, Any] | None = None,
    *,
    strict: bool = False,
) -> dict[str, Any]:
    blockers: list[str] = []
    warnings: list[str] = []
    volume = after.get("volume") or {}
    latest = after.get("latest_run") or {}

    if _int(volume.get("items")) <= 0:
        blockers.append("aucun item reconstruit")
    if _int(volume.get("incidents")) <= 0:
        blockers.append("aucun incident reconstruit")
    if _int(volume.get("duplicate_item_ids")):
        blockers.append("Item_ID dupliqués")
    if _int(volume.get("duplicate_incident_ids")):
        blockers.append("Incident_ID dupliqués")
    if latest.get("overall_status") and latest.get("overall_status") != "OK":
        blockers.append(f"dernier run non OK: {latest.get('overall_status')}")

    failed = [sid for sid, state in (after.get("sources") or {}).items() if state.get("status") == "FAIL"]
    if failed:
        blockers.append("sources en échec: " + ", ".join(sorted(failed)))

    if strict:
        partial = [
            sid for sid, state in (after.get("sources") or {}).items()
            if state.get("status") == "PARTIAL"
        ]
        if partial:
            blockers.append("sources partielles: " + ", ".join(sorted(partial)))

        coverage_limits = {"threat": 95.0, "sector": 75.0, "location": 80.0}
        incident_coverage = after.get("incident_coverage") or {}
        for field, minimum in coverage_limits.items():
            known_pct = _float((incident_coverage.get(field) or {}).get("known_pct"))
            if known_pct < minimum:
                blockers.append(
                    f"couverture incidents {field} insuffisante: {known_pct:.1f}% < {minimum:.1f}%"
                )

        qualification = after.get("qualification_ai") or {}
        if _int(qualification.get("sector_remaining_unknown")) and qualification.get("status") != "OK":
            blockers.append(
                "arbitrage LLM qualification non exécuté malgré des secteurs non résolus "
                f"(status={qualification.get('status') or 'MISSING'})"
            )

        dedup = after.get("dedup_ai") or {}
        if _int(dedup.get("candidates_generated")) and dedup.get("status") != "OK":
            blockers.append(
                "arbitrage LLM déduplication non exécuté malgré des candidats "
                f"(status={dedup.get('status') or 'MISSING'})"
            )
        if _int(dedup.get("review_required")):
            blockers.append("revues de déduplication encore requises")

        facts = after.get("facts_quality") or {}
        if not facts.get("report_available"):
            blockers.append("rapport de qualité des fiches incident absent")
        else:
            if _float(facts.get("incident_coverage_pct")) < 100.0:
                blockers.append("rapport de fiches incident incomplet")
            if _float(facts.get("summary_accepted_pct")) < 85.0:
                blockers.append(
                    "résumés de fiches incident insuffisants: "
                    f"{_float(facts.get('summary_accepted_pct')):.1f}% < 85.0%"
                )
            if _int(facts.get("promotion_gaps")):
                blockers.append("faits sémantiques extraits mais non publiés")

    deltas: dict[str, Any] = {}
    if before:
        old_volume = before.get("volume") or {}
        old_items = _int(old_volume.get("items"))
        old_incidents = _int(old_volume.get("incidents"))
        new_items = _int(volume.get("items"))
        new_incidents = _int(volume.get("incidents"))
        item_delta_pct = ((new_items - old_items) / old_items * 100) if old_items else 0.0
        incident_delta_pct = ((new_incidents - old_incidents) / old_incidents * 100) if old_incidents else 0.0
        deltas["items_pct"] = round(item_delta_pct, 2)
        deltas["incidents_pct"] = round(incident_delta_pct, 2)
        if item_delta_pct < -20:
            warnings.append(f"volume items en baisse de {abs(item_delta_pct):.1f}%")
        if incident_delta_pct < -20:
            warnings.append(f"volume incidents en baisse de {abs(incident_delta_pct):.1f}%")

        for field in ("threat", "sector", "location"):
            old_cov = _float(((before.get("item_coverage") or {}).get(field) or {}).get("known_pct"))
            new_cov = _float(((after.get("item_coverage") or {}).get(field) or {}).get("known_pct"))
            delta = new_cov - old_cov
            deltas[f"item_{field}_known_pp"] = round(delta, 2)
            if delta < -10:
                warnings.append(f"couverture {field} en baisse de {abs(delta):.1f} points")

    return {
        "schema": "cyberwatch-post-reset-audit-v1",
        "strict": strict,
        "verdict": "GO" if not blockers else "NO-GO",
        "blockers": blockers,
        "warnings": warnings,
        "deltas": deltas,
        "after": after,
    }


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON objet attendu: {path}")
    return value


def _write(payload: dict[str, Any], output: str | None) -> None:
    text = json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if output:
        Path(output).write_text(text, encoding="utf-8")
    else:
        print(text, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyberwatch.reset_baseline")
    sub = parser.add_subparsers(dest="command", required=True)

    baseline_parser = sub.add_parser("baseline")
    baseline_parser.add_argument("--data-dir", default=str(DEFAULT_DATA))
    baseline_parser.add_argument("--output")

    audit_parser = sub.add_parser("audit")
    audit_parser.add_argument("--data-dir", default=str(DEFAULT_DATA))
    audit_parser.add_argument("--before")
    audit_parser.add_argument("--output")
    audit_parser.add_argument(
        "--strict",
        action="store_true",
        help="applique les seuils bloquants de passage en préproduction",
    )

    args = parser.parse_args(argv)
    after = build_baseline(Path(args.data_dir))
    if args.command == "baseline":
        _write(after, args.output)
        return 0

    before = _load_json(Path(args.before)) if args.before else None
    payload = audit(after, before, strict=args.strict)
    _write(payload, args.output)
    return 0 if payload["verdict"] == "GO" else 2


if __name__ == "__main__":
    raise SystemExit(main())
