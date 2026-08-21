"""Décisions offline sur le portefeuille de sources Cyberwatch.

Ce module transforme le scorecard existant en actions explicites sans réseau,
sans mutation du référentiel et sans nouvelle source de vérité. Il répond à deux
questions : quelles sources actives méritent surveillance/désactivation, et
quelles sources inactives du référentiel sont les meilleures candidates à
réévaluer pour combler les angles morts observés ?
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from . import config, source_scorecard, sources


def _active_action(row: dict[str, Any]) -> tuple[str, list[str]]:
    score = float(row.get("value_index", 0) or 0)
    reliability = row.get("reliability_pct")
    recent_runs = int(row.get("recent_runs", 0) or 0)
    exclusive = int(row.get("exclusive_incidents", 0) or 0)
    warnings = list(row.get("warnings") or [])
    reasons: list[str] = []

    if score >= 65:
        return "KEEP", [f"value_index={score:.1f}"]

    if score < 35 and recent_runs >= 5 and reliability is not None and float(reliability) < 50 and exclusive == 0:
        reasons.extend([
            f"value_index={score:.1f}",
            f"reliability={float(reliability):.0f}%/{recent_runs} runs",
            "no_exclusive_incident",
        ])
        return "DEACTIVATION_CANDIDATE", reasons

    if score < 50:
        reasons.append(f"value_index={score:.1f}")
        reasons.extend(warnings[:3])
        return "REVIEW", reasons

    reasons.append(f"value_index={score:.1f}")
    reasons.extend(warnings[:2])
    return "WATCH", reasons


def _candidate_priority(spec, missing_locations: set[str]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    zone = str(spec.zone or "")

    if zone in missing_locations:
        score += 50
        reasons.append("fills_observed_location_gap")
    elif zone and zone != config.LOC_FRANCE:
        score += 20
        reasons.append("regional_diversification")

    if spec.layer == config.LAYER_CORE:
        score += 20
        reasons.append("direct_core_source")
    elif spec.layer != config.LAYER_DISABLED:
        score += 10
        reasons.append("declared_operational_layer")

    collector = str(spec.collector or "")
    if collector and collector != "autodetect":
        score += 10
        reasons.append("dedicated_collector_contract")

    if spec.start_url:
        score += 5
        reasons.append("known_start_url")
    if spec.success_test:
        score += 5
        reasons.append("explicit_success_test")

    notes = str(spec.notes or "").lower()
    if "403" in notes or "404" in notes or "coquille javascript" in notes:
        score -= 25
        reasons.append("known_access_blocker")
    if "réactiver" in notes or "reactiver" in notes:
        reasons.append("reactivation_condition_documented")

    return max(0, score), reasons


def build_portfolio(scorecard: dict[str, Any], specs) -> dict[str, Any]:
    score_rows = {row["source_id"]: row for row in scorecard.get("sources", [])}
    active: list[dict[str, Any]] = []
    for spec in sorted((s for s in specs if s.active), key=lambda s: s.source_id):
        row = score_rows.get(spec.source_id, {"source_id": spec.source_id, "value_index": 0, "warnings": ["missing_scorecard_row"]})
        action, reasons = _active_action(row)
        active.append({
            "source_id": spec.source_id,
            "zone": spec.zone,
            "action": action,
            "reasons": reasons,
            "value_index": row.get("value_index", 0),
            "reliability_pct": row.get("reliability_pct"),
            "exclusive_incidents": row.get("exclusive_incidents", 0),
            "recent_runs": row.get("recent_runs", 0),
        })

    missing = set(scorecard.get("coverage", {}).get("missing_tracked_locations", []))
    inactive: list[dict[str, Any]] = []
    for spec in sorted((s for s in specs if not s.active), key=lambda s: s.source_id):
        priority, reasons = _candidate_priority(spec, missing)
        inactive.append({
            "source_id": spec.source_id,
            "zone": spec.zone,
            "layer": spec.layer,
            "collector": spec.collector,
            "priority": priority,
            "reasons": reasons,
            "start_url": spec.start_url,
        })
    inactive.sort(key=lambda row: (-row["priority"], row["source_id"]))

    counts: dict[str, int] = {}
    for row in active:
        counts[row["action"]] = counts.get(row["action"], 0) + 1

    return {
        "schema": "cyberwatch-source-portfolio-v1",
        "as_of": scorecard.get("as_of", ""),
        "snapshot_run_id": scorecard.get("snapshot_run_id", ""),
        "active_decisions": active,
        "inactive_candidates": inactive,
        "coverage_gaps": sorted(missing),
        "decision_counts": dict(sorted(counts.items())),
        "policy": {
            "deactivation": "candidate only when value_index <35, >=5 recent runs, reliability <50%, and zero exclusive incidents; never auto-mutates sources.py",
            "candidate_priority": "observed geographic gap > regional diversification > direct/core contract > dedicated collector > documented access; known blockers subtract priority",
            "note": "Decisions are evidence-based prompts for maintenance, not automatic source enable/disable actions.",
        },
    }


def current_portfolio(recent_runs: int = 10) -> dict[str, Any]:
    scorecard = source_scorecard.current_scorecard(recent_runs)
    return build_portfolio(scorecard, sources.ALL_SOURCES)


def markdown(payload: dict[str, Any]) -> str:
    lines = [
        "### Source portfolio",
        "",
        "| Source active | Action | Index | Fiabilité | Exclusifs | Raisons |",
        "|---|---|---:|---:|---:|---|",
    ]
    for row in payload.get("active_decisions", []):
        reliability = "—" if row.get("reliability_pct") is None else f"{float(row['reliability_pct']):.0f}%"
        lines.append(
            f"| {row['source_id']} | **{row['action']}** | {float(row.get('value_index', 0)):.1f} | "
            f"{reliability} | {row.get('exclusive_incidents', 0)} | {', '.join(row.get('reasons', []))} |"
        )

    candidates = payload.get("inactive_candidates", [])[:5]
    lines.extend(["", "#### Candidats inactifs à réévaluer", "", "| Priorité | Source | Zone | Raisons |", "|---:|---|---|---|"])
    for row in candidates:
        lines.append(f"| {row['priority']} | {row['source_id']} | {row['zone']} | {', '.join(row['reasons'])} |")

    gaps = payload.get("coverage_gaps", [])
    lines.extend([
        "",
        f"Angles morts observés : **{', '.join(gaps) or 'aucun territoire sans incident'}**.",
        "",
        "> Aucune source n'est activée ou désactivée automatiquement : le portefeuille transforme les métriques en décisions vérifiables.",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyberwatch.source_portfolio")
    parser.add_argument("--recent-runs", type=int, default=10)
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    payload = current_portfolio(max(1, args.recent_runs))
    text = markdown(payload) if args.markdown else json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
    if args.output:
        Path(args.output).write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
