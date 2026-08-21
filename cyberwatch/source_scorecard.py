"""Scorecard offline de valeur des sources Cyberwatch.

Le module ne fait aucun accès réseau et ne modifie jamais les données. Il exploite
uniquement le snapshot courant, ITEMS, INCIDENTS et l'historique RUN_SOURCES pour
répondre à une question produit simple : quelles sources apportent réellement de
la valeur, où sont les angles morts et quels signaux justifient un prochain
investissement ?
"""
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

from . import config, sources, store

UNKNOWN = "Inconnu"


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


def _parse_date(value: str | None) -> date | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).date()
    except ValueError:
        try:
            return date.fromisoformat(raw[:10])
        except ValueError:
            return None


def _split_sources(value: str | None) -> set[str]:
    return {token.strip() for token in str(value or "").split("|") if token.strip()}


def _ratio(part: int, total: int) -> float:
    return round(part / total, 4) if total else 0.0


def _pct(part: int, total: int) -> float:
    return round(100.0 * part / total, 1) if total else 0.0


def _freshness_score(days: int | None) -> float:
    if days is None:
        return 0.0
    if days <= 2:
        return 100.0
    if days <= 7:
        return 80.0
    if days <= 30:
        return 50.0
    return 20.0


def _efficiency_score(items_per_call: float) -> float:
    if items_per_call >= 2.0:
        return 100.0
    if items_per_call >= 1.0:
        return 75.0
    if items_per_call >= 0.5:
        return 50.0
    if items_per_call > 0:
        return 25.0
    return 0.0


def _weighted_score(parts: list[tuple[float | None, float]]) -> float:
    available = [(value, weight) for value, weight in parts if value is not None]
    if not available:
        return 0.0
    weight_total = sum(weight for _, weight in available)
    return round(sum(float(value) * weight for value, weight in available) / weight_total, 1)


def _grade(score: float) -> str:
    if score >= 80:
        return "A"
    if score >= 65:
        return "B"
    if score >= 50:
        return "C"
    return "D"


def _latest_runs(run_rows: Iterable[dict], source_id: str, limit: int) -> list[dict]:
    rows = [row for row in run_rows if row.get("Source_ID") == source_id]
    rows.sort(key=lambda row: (row.get("As_Of", ""), row.get("Run_ID", "")))
    return rows[-limit:]


def build_scorecard(
    *,
    items: list[dict],
    incidents: list[dict],
    run_sources: list[dict],
    snapshot: dict,
    active_source_ids: list[str],
    recent_runs: int = 10,
) -> dict[str, Any]:
    as_of = _parse_date(snapshot.get("As_Of")) or date.today()
    item_by_source: dict[str, list[dict]] = defaultdict(list)
    for row in items:
        item_by_source[row.get("Source_ID", "")].append(row)

    incident_sources: list[tuple[dict, set[str]]] = [
        (row, _split_sources(row.get("Sources"))) for row in incidents
    ]

    source_rows: list[dict[str, Any]] = []
    for source_id in sorted(active_source_ids):
        source_items = item_by_source.get(source_id, [])
        touched = [row for row, ids in incident_sources if source_id in ids]
        exclusive = [row for row, ids in incident_sources if ids == {source_id}]
        corroborated = [row for row, ids in incident_sources if source_id in ids and len(ids) > 1]

        item_dates = [
            value
            for row in source_items
            for value in [_parse_date(row.get("Event_Date") or row.get("Published_Date"))]
            if value is not None
        ]
        latest = max(item_dates) if item_dates else None
        freshness_days = (as_of - latest).days if latest else None

        total = len(source_items)
        threat_unknown = sum(row.get("Threat") == UNKNOWN for row in source_items)
        sector_unknown = sum(row.get("Sector") == UNKNOWN for row in source_items)
        location_unknown = sum(row.get("Location") == UNKNOWN for row in source_items)
        completeness = 100.0 * (
            1.0
            - mean(
                [
                    _ratio(threat_unknown, total),
                    _ratio(sector_unknown, total),
                    _ratio(location_unknown, total),
                ]
            )
        ) if total else 0.0

        history = _latest_runs(run_sources, source_id, recent_runs)
        ok_runs = sum(row.get("Status") == "OK" for row in history)
        partial_runs = sum(row.get("Status") == "PARTIAL" for row in history)
        fail_runs = sum(row.get("Status") == "FAIL" for row in history)
        reliability = _pct(ok_runs, len(history)) if history else None
        avg_duration = round(mean(_float(row.get("Duration_s")) for row in history), 2) if history else 0.0
        total_calls = sum(_int(row.get("Calls")) for row in history)
        total_collected = sum(_int(row.get("Items_collected")) for row in history)
        items_per_call = round(total_collected / total_calls, 3) if total_calls else 0.0
        exclusivity = _pct(len(exclusive), len(touched)) if touched else 0.0

        score = _weighted_score(
            [
                (reliability, 30.0),
                (_freshness_score(freshness_days), 20.0),
                (round(completeness, 1), 20.0),
                (exclusivity, 20.0),
                (_efficiency_score(items_per_call), 10.0),
            ]
        )

        warnings: list[str] = []
        if not source_items:
            warnings.append("no_items")
        if freshness_days is not None and freshness_days > 30:
            warnings.append("stale_over_30d")
        if reliability is not None and reliability < 80:
            warnings.append("reliability_below_80pct")
        if _pct(threat_unknown, total) > 25:
            warnings.append("threat_unknown_over_25pct")
        if _pct(sector_unknown, total) > 50:
            warnings.append("sector_unknown_over_50pct")
        if _pct(location_unknown, total) > 50:
            warnings.append("location_unknown_over_50pct")
        if touched and not exclusive:
            warnings.append("no_exclusive_incident")

        source_rows.append(
            {
                "source_id": source_id,
                "value_index": score,
                "grade": _grade(score),
                "items": total,
                "incidents_touched": len(touched),
                "exclusive_incidents": len(exclusive),
                "corroborated_incidents": len(corroborated),
                "exclusive_share_pct": exclusivity,
                "unique_organisations": len({row.get("Organisation_Key") for row in source_items if row.get("Organisation_Key")}),
                "latest_item_date": latest.isoformat() if latest else "",
                "freshness_days": freshness_days,
                "recent_runs": len(history),
                "ok_runs": ok_runs,
                "partial_runs": partial_runs,
                "fail_runs": fail_runs,
                "reliability_pct": reliability,
                "avg_duration_s": avg_duration,
                "items_per_call": items_per_call,
                "threat_unknown_pct": _pct(threat_unknown, total),
                "sector_unknown_pct": _pct(sector_unknown, total),
                "location_unknown_pct": _pct(location_unknown, total),
                "completeness_pct": round(completeness, 1),
                "warnings": warnings,
            }
        )

    location_counts = Counter(row.get("Localisation") or UNKNOWN for row in incidents)
    threat_counts = Counter(row.get("Menace") or UNKNOWN for row in incidents)
    sector_counts = Counter(row.get("Secteur") or UNKNOWN for row in incidents)
    tracked = [location for location in config.LOCATIONS if location != config.LOC_INCONNU]
    missing_locations = [location for location in tracked if location_counts.get(location, 0) == 0]

    return {
        "schema": "cyberwatch-source-scorecard-v1",
        "as_of": snapshot.get("As_Of", ""),
        "snapshot_run_id": snapshot.get("Run_ID", ""),
        "items": len(items),
        "incidents": len(incidents),
        "sources": source_rows,
        "coverage": {
            "locations": dict(sorted(location_counts.items())),
            "threats": dict(sorted(threat_counts.items())),
            "sectors": dict(sorted(sector_counts.items())),
            "missing_tracked_locations": missing_locations,
            "unknown_location_pct": _pct(location_counts.get(UNKNOWN, 0), len(incidents)),
            "unknown_threat_pct": _pct(threat_counts.get(UNKNOWN, 0), len(incidents)),
            "unknown_sector_pct": _pct(sector_counts.get(UNKNOWN, 0), len(incidents)),
        },
        "method": {
            "value_index": "30% reliability + 20% freshness + 20% field completeness + 20% exclusive contribution + 10% collection efficiency; missing components are renormalized",
            "note": "The index is a prioritization aid, not a truth or quality certification.",
        },
    }


def current_scorecard(recent_runs: int = 10) -> dict[str, Any]:
    return build_scorecard(
        items=[item.to_row() for item in store.load_items()],
        incidents=[incident.to_row() for incident in store.load_incidents()],
        run_sources=store.load_run_sources(),
        snapshot=store.load_snapshot(),
        active_source_ids=sorted(spec.source_id for spec in sources.ALL_SOURCES if spec.active),
        recent_runs=recent_runs,
    )


def markdown(payload: dict[str, Any]) -> str:
    lines = [
        "### Source scorecard",
        "",
        "| Source | Index | Grade | Items | Incidents | Exclusifs | Fiabilité | Fraîcheur | Inconnu S/T/L |",
        "|---|---:|:---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in sorted(payload.get("sources", []), key=lambda value: (-value["value_index"], value["source_id"])):
        reliability = "—" if row["reliability_pct"] is None else f"{row['reliability_pct']:.0f}%"
        freshness = "—" if row["freshness_days"] is None else f"{row['freshness_days']} j"
        unknowns = f"{row['sector_unknown_pct']:.0f}/{row['threat_unknown_pct']:.0f}/{row['location_unknown_pct']:.0f}%"
        lines.append(
            f"| {row['source_id']} | {row['value_index']:.1f} | {row['grade']} | {row['items']} | "
            f"{row['incidents_touched']} | {row['exclusive_incidents']} | {reliability} | {freshness} | {unknowns} |"
        )
    coverage = payload.get("coverage", {})
    lines.extend(
        [
            "",
            f"Angles morts géographiques sans incident publié : **{', '.join(coverage.get('missing_tracked_locations', [])) or 'aucun'}**.",
            f"Inconnus incidents — secteur **{coverage.get('unknown_sector_pct', 0):.1f}%**, menace **{coverage.get('unknown_threat_pct', 0):.1f}%**, localisation **{coverage.get('unknown_location_pct', 0):.1f}%**.",
            "",
            "> L'index sert à prioriser les sources ; il ne certifie ni leur véracité ni leur exhaustivité.",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m cyberwatch.source_scorecard")
    parser.add_argument("--recent-runs", type=int, default=10)
    parser.add_argument("--markdown", action="store_true")
    parser.add_argument("--output", help="Écrire le JSON dans ce fichier en plus de stdout.")
    args = parser.parse_args(argv)
    payload = current_scorecard(max(1, args.recent_runs))
    if args.output:
        Path(args.output).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(markdown(payload) if args.markdown else json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
