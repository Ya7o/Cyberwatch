"""Historique compact et détection de dérive de la qualification."""
from __future__ import annotations
from collections import defaultdict
from datetime import datetime, timezone

def history_rows(report: dict[str, object], *, run_id: str, recorded_at: str | None = None) -> list[dict[str, object]]:
    stamp = recorded_at or datetime.now(timezone.utc).isoformat()
    decision_by_field = defaultdict(lambda: {"Decisions": 0, "Applied": 0, "Rejected": 0, "Protected": 0})
    for row in report.get("decision_summary", []):
        bucket = decision_by_field[row["Field"]]
        for key in bucket: bucket[key] += int(row.get(key, 0))
    rows = []
    for coverage in report.get("coverage", []):
        rows.append({"Run_ID": run_id, "Recorded_At": stamp, "Source_ID": coverage["Source_ID"], "Field": coverage["Field"],
                     "Total": int(coverage["Total"]), "Known": int(coverage["Known"]), "Unknown": int(coverage["Unknown"]),
                     "Coverage_pct": float(coverage["Coverage_pct"]), **decision_by_field[coverage["Field"]]})
    return rows

def detect_source_drift(current, history, *, lookback=5, coverage_drop_pct=2.0, unknown_growth_pct=10.0):
    previous = defaultdict(list)
    for row in history: previous[(row["Source_ID"], row["Field"])].append(row)
    alerts = []
    for row in current:
        key = (row["Source_ID"], row["Field"]); samples = previous.get(key, [])[-lookback:]
        if not samples: continue
        avg_cov = sum(float(x["Coverage_pct"]) for x in samples) / len(samples)
        avg_unknown = sum(int(x["Unknown"]) for x in samples) / len(samples)
        cov_drop = avg_cov - float(row["Coverage_pct"])
        unknown_growth = ((int(row["Unknown"]) - avg_unknown) / max(avg_unknown, 1.0)) * 100.0
        reasons = []
        if cov_drop >= coverage_drop_pct: reasons.append(f"coverage_drop={cov_drop:.1f}pp")
        if int(row["Unknown"]) >= 3 and unknown_growth >= unknown_growth_pct: reasons.append(f"unknown_growth={unknown_growth:.1f}%")
        if reasons:
            alerts.append({"Source_ID": key[0], "Field": key[1], "Run_ID": row["Run_ID"], "Severity": "WARN", "Reasons": reasons,
                           "Coverage_pct": row["Coverage_pct"], "Baseline_coverage_pct": round(avg_cov, 1),
                           "Unknown": row["Unknown"], "Baseline_unknown": round(avg_unknown, 1)})
    return alerts
