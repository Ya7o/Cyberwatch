"""Répartitions descriptives par périmètre et période, ancrées sur le snapshot."""
from __future__ import annotations

from collections import Counter

from . import config, site_window


def _counts(rows: list[dict], field: str) -> list[dict]:
    counts = Counter(str(row.get(field) or "Inconnu") for row in rows)
    return [{"label": label, "count": count} for label, count in
            sorted(counts.items(), key=lambda pair: (-pair[1], pair[0]))]


def build(rows: list[dict], as_of: str) -> dict:
    """Les compteurs du graphique et la recherche partagent la même fenêtre."""
    scopes = {
        "all": None,
        "metro": {config.LOC_FRANCE},
        "focus": set(config.FOCUS_LOCATIONS),
        "ocean": set(config.OCEAN_LOCATIONS),
    }
    result = {}
    for scope, locations in scopes.items():
        scoped = [row for row in rows if locations is None or row.get("location") in locations]
        result[scope] = {}
        for period in ("30", "90", "365", "all"):
            selected = scoped if period == "all" else site_window.latest_rows(
                scoped, as_of, window_days=int(period),
            )
            dates = sorted(str(row["date"]) for row in selected if site_window.iso_day(row.get("date")))
            months = Counter(day[:7] for day in dates)
            result[scope][period] = {
                "incidents": len(selected),
                "organisations": len({str(row.get("org") or "") for row in selected}),
                "first_date": dates[0] if dates else "",
                "last_date": dates[-1] if dates else "",
                "undated": len(selected) - len(dates),
                "threat": _counts(selected, "threat"),
                "sector": _counts(selected, "sector"),
                "months": [{"label": month, "count": count} for month, count in sorted(months.items())],
            }
    return result
