"""Fenêtres temporelles de publication du dashboard.

Le libellé « 30 jours » doit être ancré sur la date du run publié, jamais sur
la date du dernier incident observé. Sinon une période sans incident conserve
indéfiniment d'anciennes cartes tout en les présentant comme récentes.
"""
from __future__ import annotations

from datetime import date, timedelta

COVERAGE_WINDOW_DAYS = 30
TREND_REQUIRED_DAYS = 2 * COVERAGE_WINDOW_DAYS


def iso_day(value: object) -> date | None:
    """Retourne le jour ISO d'une date ou d'un timestamp, sinon ``None``."""
    try:
        return date.fromisoformat(str(value or "")[:10])
    except (TypeError, ValueError):
        return None


def latest_rows(payload: list[dict], as_of: object, *, window_days: int = 30) -> list[dict]:
    """Sélectionne la fenêtre inclusive terminant au jour ``as_of``.

    Le repli sur le jour maximum du payload préserve la compatibilité des
    appels historiques qui n'ont pas de contexte de run, mais le site public
    passe toujours explicitement ``status.run.as_of``.
    """
    if window_days < 1:
        raise ValueError("window_days doit être >= 1")

    reference = iso_day(as_of)
    if reference is None:
        days = [day for day in (iso_day(row.get("date")) for row in payload) if day]
        if not days:
            return []
        reference = max(days)

    cutoff = reference - timedelta(days=window_days - 1)
    recent = []
    for row in payload:
        day = iso_day(row.get("date"))
        if day is not None and cutoff <= day <= reference:
            recent.append(row)

    recent.sort(
        key=lambda row: (str(row.get("date") or ""), str(row.get("id") or "")),
        reverse=True,
    )
    return recent


def coverage_status(run_log: list[dict]) -> dict:
    """Décrit la couverture continue du corpus depuis le dernier ``CREATE``.

    Les tendances comparent 30 jours aux 30 jours précédents : elles ne sont
    publiables qu'après 60 jours continus. Un simple minimum/maximum masquerait
    les trous de collecte ; les intervalles sont donc fusionnés et seul le
    segment continu qui se termine sur le run le plus récent est retenu.
    """
    last_create = -1
    for index, row in enumerate(run_log):
        if (
            str(row.get("Mode") or "").upper() == "CREATE"
            and str(row.get("Overall_Status") or "").upper() == "OK"
        ):
            last_create = index

    empty = {
        "known": False,
        "start": "",
        "end": "",
        "days": 0,
        "window_days": COVERAGE_WINDOW_DAYS,
        "trend_required_days": TREND_REQUIRED_DAYS,
        "trend_ready": False,
    }
    if last_create < 0:
        return empty

    intervals: list[tuple[date, date]] = []
    for row in run_log[last_create:]:
        mode = str(row.get("Mode") or "").upper()
        if mode not in {"CREATE", "MAJ"}:
            continue
        if str(row.get("Overall_Status") or "").upper() != "OK":
            continue
        start = iso_day(row.get("Target_Start"))
        end = iso_day(row.get("Target_End") or row.get("As_Of"))
        if start is not None and end is not None and start <= end:
            intervals.append((start, end))

    if not intervals:
        return empty

    merged: list[list[date]] = []
    for start, end in sorted(intervals):
        if not merged or start > merged[-1][1] + timedelta(days=1):
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    start, end = max(merged, key=lambda interval: interval[1])
    days = (end - start).days + 1
    return {
        "known": True,
        "start": start.isoformat(),
        "end": end.isoformat(),
        "days": days,
        "window_days": COVERAGE_WINDOW_DAYS,
        "trend_required_days": TREND_REQUIRED_DAYS,
        "trend_ready": days >= TREND_REQUIRED_DAYS,
    }
