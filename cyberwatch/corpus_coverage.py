"""Couverture temporelle cumulée du corpus canonique.

Un run ``MAJ`` ne décrit que sa propre fenêtre de collecte (souvent quelques
jours de chevauchement). Cette fenêtre ne doit donc jamais être confondue avec
la profondeur historique réellement présente dans le corpus. La couverture
cumulée repart du dernier ``CREATE`` réussi puis agrège les fenêtres des
``MAJ`` réussies qui suivent.
"""
from __future__ import annotations

from datetime import date
from typing import Iterable, Mapping


_WRITING_MODES = {"CREATE", "MAJ"}


def _day(value: object) -> date | None:
    text = str(value or "").strip()[:10]
    if not text:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def summarize(run_log: Iterable[Mapping[str, object]]) -> dict[str, object]:
    """Retourne la fenêtre cumulée depuis le dernier ``CREATE`` réussi.

    Les runs ``BROKEN`` ne peuvent pas élargir la couverture publiée, puisque
    le snapshot canonique n'est alors pas considéré comme validé.
    """
    rows = list(run_log)
    last_create = None
    for index, row in enumerate(rows):
        if (
            str(row.get("Mode") or "").upper() == "CREATE"
            and str(row.get("Overall_Status") or "").upper() == "OK"
        ):
            last_create = index

    if last_create is None:
        return {"start": "", "end": "", "days": 0, "basis": "unknown"}

    starts: list[date] = []
    ends: list[date] = []
    for row in rows[last_create:]:
        if str(row.get("Overall_Status") or "").upper() != "OK":
            continue
        if str(row.get("Mode") or "").upper() not in _WRITING_MODES:
            continue
        start = _day(row.get("Target_Start"))
        end = _day(row.get("Target_End") or row.get("As_Of"))
        if start is None or end is None or end < start:
            continue
        starts.append(start)
        ends.append(end)

    if not starts or not ends:
        return {"start": "", "end": "", "days": 0, "basis": "unknown"}

    start = min(starts)
    end = max(ends)
    return {
        "start": start.isoformat(),
        "end": end.isoformat(),
        "days": (end - start).days + 1,
        "basis": "last_successful_create_plus_updates",
    }


def needs_backfill(run_log: Iterable[Mapping[str, object]], target_start: str) -> bool:
    """Indique si la couverture cumulée commence après ``target_start``."""
    target = _day(target_start)
    if target is None:
        raise ValueError("target_start doit être une date ISO AAAA-MM-JJ")
    current = _day(summarize(run_log).get("start"))
    return current is None or current > target
