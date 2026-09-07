"""Fenêtres temporelles de publication du dashboard.

Le libellé « 30 jours » doit être ancré sur la date du run publié, jamais sur
la date du dernier incident observé. Sinon une période sans incident conserve
indéfiniment d'anciennes cartes tout en les présentant comme récentes.
"""
from __future__ import annotations

from datetime import date, timedelta


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
