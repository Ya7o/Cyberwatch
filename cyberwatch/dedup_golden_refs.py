"""Références stables pour le golden de déduplication.

Le golden historique stocke des Item_ID, qui peuvent changer lors d'une
reconstruction. Ce module résout une identité source persistante : Source_ID +
Source_Item_ID quand l'ID natif existe ; pour les sources sans ID natif ou qui
réutilisent une même URL, l'URL est complétée par la date de publication et le
nom brut de victime. L'Item_ID reste une trace de migration, pas l'identité du
cas certifié.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Item

RESOLVED = "RESOLVED"
MISSING = "MISSING"
AMBIGUOUS = "AMBIGUOUS"
LEGACY = "LEGACY"

LEFT_STABLE_REF_COLUMNS = (
    "Left_Source_ID",
    "Left_Source_Item_ID",
    "Left_Stable_URL",
    "Left_Stable_Published_Date",
    "Left_Stable_Organisation_Raw",
)
RIGHT_STABLE_REF_COLUMNS = (
    "Right_Source_ID",
    "Right_Source_Item_ID",
    "Right_Stable_URL",
    "Right_Stable_Published_Date",
    "Right_Stable_Organisation_Raw",
)
STABLE_REF_COLUMNS = LEFT_STABLE_REF_COLUMNS + RIGHT_STABLE_REF_COLUMNS


@dataclass(frozen=True)
class GoldenResolution:
    status: str
    item: Item | None
    candidates: tuple[str, ...] = ()


def stable_ref_for_item(item: Item) -> tuple[str, str, str, str, str]:
    """Retourne les discriminants source persistants d'un item."""
    return (
        item.Source_ID,
        item.Source_Item_ID or "",
        item.URL or "",
        item.Published_Date or "",
        item.Organisation_Raw or "",
    )


def _resolution(matches: list[Item]) -> GoldenResolution:
    if len(matches) == 1:
        item = matches[0]
        return GoldenResolution(RESOLVED, item, (item.Item_ID,))
    if len(matches) > 1:
        return GoldenResolution(
            AMBIGUOUS,
            None,
            tuple(sorted(item.Item_ID for item in matches)),
        )
    return GoldenResolution(MISSING, None)


def _narrow(
    matches: list[Item],
    *,
    stable_url: str,
    published_date: str,
    organisation_raw: str,
) -> list[Item]:
    """Affûte un ensemble ambigu sans rendre un discriminant optionnel bloquant."""
    narrowed = matches
    for expected, getter in (
        (stable_url, lambda item: item.URL),
        (published_date, lambda item: item.Published_Date),
        (organisation_raw, lambda item: item.Organisation_Raw),
    ):
        if not expected or len(narrowed) <= 1:
            continue
        candidates = [item for item in narrowed if getter(item) == expected]
        if candidates:
            narrowed = candidates
    return narrowed


def resolve_golden_side(
    row: dict[str, str],
    side: str,
    items: list[Item],
) -> GoldenResolution:
    """Résout un côté Left/Right du golden sans choix arbitraire."""
    source_id = (row.get(f"{side}_Source_ID") or "").strip()
    source_item_id = (row.get(f"{side}_Source_Item_ID") or "").strip()
    stable_url = (row.get(f"{side}_Stable_URL") or "").strip()
    published_date = (row.get(f"{side}_Stable_Published_Date") or "").strip()
    organisation_raw = (row.get(f"{side}_Stable_Organisation_Raw") or "").strip()
    item_id = (row.get(f"{side}_Item_ID") or "").strip()

    if source_id and source_item_id:
        matches = [
            item for item in items
            if item.Source_ID == source_id and item.Source_Item_ID == source_item_id
        ]
        if len(matches) > 1:
            matches = _narrow(
                matches,
                stable_url=stable_url,
                published_date=published_date,
                organisation_raw=organisation_raw,
            )
        return _resolution(matches)

    if source_id and stable_url:
        matches = [
            item for item in items
            if item.Source_ID == source_id and item.URL == stable_url
        ]
        if len(matches) > 1:
            matches = _narrow(
                matches,
                stable_url="",
                published_date=published_date,
                organisation_raw=organisation_raw,
            )
        return _resolution(matches)

    # Compatibilité temporaire pendant la migration DEDUP-GOLDEN-1 -> stable refs.
    if item_id:
        matches = [item for item in items if item.Item_ID == item_id]
        if len(matches) == 1:
            return GoldenResolution(LEGACY, matches[0], (item_id,))
    return GoldenResolution(MISSING, None)


def enrich_golden_row(row: dict[str, str], items_by_id: dict[str, Item]) -> dict[str, str]:
    """Ajoute les références stables à une ligne Golden historique."""
    enriched = dict(row)
    for side in ("Left", "Right"):
        item_id = (row.get(f"{side}_Item_ID") or "").strip()
        item = items_by_id.get(item_id)
        if item is None:
            raise KeyError(f"{row.get('Case_ID', '<unknown>')}:{side}:{item_id}")
        source_id, source_item_id, stable_url, published_date, organisation_raw = stable_ref_for_item(item)
        enriched[f"{side}_Source_ID"] = source_id
        enriched[f"{side}_Source_Item_ID"] = source_item_id
        enriched[f"{side}_Stable_URL"] = stable_url
        enriched[f"{side}_Stable_Published_Date"] = published_date
        enriched[f"{side}_Stable_Organisation_Raw"] = organisation_raw
    return enriched


def has_stable_refs(row: dict[str, str]) -> bool:
    for side in ("Left", "Right"):
        source_id = (row.get(f"{side}_Source_ID") or "").strip()
        source_item_id = (row.get(f"{side}_Source_Item_ID") or "").strip()
        stable_url = (row.get(f"{side}_Stable_URL") or "").strip()
        published_date = (row.get(f"{side}_Stable_Published_Date") or "").strip()
        organisation_raw = (row.get(f"{side}_Stable_Organisation_Raw") or "").strip()
        if not source_id:
            return False
        if source_item_id:
            continue
        if not stable_url or not published_date or not organisation_raw:
            return False
    return True
