"""Références stables pour le golden de déduplication.

Le golden historique stocke des Item_ID, qui peuvent changer lors d'une
reconstruction. Ce module résout en priorité une identité source persistante :
Source_ID + Source_Item_ID quand l'ID natif existe, sinon Source_ID + URL.
L'Item_ID reste conservé comme trace et fallback de compatibilité pendant la
migration.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Item

RESOLVED = "RESOLVED"
MISSING = "MISSING"
AMBIGUOUS = "AMBIGUOUS"
LEGACY = "LEGACY"

STABLE_REF_COLUMNS = (
    "Left_Source_ID",
    "Left_Source_Item_ID",
    "Left_Stable_URL",
    "Right_Source_ID",
    "Right_Source_Item_ID",
    "Right_Stable_URL",
)


@dataclass(frozen=True)
class GoldenResolution:
    status: str
    item: Item | None
    candidates: tuple[str, ...] = ()


def stable_ref_for_item(item: Item) -> tuple[str, str, str]:
    """Retourne (Source_ID, Source_Item_ID, URL) pour persistance Golden."""
    return item.Source_ID, item.Source_Item_ID or "", item.URL or ""


def _matches_stable_ref(
    item: Item,
    source_id: str,
    source_item_id: str,
    stable_url: str,
) -> bool:
    if not source_id or item.Source_ID != source_id:
        return False
    if source_item_id:
        return item.Source_Item_ID == source_item_id
    if stable_url:
        return item.URL == stable_url
    return False


def resolve_golden_side(
    row: dict[str, str],
    side: str,
    items: list[Item],
) -> GoldenResolution:
    """Résout un côté Left/Right du golden de façon déterministe."""
    source_id = (row.get(f"{side}_Source_ID") or "").strip()
    source_item_id = (row.get(f"{side}_Source_Item_ID") or "").strip()
    stable_url = (row.get(f"{side}_Stable_URL") or "").strip()
    item_id = (row.get(f"{side}_Item_ID") or "").strip()

    if source_id and (source_item_id or stable_url):
        matches = [
            item for item in items
            if _matches_stable_ref(item, source_id, source_item_id, stable_url)
        ]
        if len(matches) == 1:
            return GoldenResolution(RESOLVED, matches[0], (matches[0].Item_ID,))
        if len(matches) > 1:
            return GoldenResolution(
                AMBIGUOUS,
                None,
                tuple(sorted(item.Item_ID for item in matches)),
            )
        return GoldenResolution(MISSING, None)

    # Compatibilité temporaire avec DEDUP-GOLDEN-1 avant migration complète.
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
        source_id, source_item_id, stable_url = stable_ref_for_item(item)
        enriched[f"{side}_Source_ID"] = source_id
        enriched[f"{side}_Source_Item_ID"] = source_item_id
        enriched[f"{side}_Stable_URL"] = stable_url
    return enriched


def has_stable_refs(row: dict[str, str]) -> bool:
    for side in ("Left", "Right"):
        source_id = (row.get(f"{side}_Source_ID") or "").strip()
        source_item_id = (row.get(f"{side}_Source_Item_ID") or "").strip()
        stable_url = (row.get(f"{side}_Stable_URL") or "").strip()
        if not source_id or not (source_item_id or stable_url):
            return False
    return True
