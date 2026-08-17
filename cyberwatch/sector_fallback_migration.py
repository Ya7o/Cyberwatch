"""Migration déterministe des anciens secteurs injectés par le fallback LLM.

Le fallback Sector historique pouvait promouvoir une valeur à partir d'une
simple URL externe. Lorsqu'une politique de preuve plus stricte est déployée,
ces valeurs déjà persistées doivent repasser par le nouveau garde ; sinon une
valeur devenue « connue » ne serait jamais réévaluée.

Cette migration ne touche qu'une valeur dont la provenance prouve qu'elle a été
ajoutée par ``LLM_SOURCE_FALLBACK`` depuis ``Inconnu`` et seulement si la valeur
courante est encore exactement celle qui avait été injectée. Une correction
ultérieure différente, manuelle ou issue d'une autre couche, est donc protégée.
"""

from __future__ import annotations

from . import config
from .model import Item

_FALLBACK_ORIGIN = "LLM_SOURCE_FALLBACK"


def restore_legacy_sector_fallbacks(
    items: list[Item],
    provenance_rows: list[dict[str, str]],
) -> int:
    """Restaure les anciens secteurs fallback à ``Inconnu`` avant revalidation.

    La fonction est volontairement idempotente : une fois la valeur restaurée,
    un second appel ne la modifie plus. Après la qualification courante, le
    nouveau fallback peut uniquement la réappliquer s'il satisfait le garde de
    preuve en vigueur.
    """
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    restored = 0

    for row in provenance_rows:
        if row.get("Field") != "Sector":
            continue
        if row.get("Origin") != _FALLBACK_ORIGIN or row.get("Decision") != "APPLIED":
            continue
        if row.get("Previous_Value") != config.SECTOR_UNKNOWN:
            continue

        item = by_id.get(row.get("Item_ID", ""))
        final_value = row.get("Final_Value", "")
        if item is None or not final_value:
            continue

        # Ne jamais écraser une correction ultérieure. Seule la valeur exacte
        # laissée par l'ancien fallback est éligible à la revalidation.
        if item.Sector != final_value:
            continue

        item.Sector = config.SECTOR_UNKNOWN
        restored += 1

    return restored
