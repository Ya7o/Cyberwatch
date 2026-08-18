"""Réapplication sûre du cache LLM pendant un rebuild post-développement.

Le rebuild peut faire varier le texte collecté sans changer l'identité métier de
l'item. Le cache exact de ``ai.py`` est volontairement lié au hash du contexte ;
ce module ajoute un fallback de rebuild plus stable, limité au même Item_ID,
Source_ID, modèle et version de prompt.

Aucun appel réseau n'est effectué ici. Seuls des champs actuellement ``Inconnu``
peuvent être complétés, et uniquement avec une décision cache au-dessus du seuil
canonique du champ.
"""

from __future__ import annotations

from collections import defaultdict

from . import ai, config
from .model import Item


def _float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def reapply_cached_qualifications(
    items: list[Item],
    cache_rows: list[dict],
    *,
    model: str | None = None,
    prompt_version: str | None = None,
) -> dict[str, int]:
    """Réapplique les décisions LLM compatibles aux champs encore inconnus.

    La dernière décision compatible et valide pour un ``Item_ID`` est retenue.
    Une décision d'un autre modèle, prompt, source ou taxonomie est ignorée.
    """
    expected_model = model or ai.DEFAULT_MODEL
    expected_prompt = prompt_version or ai.PROMPT_VERSION
    by_item: dict[str, list[dict]] = defaultdict(list)
    for row in cache_rows:
        if row.get("Model") != expected_model:
            continue
        if row.get("Prompt_Version") != expected_prompt:
            continue
        item_id = row.get("Item_ID", "")
        if item_id:
            by_item[item_id].append(row)

    stats = {
        "items_seen": len(items),
        "cache_items_compatible": len(by_item),
        "cache_item_hits": 0,
        "cache_item_misses": 0,
        "threat_restored": 0,
        "sector_restored": 0,
        "location_restored": 0,
    }

    field_map = {
        "Threat": (config.THREAT_UNKNOWN, config.THREATS, "threat_restored"),
        "Sector": (config.SECTOR_UNKNOWN, config.SECTORS, "sector_restored"),
        "Location": (config.LOC_INCONNU, config.LOCATIONS, "location_restored"),
    }

    for item in items:
        rows = [
            row for row in by_item.get(item.Item_ID, [])
            if row.get("Source_ID") == item.Source_ID
        ]
        if not rows:
            stats["cache_item_misses"] += 1
            continue
        stats["cache_item_hits"] += 1

        for field_name, (unknown, taxonomy, stat_key) in field_map.items():
            if getattr(item, field_name) != unknown:
                continue
            threshold = ai.FIELD_SPECS[field_name][3]
            # Le CSV est append-only : parcourir à rebours privilégie la décision
            # compatible la plus récente sans dépendre du hash de contexte.
            for row in reversed(rows):
                value = (row.get(field_name) or "").strip()
                confidence = _float(row.get(f"{field_name}_Confidence"))
                if value in taxonomy and value != unknown and confidence >= threshold:
                    setattr(item, field_name, value)
                    stats[stat_key] += 1
                    break

    return stats
