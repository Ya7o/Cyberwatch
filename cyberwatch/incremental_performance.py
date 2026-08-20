"""Fast-paths incrémentaux sans modifier la sémantique canonique du snapshot.

Le premier objectif est d'éviter les appels SourceFacts/LLM quand un item déjà
connu est recollecté avec exactement le même contenu source et la même version
d'extraction. La ligne SOURCE_FACTS existante est alors réutilisée telle quelle.

La qualification canonique globale reste volontairement inchangée : cette
extension optimise le travail externe coûteux sans affaiblir les contrôles de
reproductibilité du runner.
"""
from __future__ import annotations

import json
import os
from typing import Callable

_INSTALLED = False
_CACHE_BY_ITEM: dict[str, dict] | None = None
_FULL_FACT_CACHE_HITS = 0


def _enabled() -> bool:
    value = os.getenv("CYBERWATCH_INCREMENTAL_SOURCE_FACTS", "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _load_cache() -> dict[str, dict]:
    global _CACHE_BY_ITEM
    if _CACHE_BY_ITEM is not None:
        return _CACHE_BY_ITEM

    from . import store

    _CACHE_BY_ITEM = {
        str(row.get("Item_ID") or "").strip(): row
        for row in store.load_source_facts()
        if str(row.get("Item_ID") or "").strip()
    }
    return _CACHE_BY_ITEM


def _metadata(row: dict) -> dict:
    raw = str(row.get("Source_Metadata_JSON") or "").strip()
    if not raw:
        return {}
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _reusable_fact(item, entry, spec) -> dict | None:
    """Retourne la ligne existante seulement si sa preuve de fraîcheur est forte."""
    if not _enabled():
        return None

    from . import source_facts, source_facts_ai

    if spec.source_id not in source_facts_ai.TARGET_SOURCES:
        return None

    cached = _load_cache().get(item.Item_ID)
    if not cached:
        return None
    if str(cached.get("Source_ID") or "") != item.Source_ID:
        return None
    if str(cached.get("Extraction_Version") or "") != source_facts.SOURCE_FACTS_VERSION:
        return None

    previous_hash = str(_metadata(cached).get("_source_facts_content_hash") or "")
    current_hash = source_facts_ai.content_hash(entry)
    if not previous_hash or previous_hash != current_hash:
        return None

    # Copie défensive : les étapes suivantes peuvent enrichir/fusionner la ligne.
    return dict(cached)


def _apply_cached_sector_side_effect(item, fact: dict) -> None:
    """Préserve l'effet de l'extension sector_completion sans relancer l'extraction."""
    try:
        from . import config, sector
        from .sector_completion import _strong_activity_sector
    except ImportError:
        return

    if item.Sector != config.SECTOR_UNKNOWN:
        return

    raw_sector = str(fact.get("Source_Sector_Raw") or "").strip()
    if raw_sector:
        candidate = sector.classify_source_sector(raw_sector)
        if candidate in config.SECTORS and candidate != config.SECTOR_UNKNOWN:
            item.Sector = candidate
            return

    activity = str(fact.get("Activity_Description") or "").strip()
    candidate = _strong_activity_sector(activity)
    if candidate in config.SECTORS and candidate != config.SECTOR_UNKNOWN:
        item.Sector = candidate


def _patch_source_facts() -> None:
    from . import source_facts

    if getattr(source_facts, "_incremental_performance_installed", False):
        return

    original_extract: Callable = source_facts.extract_source_fact

    def extract_source_fact(item, entry, spec):
        global _FULL_FACT_CACHE_HITS
        cached = _reusable_fact(item, entry, spec)
        if cached is not None:
            _FULL_FACT_CACHE_HITS += 1
            _apply_cached_sector_side_effect(item, cached)
            return cached
        return original_extract(item, entry, spec)

    source_facts.extract_source_fact = extract_source_fact
    source_facts._incremental_performance_installed = True


def stats() -> dict[str, int]:
    return {"full_fact_cache_hits": _FULL_FACT_CACHE_HITS}


def reset_for_tests() -> None:
    global _CACHE_BY_ITEM, _FULL_FACT_CACHE_HITS
    _CACHE_BY_ITEM = None
    _FULL_FACT_CACHE_HITS = 0


def install() -> None:
    """Installe le fast-path une seule fois par processus."""
    global _INSTALLED
    if _INSTALLED:
        return
    _patch_source_facts()
    _INSTALLED = True
