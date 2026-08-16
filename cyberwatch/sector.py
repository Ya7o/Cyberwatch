"""Politique déterministe de qualification du secteur.

Les noms d'organisation et les descriptions d'activité ne sont jamais soumis
au même vocabulaire : un mot de marque (``Tech``, ``Immo``, ``Formation``...)
ne constitue pas, à lui seul, une preuve métier.
"""

from __future__ import annotations

import re

from . import config
from .normalize import organisation_key, searchable


def _contains(haystack: str, needle: str) -> bool:
    pattern = r"(?<!\w)" + re.escape(needle.strip()) + r"(?!\w)"
    return re.search(pattern, haystack) is not None


def _from_rules(text: str, rules: list[tuple[str, list[str]]]) -> str:
    blob = searchable(text)
    if not blob:
        return config.SECTOR_UNKNOWN
    for sector, patterns in rules:
        for pattern in patterns:
            if _contains(blob, pattern):
                return sector
    return config.SECTOR_UNKNOWN


def classify_source_sector(given: str = "") -> str:
    """Normalise uniquement un secteur explicitement structuré par la source."""
    cleaned = (given or "").strip()
    if not cleaned:
        return config.SECTOR_UNKNOWN
    if cleaned in config.SECTORS:
        return cleaned
    return config.ACTIVITY_TO_SECTOR.get(searchable(cleaned), config.SECTOR_UNKNOWN)


def _watchlist_sector(organisation: str) -> str:
    """Secteur d'une entité de veille exactement reconnue, aliases inclus.

    La watchlist est un référentiel versionné et explicite : l'utiliser ici ne
    réintroduit aucune heuristique sur les mots du nom. Une organisation hors
    référentiel reste inconnue.
    """
    key = organisation_key(organisation)
    if not key:
        return config.SECTOR_UNKNOWN

    # Import local pour éviter de coupler l'initialisation du module de
    # politique Sector à celle des listes de veille.
    from . import watchlists

    for entity in watchlists.ALL_ENTITIES:
        if organisation_key(entity.name) == key:
            return entity.sector_hint or config.SECTOR_UNKNOWN
        if any(organisation_key(alias) == key for alias in entity.aliases):
            return entity.sector_hint or config.SECTOR_UNKNOWN
    return config.SECTOR_UNKNOWN


def classify_sector_name(organisation: str) -> str:
    """Classe un nom uniquement avec des preuves nominatives sûres."""
    sector = _watchlist_sector(organisation)
    if sector != config.SECTOR_UNKNOWN:
        return sector
    return _from_rules(organisation, config.SECTOR_NAME_RULES)


def classify_sector_activity(activity_description: str) -> str:
    """Classe une description d'activité explicitement extraite de la source."""
    return _from_rules(activity_description, config.SECTOR_ACTIVITY_RULES)
