"""Politique déterministe de qualification du secteur.

Les noms d'organisation et les descriptions d'activité ne sont jamais soumis
au même vocabulaire : un mot de marque (``Tech``, ``Immo``, ``Formation``...)
ne constitue pas, à lui seul, une preuve métier.
"""

from __future__ import annotations

import re

from . import config
from .normalize import organisation_key, searchable


# Catégories réellement observées dans le champ structuré ``sector`` de
# ransomware.live lors de l'audit Sprint Sector A. Elles sont séparées de la
# table générique ACTIVITY_TO_SECTOR pour rendre explicite qu'il s'agit de
# libellés de taxonomie source, et non de mots-clés acceptables dans du texte
# libre. Seules les correspondances sémantiquement univoques sont admises.
_STRUCTURED_SOURCE_SECTOR_ALIASES = {
    "professional services": config.SECTOR_SERVICES,
    "technology": config.SECTOR_TECH,
    "retail e commerce": config.SECTOR_RETAIL,
}


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
    key = searchable(cleaned)
    return config.ACTIVITY_TO_SECTOR.get(
        key,
        _STRUCTURED_SOURCE_SECTOR_ALIASES.get(key, config.SECTOR_UNKNOWN),
    )


def _watchlist_sector(organisation: str) -> str:
    """Secteur d'une entité de veille exactement reconnue, aliases inclus."""
    key = organisation_key(organisation)
    if not key:
        return config.SECTOR_UNKNOWN

    from . import watchlists

    for entity in watchlists.ALL_ENTITIES:
        if organisation_key(entity.name) == key:
            return entity.sector_hint or config.SECTOR_UNKNOWN
        if any(organisation_key(alias) == key for alias in entity.aliases):
            return entity.sector_hint or config.SECTOR_UNKNOWN
    return config.SECTOR_UNKNOWN


# Vocabulaire sportif suffisamment discriminant pour qu'une « Fédération
# française » ne soit plus automatiquement classée Sport. La fédération
# maçonnique observée dans la DB est le cas de régression qui motive ce garde.
_SPORT_NAME_TERMS = (
    "football", "rugby", "handball", "basket", "basketball", "volley",
    "tennis", "golf", "karate", "judo", "aikido", "motocyclisme",
    "cyclisme", "danse", "voile", "escrime", "randonnee", "natation",
    "athletisme", "gymnastique", "badminton", "hockey", "chasse",
    "sport", "sports",
)


def _safe_institutional_name_sector(organisation: str) -> str:
    blob = searchable(organisation)
    if not blob:
        return config.SECTOR_UNKNOWN

    # Identités institutionnelles quasi auto-descriptives. Les variantes avec
    # apostrophe deviennent « d » après normalisation (Mairie d'Eyguières,
    # Université d'Avignon).
    admin_prefixes = (
        "mairie ", "ville de ", "commune de ", "the commune of ",
        "ministere de ", "ministere des ", "ministry of ",
        "prefecture de ", "metropole de ",
    )
    if blob.startswith(admin_prefixes):
        return config.SECTOR_ADMIN

    education_prefixes = (
        "universite ", "university of ", "ecole nationale ",
        "ecole superieure ", "academie de ", "rectorat de ",
    )
    if blob.startswith(education_prefixes):
        return config.SECTOR_EDUCATION

    if blob.startswith("mutuelle "):
        return config.SECTOR_FINANCE

    if "stade francais" in blob:
        return config.SECTOR_SPORT
    if blob.startswith("federation sportive "):
        return config.SECTOR_SPORT
    if blob.startswith(("federation francaise ", "federation nationale ")):
        if any(_contains(blob, term) for term in _SPORT_NAME_TERMS):
            return config.SECTOR_SPORT

    return config.SECTOR_UNKNOWN


def classify_sector_name(organisation: str) -> str:
    """Classe un nom uniquement avec des preuves nominatives sûres."""
    sector = _watchlist_sector(organisation)
    if sector != config.SECTOR_UNKNOWN:
        return sector

    sector = _safe_institutional_name_sector(organisation)
    if sector != config.SECTOR_UNKNOWN:
        return sector

    # On conserve les règles historiques sûres mais jamais la règle Sport
    # générique « fédération française de » : le Sport est traité ci-dessus
    # avec un vocabulaire sportif explicite.
    safe_rules = [
        (sector_name, patterns)
        for sector_name, patterns in config.SECTOR_NAME_RULES
        if sector_name != config.SECTOR_SPORT
    ]
    return _from_rules(organisation, safe_rules)


def classify_sector_activity(activity_description: str) -> str:
    """Classe une description d'activité explicitement extraite de la source."""
    return _from_rules(activity_description, config.SECTOR_ACTIVITY_RULES)
