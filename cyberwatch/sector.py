"""Politique déterministe de qualification du secteur.

Les noms d'organisation et les descriptions d'activité ne sont jamais soumis
au même vocabulaire : un mot de marque (``Tech``, ``Immo``, ``Formation``...)
ne constitue pas, à lui seul, une preuve métier.
"""

from __future__ import annotations

import re

from . import config
from .normalize import organisation_key, searchable


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
# française » ne soit plus automatiquement classée Sport. Cette liste couvre
# les disciplines réellement observées dans la base tout en conservant le garde
# contre les fédérations non sportives.
_SPORT_NAME_TERMS = (
    "football", "rugby", "handball", "basket", "basketball", "volley",
    "tennis", "golf", "karate", "judo", "aikido", "motocyclisme",
    "cyclisme", "danse", "voile", "escrime", "randonnee", "natation",
    "athletisme", "gymnastique", "gym", "badminton", "hockey", "chasse",
    "equitation", "bridge", "savate", "ski", "vol libre", "aeronautique",
    "escalade", "twirling", "squash", "ulm", "pagaie", "handisport",
    "tennis de table", "sport automobile", "sport universitaire",
    "sport scolaire", "sport", "sports",
)

_HEALTH_INSTITUTION_TERMS = (
    "agence nationale", "agence regionale", "etablissement public",
    "autorite", "office national", "institut national",
)
_HEALTH_MISSION_TERMS = (
    "sante", "sanitaire", "medical", "medicament", "pharmacie",
    "hospitalier", "prevention",
)


def _health_institution_sector(text: str) -> str:
    """Reconnaît un organisme de santé lorsque mission et statut convergent."""
    blob = searchable(text)
    if not blob:
        return config.SECTOR_UNKNOWN

    if blob.startswith("sante publique "):
        return config.SECTOR_HEALTH

    institutional = any(_contains(blob, term) for term in _HEALTH_INSTITUTION_TERMS)
    health = any(_contains(blob, term) for term in _HEALTH_MISSION_TERMS)
    if institutional and health:
        return config.SECTOR_HEALTH
    return config.SECTOR_UNKNOWN


def _safe_institutional_name_sector(organisation: str) -> str:
    blob = searchable(organisation)
    if not blob:
        return config.SECTOR_UNKNOWN

    health_sector = _health_institution_sector(organisation)
    if health_sector != config.SECTOR_UNKNOWN:
        return health_sector

    # Formulations sanitaires auto-descriptives observées en base.
    if blob.startswith((
        "agence regionale de sante", "centre hospitalier ", "centre d imagerie medicale ",
        "centre imagerie medicale ", "clinique ", "hopital ", "hospices civils ",
        "federation hospitaliere ",
    )):
        return config.SECTOR_HEALTH

    if blob == "service public":
        return config.SECTOR_ADMIN

    admin_prefixes = (
        "mairie ", "ville de ", "ville d ", "commune de ", "commune d ",
        "the commune of ", "ministere de ", "ministere des ", "ministry of ",
        "fr ministry of ", "prefecture de ", "metropole de ", "metropole ",
        "region ", "la region ", "departement de ", "conseil departemental ",
        "centre communal d action sociale ", "service public ", "france services",
    )
    if blob.startswith(admin_prefixes):
        return config.SECTOR_ADMIN
    # Les métropoles françaises sont fréquemment nommées « X Métropole »
    # (Nantes Métropole, Rennes Métropole), et non « Métropole de X ».
    if blob.endswith(" metropole"):
        return config.SECTOR_ADMIN

    education_prefixes = (
        "universite ", "university of ", "ecole nationale ", "ecole superieure ",
        "ecole elementaire ", "ecole ", "academie de ", "rectorat de ",
        "lycee ", "college ", "campus france", "paris school of business",
        "ppa business school", "enseignement catholique", "sciences po",
    )
    if blob.startswith(education_prefixes):
        return config.SECTOR_EDUCATION
    # Une dénomination terminant explicitement par « School of Business » ou
    # « Business School » décrit l'établissement, sans généraliser le mot
    # « business » à lui seul.
    if blob.endswith((" school of business", " business school")):
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

    safe_rules = [
        (sector_name, patterns)
        for sector_name, patterns in config.SECTOR_NAME_RULES
        if sector_name != config.SECTOR_SPORT
    ]
    return _from_rules(organisation, safe_rules)


def classify_sector_activity(activity_description: str) -> str:
    """Classe une description d'activité explicitement extraite de la source."""
    health_sector = _health_institution_sector(activity_description)
    if health_sector != config.SECTOR_UNKNOWN:
        return health_sector
    return _from_rules(activity_description, config.SECTOR_ACTIVITY_RULES)
