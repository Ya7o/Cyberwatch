"""Référentiel manuel pour compléter prudemment les champs inconnus.

Ce module ne collecte rien et ne déduit rien : seules les lignes validées du
CSV peuvent compléter un secteur ou un territoire absent des sources.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config, store
from .identity import sort_items
from .model import Item
from .normalize import classify_location, classify_threat, organisation_key, searchable


@dataclass(frozen=True)
class Enrichment:
    organisation: str
    sector: str
    location: str
    scope: str
    reason: str
    validation_url: str


def load_reference() -> dict[str, Enrichment]:
    """Charge le référentiel par clé normalisée et refuse les lignes invalides."""
    result: dict[str, Enrichment] = {}
    for row in store.read_csv(store.ENRICHMENT_REFERENCE_CSV):
        key = organisation_key(row.get("Organisation_Key", ""))
        sector = _canonical((row.get("Secteur") or "").strip(), config.SECTORS)
        location = _canonical((row.get("Localisation") or "").strip(), config.LOCATIONS)
        if not key or (row.get("Secteur") and not sector) or (row.get("Localisation") and not location):
            continue
        result[key] = Enrichment(
            organisation=(row.get("Organisation") or "").strip(),
            sector=sector,
            location=location,
            scope=(row.get("Périmètre") or "").strip(),
            reason=(row.get("Motif") or "").strip(),
            validation_url=(row.get("URL_de_validation") or "").strip(),
        )
    return result


def _canonical(value: str, choices: list[str]) -> str:
    """Accepte les libellés CSV équivalents sans inventer de valeur métier."""
    if not value:
        return ""
    # Certains environnements Windows/WSL peuvent lire un CSV UTF-8 déjà
    # décodé comme latin-1 ; réparer cette forme connue reste déterministe.
    if "Ã" in value:
        try:
            value = value.encode("latin-1").decode("utf-8")
        except UnicodeError:
            pass
    key = searchable(value)
    return next((choice for choice in choices if searchable(choice) == key), "")


def enrich_unknowns(
    organisation: str, sector: str, location: str, reference: dict[str, Enrichment]
) -> tuple[str, str]:
    """Complète uniquement les valeurs inconnues ; une source garde sa priorité."""
    entry = reference.get(organisation_key(organisation))
    if entry is None:
        return sector, location
    if sector == config.SECTOR_UNKNOWN and entry.sector:
        sector = entry.sector
    if location == config.LOC_INCONNU and entry.location:
        location = entry.location
    return sector, location


def enrich_items(items: list[Item], reference: dict[str, Enrichment]) -> dict[str, int]:
    """Applique le référentiel aux seuls champs inconnus et compte les impacts."""
    report = {"sector": 0, "location": 0, "ocean_indian": 0, "france": 0}
    for item in items:
        before_sector, before_location = item.Sector, item.Location
        item.Sector, item.Location = enrich_unknowns(
            item.Organisation_Raw, item.Sector, item.Location, reference
        )
        entry = reference.get(organisation_key(item.Organisation_Raw))
        if item.Sector != before_sector:
            report["sector"] += 1
        if item.Location != before_location:
            report["location"] += 1
        if entry and (item.Sector != before_sector or item.Location != before_location):
            report["ocean_indian" if entry.scope == "Océan Indien" else "france"] += 1
    return report


# Marqueurs volontairement courts, appliqués uniquement aux menaces encore
# inconnues. Ils couvrent les formulations où le nom de l'objet et l'action
# sont séparés ("données de 12 000 agents diffusées", par exemple).
_UNKNOWN_LEAK_MARKERS = ("fuite", "expos", "diffus", "revendiqu")


def _backfill_unknown_threat(item: Item) -> str:
    threat = classify_threat(item.Title, item.Threat_Raw)
    if threat != config.THREAT_UNKNOWN:
        return threat
    title = searchable(item.Title)
    if any(marker in title for marker in _UNKNOWN_LEAK_MARKERS):
        return config.THREAT_LEAK
    return config.THREAT_UNKNOWN


def backfill_unknowns(items: list[Item], reference: dict[str, Enrichment]) -> dict[str, int]:
    """Complète uniquement menace/localisation inconnues, sans changer d'identité.

    Première passe : règles directes. Deuxième passe : réutilisation d'une
    localisation unique déjà connue pour la même Organisation_Key. Cette
    séparation rend le résultat déterministe et complet en une seule exécution.
    """
    report = {"threat": 0, "location_rule": 0, "location_reused": 0}
    ordered = sort_items(items)

    for item in ordered:
        if item.Threat == config.THREAT_UNKNOWN:
            threat = _backfill_unknown_threat(item)
            if threat != config.THREAT_UNKNOWN:
                item.Threat = threat
                report["threat"] += 1

        if item.Location != config.LOC_INCONNU:
            continue
        _sector, location = enrich_unknowns(
            item.Organisation_Raw, item.Sector, item.Location, reference
        )
        if location == config.LOC_INCONNU:
            location = classify_location(item.Title, item.Organisation_Raw)
        if location != config.LOC_INCONNU:
            item.Location = location
            report["location_rule"] += 1

    known_locations: dict[str, set[str]] = {}
    for item in ordered:
        if item.Organisation_Key and item.Location != config.LOC_INCONNU:
            known_locations.setdefault(item.Organisation_Key, set()).add(item.Location)

    for item in ordered:
        if item.Location != config.LOC_INCONNU:
            continue
        candidates = known_locations.get(item.Organisation_Key, set())
        if len(candidates) == 1:
            item.Location = next(iter(candidates))
            report["location_reused"] += 1

    return report
