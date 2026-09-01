"""Référentiel manuel pour compléter prudemment les champs inconnus.

Ce module ne collecte rien et ne déduit rien : seules les lignes validées du
CSV peuvent compléter un secteur ou un territoire absent des sources.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import config, store, watchlists
from .dedup import build_incidents_with_registry
from .identity import sort_items
from .model import Incident, Item
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


def enrich_items(
    items: list[Item],
    reference: dict[str, Enrichment],
    *,
    include_sector: bool = True,
) -> dict[str, int]:
    """Applique le référentiel aux seuls champs inconnus et compte les impacts."""
    report = {"sector": 0, "location": 0, "ocean_indian": 0, "france": 0}
    for item in items:
        before_sector, before_location = item.Sector, item.Location
        candidate_sector, item.Location = enrich_unknowns(
            item.Organisation_Raw, item.Sector, item.Location, reference
        )
        if include_sector:
            item.Sector = candidate_sector
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


def _source_location_default(source_id: str) -> str:
    # Import local pour garder l'enrichissement indépendant de
    # l'inventaire des collecteurs à l'import.
    from . import sources

    spec = sources.by_id(source_id)
    if spec and spec.location_rule in config.LOCATIONS:
        return spec.location_rule
    return ""


def backfill_unknowns(items: list[Item], reference: dict[str, Enrichment]) -> dict[str, int]:
    """Complète menace/localisation inconnues avec la même logique hors-ligne.

    Pour Location : référentiel/watchlist -> indice territorial sûr -> défaut
    de la source. Aucun appel réseau ni propagation entre organisations.
    """
    report = {
        "threat": 0,
        "location_rule": 0,
        "location_default": 0,
        "location_reused": 0,
    }
    ordered = sort_items(items)
    territories = watchlists.entity_territories()

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
            location = territories.get(searchable(item.Organisation_Raw), config.LOC_INCONNU)
            if location != config.LOC_INCONNU:
                report["location_rule"] += 1

        if location == config.LOC_INCONNU:
            location = classify_location(item.Title, item.Organisation_Raw)
            if location != config.LOC_INCONNU:
                report["location_rule"] += 1

        if location == config.LOC_INCONNU:
            default = _source_location_default(item.Source_ID)
            if default:
                location = default
                report["location_default"] += 1

        if location != config.LOC_INCONNU:
            item.Location = location

    return report


@dataclass(frozen=True)
class EnrichmentReport:
    items: list[Item]
    incidents: list[Incident]
    incident_id_registry: list[dict[str, str]]


_AUTHORITATIVE_NATIVE_THREAT_SOURCES = frozenset({"VEILLE_LLM"})
_AUTHORITATIVE_DEFAULT_THREATS = {"RANSOMWARE_LIVE": config.THREAT_RANSOMWARE}
_SOURCE_SCOPE_THREATS = {
    "FRENCHBREACHES": config.THREAT_LEAK,
    "BONJOURLAFUITE": config.THREAT_LEAK,
}
_STRONG_SOURCE_SCOPE_OVERRIDES = frozenset({
    config.THREAT_RANSOMWARE, config.THREAT_DDOS, config.THREAT_MALWARE,
    config.THREAT_LEAK, config.THREAT_PHISHING, config.THREAT_THIRD_PARTY,
})


def stabilize_threats(items: list[Item]) -> int:
    """Applique les quelques contrats de menace propres aux sources."""
    changed = 0
    for item in items:
        before = item.Threat
        explicit = classify_threat(item.Title, item.Threat_Raw)
        leak_words = (
            "fuite", "exposition de donnees", "donnees publiees",
            "donnees volees", "donnees exfiltrees",
        )
        if explicit == config.THREAT_LEAK or any(
            word in searchable(f"{item.Title} {item.Threat_Raw}")
            for word in leak_words
        ):
            item.Threat = config.THREAT_LEAK
            changed += item.Threat != before
            continue
        if item.Threat == config.THREAT_ACCOUNT:
            item.Threat = (
                config.THREAT_LEAK
                if item.Source_ID in _SOURCE_SCOPE_THREATS
                else config.THREAT_INTRUSION
            )
        elif item.Source_ID in _AUTHORITATIVE_NATIVE_THREAT_SOURCES:
            native = (item.Threat_Raw or "").strip()
            if native == config.THREAT_ACCOUNT:
                item.Threat = config.THREAT_INTRUSION
            elif native in config.THREATS:
                item.Threat = native
        elif item.Source_ID in _AUTHORITATIVE_DEFAULT_THREATS:
            item.Threat = _AUTHORITATIVE_DEFAULT_THREATS[item.Source_ID]
        elif item.Source_ID in _SOURCE_SCOPE_THREATS:
            if item.Threat not in _STRONG_SOURCE_SCOPE_OVERRIDES:
                item.Threat = _SOURCE_SCOPE_THREATS[item.Source_ID]
        changed += item.Threat != before
    return changed


def finalize_snapshot(items: list[Item]) -> EnrichmentReport:
    """Enrichit puis déduplique un snapshot sans appel externe."""
    ordered = sort_items(items)
    reference = load_reference()
    enrich_items(ordered, reference, include_sector=True)
    backfill_unknowns(ordered, reference)
    stabilize_threats(ordered)
    incidents, registry = build_incidents_with_registry(
        ordered,
        store.load_incident_id_registry(),
        store.load_incident_dedup_registry(),
    )
    return EnrichmentReport(ordered, incidents, registry)
