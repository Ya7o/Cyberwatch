"""Complétion prudente des secteurs encore inconnus.

Cette extension concentre les corrections mesurées après le rebuild 2026-08-17 :

1. réutiliser les preuves métier déjà extraites dans ``source_facts`` ;
2. couvrir trois trous explicites de la taxonomie sans déduire depuis un nom ;
3. exploiter des codes NAF précis dans le cache entreprise, y compris les
   enregistrements déjà collectés, sans nouvel appel réseau.

Le module est installé une seule fois au chargement du package. Les wrappers
restent volontairement petits afin de ne pas dupliquer le pipeline du runner et
de limiter les conflits avec les développements parallèles.
"""
from __future__ import annotations

from typing import Callable

from . import config

SECTOR_HOSPITALITY = "Hébergement / Tourisme / Restauration"
SECTOR_CULTURE = "Culture / Médias / Loisirs"
SECTOR_ASSOCIATIONS = "Associations / ONG / Politique"

_INSTALLED = False


def _extend_taxonomy() -> None:
    """Ajoute uniquement les familles absentes qui expliquent des gaps réels."""
    setattr(config, "SECTOR_HOSPITALITY", SECTOR_HOSPITALITY)
    setattr(config, "SECTOR_CULTURE", SECTOR_CULTURE)
    setattr(config, "SECTOR_ASSOCIATIONS", SECTOR_ASSOCIATIONS)

    additions = [SECTOR_HOSPITALITY, SECTOR_CULTURE, SECTOR_ASSOCIATIONS]
    for value in reversed(additions):
        if value in config.SECTORS:
            continue
        try:
            index = config.SECTORS.index(config.SECTOR_UNKNOWN)
        except ValueError:
            index = len(config.SECTORS)
        config.SECTORS.insert(index, value)

    # Catégories explicitement structurées par les sources. Les libellés trop
    # larges ("services", "autres", etc.) restent volontairement Inconnu.
    config.ACTIVITY_TO_SECTOR.update({
        "commerce": config.SECTOR_RETAIL,
        "commerce distribution": config.SECTOR_RETAIL,
        "distribution": config.SECTOR_RETAIL,
        "hebergement": SECTOR_HOSPITALITY,
        "hebergement restauration": SECTOR_HOSPITALITY,
        "hebergement et restauration": SECTOR_HOSPITALITY,
        "hotellerie": SECTOR_HOSPITALITY,
        "restauration": SECTOR_HOSPITALITY,
        "tourisme": SECTOR_HOSPITALITY,
        "travel hospitality": SECTOR_HOSPITALITY,
        "culture": SECTOR_CULTURE,
        "culture medias loisirs": SECTOR_CULTURE,
        "media": SECTOR_CULTURE,
        "medias": SECTOR_CULTURE,
        "loisirs": SECTOR_CULTURE,
        "entertainment": SECTOR_CULTURE,
        "association": SECTOR_ASSOCIATIONS,
        "associations": SECTOR_ASSOCIATIONS,
        "ong": SECTOR_ASSOCIATIONS,
        "politique": SECTOR_ASSOCIATIONS,
        "political organization": SECTOR_ASSOCIATIONS,
        "non profit": SECTOR_ASSOCIATIONS,
        "nonprofit": SECTOR_ASSOCIATIONS,
    })

    existing = {sector for sector, _patterns in config.SECTOR_ACTIVITY_RULES}
    extra_rules = [
        (
            SECTOR_HOSPITALITY,
            [
                "hotel", "hotellerie", "hebergement", "restaurant",
                "restauration", "tourisme", "touristique", "camping",
                "village vacances", "agence de voyages", "agence de voyage",
                "tour operateur", "residence de tourisme",
            ],
        ),
        (
            SECTOR_CULTURE,
            [
                "cinema", "theatre", "spectacle", "musee", "bibliotheque",
                "mediatheque", "presse", "media", "audiovisuel",
                "radiodiffusion", "television", "production audiovisuelle",
                "maison d edition", "loisirs", "parc de loisirs",
            ],
        ),
        (
            SECTOR_ASSOCIATIONS,
            [
                "association", "organisation non gouvernementale", "ong",
                "parti politique", "mouvement politique", "organisation politique",
                "organisation a but non lucratif", "non profit",
            ],
        ),
    ]
    for rule in extra_rules:
        if rule[0] not in existing:
            config.SECTOR_ACTIVITY_RULES.append(rule)



def _precise_naf_sector(activity_code: str) -> str:
    """Mappe uniquement des sous-classes NAF suffisamment discriminantes."""
    code = str(activity_code or "").strip().upper()
    if not code:
        return ""

    # Hébergement/restauration + agences de voyage et réservation touristique.
    if code.startswith(("55", "56", "79")):
        return SECTOR_HOSPITALITY

    # Édition, audiovisuel, diffusion, arts, patrimoine et jeux/loisirs.
    if code.startswith(("58", "59", "60", "90", "91", "92")):
        return SECTOR_CULTURE

    # 93.1 = activités liées au sport ; 93.2 = activités récréatives/loisirs.
    if code.startswith("93.1"):
        return config.SECTOR_SPORT
    if code.startswith("93.2"):
        return SECTOR_CULTURE

    # 94 = activités des organisations associatives (dont partis politiques).
    if code.startswith("94"):
        return SECTOR_ASSOCIATIONS

    return ""


def _patch_org_enrichment() -> None:
    from . import org_enrichment

    if getattr(org_enrichment, "_sector_completion_installed", False):
        return

    original_record = org_enrichment._record_from_candidate
    original_start = org_enrichment.start_state

    def record_from_candidate(org_key, query_name, candidate, fetched_at):
        record = original_record(org_key, query_name, candidate, fetched_at)
        precise = _precise_naf_sector(record.Activity_Code)
        if precise:
            record.Validated_Sector = precise
            record.Validated_Via = "naf_precise"
        return record

    def start_state():
        state = original_start()
        # Réutilise immédiatement le cache existant : aucune requête réseau n'est
        # nécessaire pour requalifier un code NAF déjà connu avec la nouvelle
        # taxonomie. Une preuve plus forte (site officiel/manuelle) reste prioritaire.
        for row in state.cache.values():
            precise = _precise_naf_sector(row.get("Activity_Code", ""))
            if not precise:
                continue
            validated_via = row.get("Validated_Via", "")
            if validated_via and validated_via not in {"deterministic", "llm_declined", "naf_precise"}:
                continue
            row["Validated_Sector"] = precise
            row["Validated_Via"] = "naf_precise"
        return state

    org_enrichment._record_from_candidate = record_from_candidate
    org_enrichment.start_state = start_state
    org_enrichment._sector_completion_installed = True


def _patch_source_facts() -> None:
    from . import sector, source_facts

    if getattr(source_facts, "_sector_completion_installed", False):
        return

    original_extract: Callable = source_facts.extract_source_fact

    def extract_source_fact(item, entry, spec):
        fact = original_extract(item, entry, spec)
        if fact is None or item.Sector != config.SECTOR_UNKNOWN:
            return fact

        # Priorité 1 : secteur explicitement structuré/extrait de la source.
        raw_sector = str(fact.get("Source_Sector_Raw") or "").strip()
        if raw_sector:
            candidate = sector.classify_source_sector(raw_sector)
            if candidate != config.SECTOR_UNKNOWN:
                item.Sector = candidate
                return fact

        # Priorité 2 : description d'activité déjà validée par source_facts.
        # Le récit cyber complet et le seul nom de l'organisation restent exclus.
        activity = str(fact.get("Activity_Description") or "").strip()
        if activity:
            candidate = sector.classify_sector_activity(activity)
            if candidate != config.SECTOR_UNKNOWN:
                item.Sector = candidate
        return fact

    source_facts.extract_source_fact = extract_source_fact
    source_facts._sector_completion_installed = True


def install() -> None:
    """Installe l'extension une seule fois par processus."""
    global _INSTALLED
    if _INSTALLED:
        return
    _extend_taxonomy()
    _patch_org_enrichment()
    _patch_source_facts()
    _INSTALLED = True
