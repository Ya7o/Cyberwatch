"""Complétion prudente des secteurs encore inconnus.

Cette extension concentre les corrections mesurées après le rebuild 2026-08-17 :

1. réutiliser les preuves métier déjà extraites dans ``source_facts`` ;
2. couvrir des trous explicites de la taxonomie sans déduire depuis un nom ;
3. exploiter des codes NAF précis dans le cache entreprise, y compris les
   enregistrements déjà collectés, sans nouvel appel réseau.

Une description éditoriale ne devient jamais automatiquement un secteur via le
classifieur large : seules des formulations métier explicitement fortes sont
acceptées. Les valeurs hors taxonomie canonique restent ``Inconnu``.
"""
from __future__ import annotations

from typing import Callable

from . import config
from .normalize import searchable

SECTOR_HOSPITALITY = "Hébergement / Tourisme / Restauration"
SECTOR_CULTURE = "Culture / Médias / Loisirs"
# Conservé comme symbole de compatibilité pour les imports historiques, mais ce
# secteur n'est plus ajouté à la taxonomie canonique. Les partis/ONG restent
# Inconnu tant que la taxonomie officielle ne les contient pas.
SECTOR_ASSOCIATIONS = "Associations / ONG / Politique"

_INSTALLED = False


def _extend_taxonomy() -> None:
    """Ajoute uniquement les familles réellement retenues dans la taxonomie."""
    setattr(config, "SECTOR_HOSPITALITY", SECTOR_HOSPITALITY)
    setattr(config, "SECTOR_CULTURE", SECTOR_CULTURE)

    additions = [SECTOR_HOSPITALITY, SECTOR_CULTURE]
    for value in reversed(additions):
        if value in config.SECTORS:
            continue
        try:
            index = config.SECTORS.index(config.SECTOR_UNKNOWN)
        except ValueError:
            index = len(config.SECTORS)
        config.SECTORS.insert(index, value)

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
        "culture": SECTOR_CULTURE,
        "culture medias loisirs": SECTOR_CULTURE,
        "media": SECTOR_CULTURE,
        "medias": SECTOR_CULTURE,
        "loisirs": SECTOR_CULTURE,
        "entertainment": SECTOR_CULTURE,
    })
    # Une ancienne version pouvait avoir muté cette table au sein d'un même
    # processus de test. On retire explicitement les aliases hors contrat.
    for alias in (
        "association", "associations", "ong", "politique",
        "political organization",
    ):
        if config.ACTIVITY_TO_SECTOR.get(alias) == SECTOR_ASSOCIATIONS:
            config.ACTIVITY_TO_SECTOR.pop(alias, None)

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
    ]
    for rule in extra_rules:
        if rule[0] not in existing:
            config.SECTOR_ACTIVITY_RULES.append(rule)


def _strong_activity_sector(activity: str) -> str:
    """Classe uniquement une formulation qui décrit explicitement le métier.

    Cette fonction sert au canal éditorial ``Activity_Description``. Elle évite
    les erreurs où un produit technologique devient une entreprise Tech, où le
    mot ``Télécom`` d'un nom masque une école, ou encore où une infrastructure
    de transport transforme un groupe de BTP en transporteur.
    """
    text = searchable(activity)
    if not text:
        return config.SECTOR_UNKNOWN

    # Activité propre d'un éditeur/plateforme logicielle, y compris SaaS vertical.
    if any(marker in text for marker in (
        "editeur de logiciel", "editeur de logiciels", "logiciel saas",
        "solution saas", "plateforme saas", "logiciel de gestion",
        "plateforme de reservation en ligne", "plateforme de prise de rendez vous",
        "solution logicielle",
    )):
        return config.SECTOR_TECH

    # Établissements d'enseignement dont le nom commercial peut être trompeur.
    if any(marker in text for marker in (
        "ecole d ingenieurs", "ecole d ingenieur", "grande ecole",
        "etablissement d enseignement superieur", "formation d ingenieurs",
        "formation d ingenieur",
    )):
        return config.SECTOR_EDUCATION

    if any(marker in text for marker in (
        "salle de sport", "salles de sport", "club de fitness",
        "clubs de fitness", "centre de fitness", "reseau de salles de sport",
        "club sportif",
    )):
        return config.SECTOR_SPORT

    # Commerce de produits : le caractère technologique des produits ne change
    # pas le métier du vendeur.
    if any(marker in text for marker in (
        "site e commerce", "site de e commerce", "commerce en ligne",
        "boutique en ligne", "vente en ligne",
    )) and any(marker in text for marker in (
        "accessoires", "coques", "etuis", "chargeurs", "produits",
        "equipements", "pieces",
    )):
        return config.SECTOR_RETAIL
    if any(marker in text for marker in (
        "fournisseur de materiel", "vente de materiel", "distributeur de materiel",
        "distribution de materiel", "vente d accessoires", "vente d equipements",
        "vente de pieces",
    )):
        return config.SECTOR_RETAIL

    if any(marker in text for marker in (
        "groupe de construction", "entreprise de construction",
        "construction et infrastructures", "travaux publics", "genie civil",
        "batiment et travaux publics", "bâtiment et travaux publics",
        "renovation de l habitat", "pose de fenetres", "pose de volets",
        "pose de portes",
    )):
        return config.SECTOR_CONSTRUCTION

    if any(marker in text for marker in (
        "fabrication industrielle", "industrie manufacturiere",
        "manutention industrie", "outillage aeronautique",
    )):
        return config.SECTOR_INDUSTRY

    if any(marker in text for marker in (
        "syndicat departemental d energie", "distribution publique d electricite",
    )):
        return config.SECTOR_ENERGY

    if any(marker in text for marker in (
        "location de bateaux", "location de voiliers", "location de catamarans",
    )):
        return SECTOR_HOSPITALITY

    return config.SECTOR_UNKNOWN


def _precise_naf_sector(activity_code: str) -> str:
    """Mappe uniquement des sous-classes NAF suffisamment discriminantes."""
    code = str(activity_code or "").strip().upper()
    if not code:
        return ""

    if code.startswith(("55", "56", "79")):
        return SECTOR_HOSPITALITY
    if code.startswith(("58", "59", "60", "90", "91", "92")):
        return SECTOR_CULTURE
    if code.startswith("93.1"):
        return config.SECTOR_SPORT
    if code.startswith("93.2"):
        return SECTOR_CULTURE
    # 94 = associations/partis, famille non représentée dans la taxonomie
    # canonique : on s'abstient au lieu d'inventer une valeur publiable.
    if code.startswith("94"):
        return ""
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
        if precise in config.SECTORS and precise != config.SECTOR_UNKNOWN:
            record.Validated_Sector = precise
            record.Validated_Via = "naf_precise"
        elif record.Validated_Sector not in config.SECTORS:
            record.Validated_Sector = ""
            record.Validated_Via = ""
        return record

    def start_state():
        state = original_start()
        for row in state.cache.values():
            # Nettoie toute ancienne valeur non canonique avant réutilisation.
            if row.get("Validated_Sector") not in config.SECTORS:
                row["Validated_Sector"] = ""
                row["Validated_Via"] = ""
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

        # Un champ sectoriel explicitement structuré par la source reste une
        # preuve de premier rang, sous réserve de la taxonomie canonique.
        raw_sector = str(fact.get("Source_Sector_Raw") or "").strip()
        if raw_sector:
            candidate = sector.classify_source_sector(raw_sector)
            if candidate in config.SECTORS and candidate != config.SECTOR_UNKNOWN:
                item.Sector = candidate
                return fact

        # Une description éditoriale est beaucoup plus risquée : elle ne peut
        # auto-classer que sur un motif métier fort. Sinon on conserve le fait
        # comme faisceau, sans mutation canonique.
        activity = str(fact.get("Activity_Description") or "").strip()
        candidate = _strong_activity_sector(activity)
        if candidate in config.SECTORS and candidate != config.SECTOR_UNKNOWN:
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
