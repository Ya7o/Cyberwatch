"""Résolution prudente de Sector à partir des preuves déjà collectées.

Le resolver n'effectue aucun appel réseau. Il agrège uniquement des descriptions
d'activité explicites déjà collectées, un contexte éditorial strictement borné
et des preuves d'activité officielle déjà validées. Une valeur n'est appliquée
que lorsque toutes les preuves fortes disponibles pour une organisation convergent.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlparse

from . import config, org_enrichment, sector
from .model import Item
from .normalize import organisation_key, searchable

ORIGIN = "ORG_CONTEXT_SECTOR"

# Seul le canal décrivant explicitement l'activité principale officielle est
# assez fort ici. Les NAF et secteurs bruts restent soumis à leur politique
# dédiée dans sector_registry / structured_source_backfill.
_OFFICIAL_CACHE_VIA = frozenset({"official_subject_activity"})


@dataclass(frozen=True)
class Evidence:
    sector: str
    kind: str
    text: str
    url: str = ""
    item_id: str = ""
    source_id: str = ""


def classify_explicit_activity(activity: str) -> str:
    """Classe un texte non structuré seulement sur des formulations métier fortes.

    Cette fonction est volontairement beaucoup plus stricte que le classifieur
    d'activité général. Elle sert aux titres/slugs d'articles où des mots comme
    ``logiciel``, ``santé`` ou ``logistique`` peuvent décrire l'incident plutôt
    que l'activité principale de la victime.
    """
    text = searchable(activity)
    if not text:
        return config.SECTOR_UNKNOWN

    if any(marker in text for marker in (
        "syndicat departemental d energie",
        "syndicat departemental energie",
        "distribution publique d electricite",
    )):
        return config.SECTOR_ENERGY

    hospitality = getattr(config, "SECTOR_HOSPITALITY", config.SECTOR_UNKNOWN)
    if hospitality != config.SECTOR_UNKNOWN and any(marker in text for marker in (
        "plateforme de location de bateaux",
        "site de location de bateaux",
        "location de bateaux",
        "location de bateau",
        "location de voiliers",
        "location de catamarans",
    )):
        return hospitality

    if any(marker in text for marker in (
        "fournisseur de materiel",
        "vente de materiel",
        "distributeur de materiel",
        "distribution de materiel",
        "vente d accessoires",
        "vente d equipements",
        "vente de pieces",
    )):
        return config.SECTOR_RETAIL

    if any(marker in text for marker in (
        "renovation de l habitat",
        "renovation habitat",
        "pose de fenetres",
        "pose de volets",
        "pose de portes",
    )):
        return config.SECTOR_CONSTRUCTION

    if any(marker in text for marker in (
        "fabrication industrielle",
        "industrie manufacturiere",
        "manutention industrie",
        "outillage aeronautique",
    )):
        return config.SECTOR_INDUSTRY

    if any(marker in text for marker in (
        "salle de realite virtuelle",
        "club de football professionnel",
        "club de football",
    )) and any(marker in text for marker in (
        "esport", "e sport", "football", "competition",
    )):
        return config.SECTOR_SPORT

    return config.SECTOR_UNKNOWN


def classify_context_activity(activity: str) -> str:
    """Classe une description explicitement identifiée comme activité principale."""
    explicit = classify_explicit_activity(activity)
    if explicit != config.SECTOR_UNKNOWN:
        return explicit
    return sector.classify_sector_activity(activity)


def _fact_evidence(row: dict[str, str]) -> list[Evidence]:
    """N'auto-classe un fait éditorial que sur une formulation métier forte.

    Activity_Description est utile comme faisceau de recherche, mais sa provenance
    éditoriale ne garantit pas qu'une formulation générique décrive bien l'activité
    principale de la victime. Le classifieur général reste réservé aux preuves
    officielles déjà validées.
    """
    activity = (row.get("Activity_Description") or "").strip()
    if not activity:
        return []
    candidate = classify_explicit_activity(activity)
    if candidate == config.SECTOR_UNKNOWN:
        return []
    return [Evidence(
        candidate,
        "source_activity",
        activity,
        item_id=(row.get("Item_ID") or "").strip(),
        source_id=(row.get("Source_ID") or "").strip(),
    )]


def _item_evidence(item: Item) -> list[Evidence]:
    """Exploite seulement un libellé métier explicite du titre ou du slug.

    Le titre doit commencer par le nom de la victime. Pour une URL, seule une
    expansion institutionnelle particulièrement forte est admise : les slugs
    rédactionnels contiennent trop souvent le vocabulaire de l'incident.
    """
    proofs: list[Evidence] = []
    org = searchable(item.Organisation_Raw)
    title = searchable(item.Title)
    if org and title.startswith(org):
        tail = title[len(org):].strip()
        candidate = classify_explicit_activity(tail)
        if candidate != config.SECTOR_UNKNOWN:
            proofs.append(Evidence(
                candidate,
                "source_title_context",
                item.Title,
                url=item.URL,
                item_id=item.Item_ID,
                source_id=item.Source_ID,
            ))

    try:
        path = searchable(urlparse(item.URL).path.replace("-", " ").replace("_", " "))
    except ValueError:
        path = ""
    if path and (
        "syndicat departemental d energie" in path
        or "syndicat departemental energie" in path
    ):
        proofs.append(Evidence(
            config.SECTOR_ENERGY,
            "source_url_context",
            urlparse(item.URL).path,
            url=item.URL,
            item_id=item.Item_ID,
            source_id=item.Source_ID,
        ))
    return proofs


def _cache_evidence(row: dict[str, str]) -> Evidence | None:
    if row.get("Match_Status") != org_enrichment.MATCHED:
        return None
    via = (row.get("Validated_Via") or "").strip()
    if via not in _OFFICIAL_CACHE_VIA:
        return None

    text = (row.get("Activity_Label") or "").strip()
    if not text:
        return None
    candidate = (row.get("Validated_Sector") or "").strip()
    classified = classify_context_activity(text)
    # Une preuve officielle mise en cache n'est réutilisée que si son libellé
    # d'activité permet aujourd'hui de retrouver exactement le secteur stocké.
    if (
        candidate not in config.SECTORS
        or candidate == config.SECTOR_UNKNOWN
        or classified != candidate
    ):
        return None
    return Evidence(
        candidate,
        via,
        text,
        url=(row.get("Evidence_URL") or "").strip(),
        source_id=(row.get("Evidence_Source") or "").strip(),
    )


def resolve_contextual_sectors(
    items: list[Item],
    source_fact_rows: list[dict[str, str]],
    org_cache_rows: list[dict[str, str]],
) -> tuple[int, list[dict[str, str]], int]:
    """Applique les preuves contextuelles convergentes aux items inconnus.

    Les données de fuite et le résumé cyber ne sont volontairement pas des
    preuves de secteur : ils peuvent aider une recherche, mais ne suffisent
    jamais à classer l'activité.
    """
    by_item = {item.Item_ID: item for item in items if item.Item_ID}
    evidence_by_org: dict[str, list[Evidence]] = defaultdict(list)

    for item in items:
        if item.Organisation_Key:
            evidence_by_org[item.Organisation_Key].extend(_item_evidence(item))

    for row in source_fact_rows:
        item = by_item.get((row.get("Item_ID") or "").strip())
        if item is None or not item.Organisation_Key:
            continue
        evidence_by_org[item.Organisation_Key].extend(_fact_evidence(row))

    for row in org_cache_rows:
        key = organisation_key(row.get("Organisation_Key") or row.get("Query_Name") or "")
        if not key:
            continue
        proof = _cache_evidence(row)
        if proof is not None:
            evidence_by_org[key].append(proof)

    resolved: dict[str, tuple[str, list[Evidence]]] = {}
    conflicts = 0
    for key, proofs in evidence_by_org.items():
        sectors = {proof.sector for proof in proofs}
        if len(sectors) == 1:
            resolved[key] = (next(iter(sectors)), proofs)
        elif len(sectors) > 1:
            conflicts += 1

    changed = 0
    provenance: list[dict[str, str]] = []
    for item in items:
        if item.Sector != config.SECTOR_UNKNOWN:
            continue
        match = resolved.get(item.Organisation_Key)
        if match is None:
            continue
        candidate, proofs = match
        previous = item.Sector
        item.Sector = candidate
        changed += 1
        evidence = " | ".join(
            f"{proof.kind}:{proof.text or proof.url}"
            for proof in proofs
            if proof.text or proof.url
        )[:2000]
        provenance.append({
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Field": "Sector",
            "Previous_Value": previous,
            "Candidate_Value": candidate,
            "Final_Value": candidate,
            "Origin": ORIGIN,
            "Confidence": "HIGH",
            "Evidence": evidence,
            "Match_Strategy": "organisation_key_context_consensus",
            "Decision": "APPLIED",
        })

    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return changed, provenance, conflicts
