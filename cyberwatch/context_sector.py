"""Résolution prudente de Sector à partir des preuves déjà collectées.

Le resolver n'effectue aucun appel réseau. Il agrège uniquement des descriptions
d'activité explicites déjà collectées, le contexte éditorial strict du sujet et
des preuves d'activité officielle déjà validées. Une valeur n'est appliquée que
lorsque toutes les preuves fortes disponibles pour une organisation convergent.
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


def classify_context_activity(activity: str) -> str:
    """Classe uniquement une description métier explicite."""
    text = searchable(activity)
    if not text:
        return config.SECTOR_UNKNOWN

    if (
        "distribution publique d electricite" in text
        or "distribution d electricite" in text
        or "distribution de gaz" in text
        or "syndicat departemental d energie" in text
        or "syndicat departemental energie" in text
    ):
        return config.SECTOR_ENERGY

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

    hospitality = getattr(config, "SECTOR_HOSPITALITY", config.SECTOR_UNKNOWN)
    if hospitality != config.SECTOR_UNKNOWN and any(marker in text for marker in (
        "location de bateaux",
        "location de bateau",
        "location nautique",
        "location de voiliers",
        "location de catamarans",
    )):
        return hospitality

    if any(marker in text for marker in ("esport", "e sport", "esports")):
        return config.SECTOR_SPORT

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

    return sector.classify_sector_activity(activity)


def _fact_evidence(row: dict[str, str]) -> list[Evidence]:
    """Ne transforme jamais Source_Sector_Raw en preuve contextuelle forte."""
    activity = (row.get("Activity_Description") or "").strip()
    if not activity:
        return []
    candidate = classify_context_activity(activity)
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
    """Exploite seulement le contexte éditorial explicitement lié au sujet.

    Le titre doit commencer par le nom de la victime ; le slug de l'URL n'est
    utilisable que si le vocabulaire métier fermé de ``classify_context_activity``
    y apparaît. Le corps de fuite, les types de données et des mots génériques
    ne sont jamais utilisés ici.
    """
    proofs: list[Evidence] = []
    org = searchable(item.Organisation_Raw)
    title = searchable(item.Title)
    if org and title.startswith(org):
        tail = title[len(org):].strip()
        candidate = classify_context_activity(tail)
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
        path = urlparse(item.URL).path
    except ValueError:
        path = ""
    if path:
        candidate = classify_context_activity(path.replace("-", " ").replace("_", " "))
        if candidate != config.SECTOR_UNKNOWN:
            proofs.append(Evidence(
                candidate,
                "source_url_context",
                path,
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
