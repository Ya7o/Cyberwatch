"""Résolution prudente de Sector à partir des preuves déjà collectées.

Le resolver n'effectue aucun appel réseau. Il agrège les descriptions d'activité
SourceFacts et les preuves officielles déjà présentes dans le cache entreprise.
Une valeur n'est appliquée que lorsque toutes les preuves fortes disponibles
pour une organisation convergent vers le même secteur.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from . import config, org_enrichment, sector
from .model import Item
from .normalize import organisation_key, searchable

ORIGIN = "ORG_CONTEXT_SECTOR"

_OFFICIAL_CACHE_VIA = frozenset({
    "official_subject_activity",
    "official_site",
    "naf_precise",
})


@dataclass(frozen=True)
class Evidence:
    sector: str
    kind: str
    text: str
    url: str = ""
    item_id: str = ""
    source_id: str = ""


def classify_context_activity(activity: str) -> str:
    """Classe uniquement une description métier explicite.

    Les quelques compléments couvrent des formulations observées dans le long
    tail et restent volontairement réservés au texte d'activité, jamais au nom.
    """
    candidate = sector.classify_sector_activity(activity)
    if candidate != config.SECTOR_UNKNOWN:
        return candidate

    text = searchable(activity)
    if not text:
        return config.SECTOR_UNKNOWN

    if any(marker in text for marker in (
        "fournisseur de materiel",
        "vente de materiel",
        "distributeur de materiel",
        "distribution de materiel",
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

    if any(marker in text for marker in (
        "esport",
        "e sport",
        "esports",
    )):
        return config.SECTOR_SPORT

    if any(marker in text for marker in (
        "renovation de l habitat",
        "renovation habitat",
        "pose de fenetres",
        "pose de volets",
        "pose de portes",
    )):
        return config.SECTOR_CONSTRUCTION

    return config.SECTOR_UNKNOWN


def _fact_evidence(row: dict[str, str]) -> list[Evidence]:
    result: list[Evidence] = []
    raw_sector = (row.get("Source_Sector_Raw") or "").strip()
    if raw_sector:
        candidate = sector.classify_source_sector(raw_sector)
        if candidate != config.SECTOR_UNKNOWN:
            result.append(Evidence(
                candidate,
                "structured_source",
                raw_sector,
                item_id=(row.get("Item_ID") or "").strip(),
                source_id=(row.get("Source_ID") or "").strip(),
            ))

    activity = (row.get("Activity_Description") or "").strip()
    if activity:
        candidate = classify_context_activity(activity)
        if candidate != config.SECTOR_UNKNOWN:
            result.append(Evidence(
                candidate,
                "source_activity",
                activity,
                item_id=(row.get("Item_ID") or "").strip(),
                source_id=(row.get("Source_ID") or "").strip(),
            ))
    return result


def _cache_evidence(row: dict[str, str]) -> Evidence | None:
    if row.get("Match_Status") != org_enrichment.MATCHED:
        return None
    via = (row.get("Validated_Via") or "").strip()
    if via not in _OFFICIAL_CACHE_VIA:
        return None
    candidate = (row.get("Validated_Sector") or "").strip()
    if candidate not in config.SECTORS or candidate == config.SECTOR_UNKNOWN:
        return None
    text = (row.get("Activity_Label") or "").strip()
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

    Retourne ``(applied, provenance, conflicts)``. Les données de fuite et le
    résumé cyber ne sont volontairement pas des preuves de secteur : ils peuvent
    aider une future recherche, mais ne suffisent jamais à classer l'activité.
    """
    by_item = {item.Item_ID: item for item in items if item.Item_ID}
    evidence_by_org: dict[str, list[Evidence]] = defaultdict(list)

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
