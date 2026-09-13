"""Activités BLF-only : preuves historiques, puis résolution externe vérifiée.

Niveau 1 — réutilisation d'une activité déjà prouvée par une source riche pour
la même identité canonique, sans extraction ni inférence LLM. Les descriptions
différentes sans compatibilité démontrée restent conflictuelles, même si elles
partagent un secteur.

Niveau 2 — si aucun historique n'existe, un resolver injecté peut aller chercher
une activité à l'extérieur (:mod:`cyberwatch.organisation_activity_external`).
Ce module ne lui fait **aucune** confiance : tout résultat repasse par les
portes pures de :mod:`cyberwatch.organisation_activity`, y compris lorsqu'il
sort d'un cache. Sans resolver, le chemin reste exactement celui du niveau 1.

La garde de composante ci-dessous est le verrou réel du périmètre : elle exige
une composante exclusivement BONJOURLAFUITE, sans secteur, sans activité et
sans rubrique exploitable. Autoriser une autre source au niveau 2 demande de
l'éditer *aussi* — la policy seule n'y suffit pas.
"""
from __future__ import annotations

import json
import logging
from typing import Protocol
from urllib.parse import urlsplit

from . import config
from . import organisation_activity
from .model import Item
from .organisation_activity import VerifiedActivityEvidence
from .normalize import searchable
from .org_identity import effective_organisation_key
from .sector import classify_source_sector
from .sector_activity import supported_activity

BLF = "BONJOURLAFUITE"
KEY = "blf_activity"
RICH_SOURCES = {"FRENCHBREACHES", "CYBERATTAQUE_ORG"}
logger = logging.getLogger(__name__)


def metadata(raw: object) -> dict:
    try:
        value = json.loads(str(raw or "{}"))
    except (ValueError, TypeError):
        return {}
    return value if isinstance(value, dict) else {}


def _dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _url(value: str) -> bool:
    try:
        parsed = urlsplit(value)
        return parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    except ValueError:
        return False


class OrganisationActivityResolver(Protocol):
    """Point d'injection du niveau 2.

    ``resolve`` reçoit l'**item** et non le seul nom : la corroboration
    d'identité du registre a besoin de ``Location``, le cache de
    ``Organisation_Key``, et l'ordonnancement de ``Published_Date``. Un seam
    limité au nom ne pourrait rien porter de tout cela.

    Un resolver peut exposer ``last_status`` (motif du dernier refus) et
    ``note_decision(applied=...)`` (comptage) ; les deux sont optionnels et lus
    défensivement.
    """

    def resolve(self, item: Item) -> "VerifiedActivityEvidence | None": ...


def activity_subject(item: Item, fact: dict) -> str:
    """Garde la citation originale d'un alias validé, sans réécrire son sujet."""
    record = metadata(fact.get("Source_Metadata_JSON")).get(KEY, {})
    if item.Source_ID == BLF and isinstance(record, dict):
        name = str(record.get("organisation") or "")
        if name and effective_organisation_key(name) == effective_organisation_key(
            item.Organisation_Raw, item.Organisation_Key
        ):
            return name
    return item.Organisation_Raw


def build_blf_summary(item: Item, fact: dict) -> str:
    """Résumé reproductible, conservant les libellés des bulles littéralement."""
    existing = str(fact.get("Summary") or "")
    if item.Source_ID != BLF or existing.strip():
        return existing
    try:
        values = json.loads(fact.get("Data_Types_JSON") or "[]")
    except (ValueError, TypeError):
        return existing
    if not isinstance(values, list) or not values or not all(
        isinstance(v, str) and v.strip() for v in values
    ):
        return existing
    certainty = {"claimed": "une revendication de fuite de données",
                 "unconfirmed": "une fuite de données non confirmée",
                 "confirmed": "une fuite de données"}.get(
                     fact.get("Claim_Status"), "un signalement de fuite de données")
    return (f"BonjourLaFuite signale {certainty} concernant {item.Organisation_Raw}. "
            "Les données indiquées comprennent : " + " ; ".join(values) + ".")


def _candidates(items: list[Item], facts: dict) -> dict[str, list[dict]]:
    index: dict[str, list[dict]] = {}
    for item in items:
        fact = facts.get(item.Item_ID, {})
        activity = str(fact.get("Activity_Description") or "").strip()
        proof = metadata(fact.get("Evidence_JSON")).get("Activity_Description", "")
        if (item.Source_ID not in RICH_SOURCES or not isinstance(proof, str)
                or not supported_activity(item.Organisation_Raw, activity, proof)):
            continue
        # Une citation est obligatoire ; l'URL de l'article porte sa provenance.
        url = item.URL if _url(item.URL) else ""
        key = effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
        if key:
            index.setdefault(key, []).append({
                "organisation": item.Organisation_Raw, "activity_description": activity,
                "evidence_quote": proof, "evidence_url": url,
                "source_item_id": item.Item_ID, "source_id": item.Source_ID,
                "date": item.Published_Date, "score": 2 if url else 1,
            })
    return index


def published_summary(organisation: str, facts: list[dict]) -> list[str]:
    """Projection carte/fiche du gabarit natif ou d'une ancienne liste BLF.

    Les bulles intégrales restent publiées séparément. Cette exception ne
    relâche pas le contrat des headlines éditoriales des autres sources.
    """
    if not facts or {f.get("source") for f in facts} != {BLF}:
        return []
    from .headline import is_publishable_for_organisation
    for fact in sorted(facts, key=lambda f: str(f.get("item_id", ""))):
        summary = str(fact.get("summary") or "")
        legacy = summary.startswith((
            "Données concernées :", "Données revendiquées selon BonjourLaFuite :",
            "Données signalées mais non confirmées :",
        ))
        expected = build_blf_summary(Item(Source_ID=BLF, Organisation_Raw=organisation), {
            "Data_Types_JSON": _dump(fact.get("data_types", [])),
            "Claim_Status": fact.get("claim_status"),
        })
        if expected and (summary == expected or legacy):
            first, _, rest = expected.partition(". Les données indiquées comprennent : ")
            first += "."
            if is_publishable_for_organisation(first, organisation):
                second = "Les données indiquées comprennent : " + rest
                return [first] + ([second] if len(second) <= 160 else [])
    return []


def _select(candidates: list[dict]) -> tuple[dict | None, bool]:
    # Pas de compatibilité supposée depuis un secteur commun : seules les
    # descriptions normalisées identiques sont démontrées équivalentes ici.
    if len({searchable(c["activity_description"]) for c in candidates}) > 1:
        return None, True
    return (max(candidates, key=lambda c: (c["score"], c["date"], c["source_item_id"]))
            if candidates else None), False


def _external(item: Item, resolver: OrganisationActivityResolver, fact: dict) -> dict:
    """Résultat du niveau 2, toujours re-vérifié, et jamais fatal.

    Rend **toujours** un dict : un `None` fondu dans le record d'absence
    perdrait le motif, or c'est le motif qui distingue « rien trouvé » de « pas
    essayé ». En mode shadow, le secteur candidat est calculé ici puis consigné
    sans être appliqué.
    """
    try:
        result = resolver.resolve(item)
    except Exception as exc:  # noqa: BLE001 — le niveau 2 ne casse pas la collecte
        logger.warning("external_activity_failed item=%s error=%s",
                       item.Item_ID, type(exc).__name__)
        return organisation_activity.not_applied(organisation_activity.EXTERNAL_ERROR)

    if not isinstance(result, VerifiedActivityEvidence):
        return organisation_activity.not_applied(str(
            getattr(resolver, "last_status", organisation_activity.EXTERNAL_NO_CANDIDATE)))
    rejection = organisation_activity.accepts(result, item)
    if rejection:
        return organisation_activity.not_applied(rejection)

    # Le mode vient du resolver lorsqu'il en porte un : c'est sa policy qui
    # fait foi, pas une seconde lecture de l'environnement à un autre moment
    # du run. Le repli couvre un resolver tiers sans policy.
    shadow = getattr(resolver, "shadow", None)
    if not isinstance(shadow, bool):
        shadow = organisation_activity.shadow_mode()
    candidate = organisation_activity.candidate_sector(
        result.organisation, result.activity_description, result.evidence_quote,
        source_sector_raw=str(fact.get("Source_Sector_Raw") or "").strip(),
    ) if shadow else None
    note = getattr(resolver, "note_decision", None)
    if callable(note):
        note(applied=not shadow)
    return organisation_activity.blf_record(result, shadow=shadow, candidate=candidate)


def enrich(items: list[Item], facts: list[dict], *, incident_decisions: list[dict] | None = None,
           provider: OrganisationActivityResolver | None = None) -> list[str]:
    """Rejoue les preuves possédées, y compris leur retrait, avant le mapper."""
    from .dedup import group_components, incident_decision_map

    by_id = {f.get("Item_ID"): f for f in facts}
    history = _candidates(items, by_id)
    previous = {}
    for item in items:
        fact = by_id.get(item.Item_ID)
        if item.Source_ID != BLF or fact is None:
            continue
        meta = metadata(fact.get("Source_Metadata_JSON"))
        if isinstance(meta.get(KEY), dict) and meta[KEY].get("origin") in {
            "BLF_ACTIVITY_REUSE", "BLF_EXTERNAL_ACTIVITY",
        }:
            previous[item.Item_ID] = (meta[KEY], fact.get("Activity_Sector_Semantic", ""),
                                      meta.get("_activity_sector_semantic"))
            for field in ("Activity_Description", "Activity_Sector_Match", "Activity_Sector_Semantic"):
                fact[field] = ""
            proof = metadata(fact.get("Evidence_JSON"))
            proof.pop("Activity_Description", None)
            fact["Evidence_JSON"] = _dump(proof)
            meta.pop("_activity_sector_semantic", None)
            item.Sector = config.SECTOR_UNKNOWN
        meta.pop(KEY, None)
        summary = build_blf_summary(item, fact)
        if summary and not str(fact.get("Summary") or "").strip():
            fact["Summary"] = summary
            proof = metadata(fact.get("Evidence_JSON"))
            proof["Summary"] = proof.get("Data_Types_JSON", fact.get("Data_Types_JSON", ""))
            fact["Evidence_JSON"] = _dump(proof)
        meta["blf_origin"] = "BLF_NATIVE"
        fact["Source_Metadata_JSON"] = _dump(meta)

    changed = []
    for component in group_components(items, incident_decision_map(incident_decisions or [])):
        if {i.Source_ID for i in component} != {BLF} or any(
            i.Sector not in {"", config.SECTOR_UNKNOWN} for i in component
        ):
            continue
        if any(str(by_id.get(i.Item_ID, {}).get("Activity_Description") or "").strip()
               or classify_source_sector(str(by_id.get(i.Item_ID, {}).get("Source_Sector_Raw") or ""))
               != config.SECTOR_UNKNOWN for i in component):
            continue
        for item in component:
            fact = by_id.get(item.Item_ID)
            if (fact is None or str(fact.get("Activity_Description") or "").strip()
                    or classify_source_sector(str(fact.get("Source_Sector_Raw") or ""))
                    != config.SECTOR_UNKNOWN):
                continue
            candidates = [c for c in history.get(effective_organisation_key(
                item.Organisation_Raw, item.Organisation_Key), [])
                if c["date"] and c["date"] <= item.Published_Date]
            chosen, conflict = _select(candidates)
            record = {"origin": "BLF_ACTIVITY_CONFLICT" if conflict else "BLF_NO_ACTIVITY_EVIDENCE"}
            if conflict:
                record["source_item_ids"] = sorted(c["source_item_id"] for c in candidates)
            elif chosen:
                record = {**chosen, "origin": "BLF_ACTIVITY_REUSE"}
            elif provider is not None:
                record = _external(item, provider, fact)
            if record.get("activity_description"):
                fact["Activity_Description"] = record["activity_description"]
                proof = metadata(fact.get("Evidence_JSON"))
                proof["Activity_Description"] = record["evidence_quote"]
                fact["Evidence_JSON"] = _dump(proof)
                changed.append(item.Item_ID)
            meta = metadata(fact.get("Source_Metadata_JSON"))
            old_record, old_sector, old_mapping = previous.get(item.Item_ID, ({}, "", None))
            if record.get("activity_description") and all(
                record.get(key) == old_record.get(key) for key in (
                    "organisation", "activity_description", "evidence_quote", "evidence_url",
                )
            ):
                fact["Activity_Sector_Semantic"] = old_sector
                if old_mapping:
                    meta["_activity_sector_semantic"] = old_mapping
            meta[KEY] = record
            fact["Source_Metadata_JSON"] = _dump(meta)
    return sorted(changed)
