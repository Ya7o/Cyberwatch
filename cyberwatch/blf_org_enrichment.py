"""Activités BLF-only : preuves historiques, sans extraction ni inférence LLM.

Un provider explicite peut être injecté ; aucun moteur externe n'est installé
ou activé par ce module. Les descriptions différentes sans compatibilité
démontrée restent conflictuelles, même si elles partagent un secteur.
"""
from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from typing import Protocol
from urllib.parse import urlsplit

from . import config
from .model import Item
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


@dataclass(frozen=True)
class ActivityEvidence:
    organisation: str
    activity_description: str
    evidence_quote: str
    evidence_url: str
    confidence: float
    provider: str


class OrganisationActivityProvider(Protocol):
    def resolve(self, organisation: str) -> ActivityEvidence | None: ...


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


def _external(item: Item, provider: OrganisationActivityProvider) -> dict | None:
    try:
        result = provider.resolve(item.Organisation_Raw)
        if (not isinstance(result, ActivityEvidence) or not result.provider.strip()
                or not _url(result.evidence_url) or not 0.8 <= result.confidence <= 1
                or effective_organisation_key(result.organisation) !=
                effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
                or not supported_activity(result.organisation, result.activity_description,
                                          result.evidence_quote)):
            return None
        return {**asdict(result), "origin": "BLF_EXTERNAL_ACTIVITY"}
    except Exception as exc:
        logger.warning("blf_activity_provider_failed item=%s error=%s", item.Item_ID, type(exc).__name__)
        return None


def enrich(items: list[Item], facts: list[dict], *, incident_decisions: list[dict] | None = None,
           provider: OrganisationActivityProvider | None = None) -> list[str]:
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
                record = _external(item, provider) or record
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
