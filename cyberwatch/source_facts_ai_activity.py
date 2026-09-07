"""Validation atomique et reprise ciblée du couple activité/secteur."""
from __future__ import annotations

from . import config
from .sector_activity import ACTIVITY_FIELDS, activity_from_text, contextual_proof, supported_activity


def rejection_reason(raw, context: str) -> str:
    from .source_facts_ai import _grounded, _valid_confidence, CONFIDENCE_THRESHOLD, MAX_EVIDENCE_CHARS
    if not isinstance(raw, dict):
        return "MISSING_MODEL_FIELD"
    if not str(raw.get("value") or "").strip():
        return "EMPTY_MODEL_VALUE"
    confidence = _valid_confidence(raw.get("confidence"))
    if confidence is None or confidence < CONFIDENCE_THRESHOLD:
        return "CONFIDENCE_REJECTED"
    evidence = str(raw.get("evidence") or "").strip()
    if not evidence:
        return "EVIDENCE_MISSING"
    if len(evidence) > MAX_EVIDENCE_CHARS:
        return "EVIDENCE_TOO_LONG"
    if not _grounded(evidence, context):
        return "EVIDENCE_NOT_GROUNDED"
    return "ACTIVITY_VICTIM_BINDING_REJECTED"


def normalize_activity(raw: dict, context: str, organisation: str) -> tuple[dict, dict]:
    from .source_facts_ai import _normalize_fact
    from .sector import classify_sector_activity

    result: dict = {}
    reasons: dict = {}
    activity = _normalize_fact(raw.get("activity_description"), context)
    matched = _normalize_fact(raw.get("activity_sector_match"), context)
    if not activity:
        reasons["activity_description"] = rejection_reason(raw.get("activity_description"), context)
    if not matched:
        reasons["activity_sector_match"] = rejection_reason(raw.get("activity_sector_match"), context)
    if activity:
        proof = activity["evidence"]
        if not supported_activity(organisation, activity["value"], proof):
            proof = contextual_proof(organisation, proof, context)
        if proof and supported_activity(organisation, activity["value"], proof):
            activity = {**activity, "evidence": proof}
        else:
            activity = None
            reasons["activity_description"] = "ACTIVITY_VICTIM_BINDING_REJECTED"
    # Le secteur n'est pas promu seul : sa citation complète peut cependant
    # fournir une description littérale validée, sans nouvelle inférence LLM.
    if not activity and matched:
        expanded = contextual_proof(organisation, matched["evidence"], context)
        value, proof = activity_from_text(organisation, expanded or matched["evidence"])
        if value:
            activity = {"value": value, "evidence": proof, "confidence": matched["confidence"]}
            reasons.pop("activity_description", None)
    if not activity:
        for field in ACTIVITY_FIELDS:
            reasons.setdefault(field, "NO_VALID_ACTIVITY_PAIR")
        return result, reasons
    proposed_sector = classify_sector_activity(str(activity["value"]))
    evidence_sector = classify_sector_activity(str(activity["evidence"]))
    if (
        proposed_sector != config.SECTOR_UNKNOWN
        and evidence_sector != config.SECTOR_UNKNOWN
        and proposed_sector != evidence_sector
    ):
        # La citation est la donnée source. Si le libellé du modèle la
        # contredit, conserver la phrase littérale permet au déterministe de
        # classer ce qui est réellement écrit.
        activity = {**activity, "value": activity["evidence"]}
        proposed_sector = evidence_sector
        reasons["activity_description"] = "ACTIVITY_VALUE_REPLACED_BY_EVIDENCE"
    result["activity_description"] = activity
    if matched and matched["value"] in config.SECTORS and matched["value"] != config.SECTOR_UNKNOWN:
        from .normalize import searchable
        proof = searchable(activity["evidence"])
        other = searchable(matched["evidence"])
        matched_sector = str(matched["value"])
        if proposed_sector != config.SECTOR_UNKNOWN and matched_sector != proposed_sector:
            reasons["activity_sector_match"] = "SECTOR_CONTRADICTS_ACTIVITY_EVIDENCE"
        elif other in proof or proof in other:
            result["activity_sector_match"] = {**matched, "evidence": activity["evidence"]}
        else:
            reasons["activity_sector_match"] = "SECTOR_ACTIVITY_EVIDENCE_MISMATCH"
    else:
        reasons["activity_sector_match"] = "NO_VALID_TAXONOMY_MATCH"
    return result, reasons


def revalidate_activity_cache(entry: dict, context: str, organisation: str, versions: dict) -> None:
    fields = entry.get("fields", {})
    if not ACTIVITY_FIELDS.intersection(fields):
        return
    if all(fields.get(field, {}).get("version") == versions[field] for field in ACTIVITY_FIELDS):
        return
    raw = {field: fields.get(field, {}).get("value") for field in ACTIVITY_FIELDS}
    normalized, _ = normalize_activity(raw, context, organisation)
    for field, value in normalized.items():
        fields[field] = {"version": versions[field], "status": "accepted", "misses": 0,
                         "value": value, "validation": "REVALIDATED_ACTIVITY_PAIR"}
