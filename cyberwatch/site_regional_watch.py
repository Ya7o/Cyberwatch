"""Qualification régionale publiée depuis les faits effectivement collectés."""
from __future__ import annotations

import json


def qualification(row: dict) -> dict:
    if row.get("Source_ID") != "VEILLE_LLM":
        return {}
    try:
        metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
    except (TypeError, ValueError):
        return {}
    if not isinstance(metadata, dict):
        return {}
    result: dict[str, object] = {
        key: str(metadata.get(key) or "").strip()
        for key in ("admission_reason", "statut", "score_definition", "localisation")
        if str(metadata.get(key) or "").strip()
    }
    score = metadata.get("score_cyberattaque")
    if isinstance(score, int) and not isinstance(score, bool) and 0 <= score <= 100:
        result["score"] = score
    return result


def decorate_details(resolved: dict, raw_facts: dict[str, list[dict]]) -> None:
    for incident_id, detail in resolved.items():
        qualifications = [fact["regional_watch"] for fact in raw_facts.get(incident_id, [])
                          if fact.get("regional_watch")]
        if qualifications:
            detail["regional_watch"] = qualifications
