"""Catégories sensibles pour les fiches, avec leur qualification source."""
from __future__ import annotations

from . import data_sensitivity
from .normalize import canonical_data_type, searchable


def payload(detail: dict, facts: list[dict]) -> dict:
    exposure = data_sensitivity.classify(detail)
    if not exposure["sensitive_data_exposed"]:
        return {}
    sensitive = set(exposure["sensitive_data_types"])
    if exposure["vulnerable_people_data_exposed"]:
        sensitive.update(exposure["personal_data_types"])
    types = []
    for entry in detail.get("data_types", []):
        value = str(entry.get("value") or "").strip()
        if value not in sensitive:
            continue
        specifics = []
        # Les listes structurées sans adaptation riche gardent les précisions
        # initiales (IBAN, RIB…). Ne pas réintroduire une extraction scalaire
        # remplacée par des preuves riches, qui peuvent la démentir.
        for fact in facts:
            if fact.get("source") not in entry.get("sources", []):
                continue
            if isinstance((fact.get("rich_facts") or {}).get("data_types"), list):
                continue
            for original in fact.get("data_types", []):
                text = str(original or "").strip()
                if (text and len(text) <= 120 and canonical_data_type(text) == value
                        and searchable(text) != searchable(value) and text not in specifics):
                    specifics.append(text)
        types.append({"value": value, "status": entry.get("status") or "unknown",
                      "sources": entry.get("sources") or [], "specifics": specifics})
    return {"types": types, "vulnerable_people": exposure["vulnerable_people_data_exposed"]}


def decorate_details(resolved: dict, raw_facts: dict[str, list[dict]]) -> None:
    for incident_id, detail in resolved.items():
        sensitive = payload(detail, raw_facts.get(incident_id, []))
        if sensitive:
            detail["sensitive_data"] = sensitive
