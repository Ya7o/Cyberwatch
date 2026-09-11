"""Contrôles de transport entre le cache sémantique et SourceFacts."""
from __future__ import annotations

import json

from . import source_facts_ai


PUBLIC_COLUMNS = {
    "summary": "Summary", "initial_access": "Initial_Access",
    "impact": "Impact",
    "threat_actor": "Threat_Actor", "third_party": "Third_Party",
    "fine_location": "Fine_Location", "data_types": "Data_Types_JSON",
    "activity_description": "Activity_Description",
    "activity_sector_match": "Activity_Sector_Match",
}
RICH_FIELDS = {
    "affected_counts", "affected_systems", "affected_datasets",
}
LIST_COLUMNS = {
    "data_types": "Data_Types_JSON",
}


def _loads(raw: object) -> object:
    try:
        return json.loads(str(raw or ""))
    except (TypeError, ValueError):
        return None


def _dumps(value: object) -> str:
    if not value:
        return ""
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def semantic_materialization_gaps(facts: list[dict]) -> list[str]:
    """Détecte une réponse LLM ``accepted`` perdue avant le CSV public."""
    gaps: list[str] = []
    for fact in facts:
        metadata = _loads(fact.get("Source_Metadata_JSON"))
        if not isinstance(metadata, dict):
            continue
        statuses = metadata.get("_source_facts_semantic_status")
        if not isinstance(statuses, dict):
            continue
        correction = metadata.get("editorial_correction")
        suppressed = {
            str(field) for field in correction.get("suppressed_semantic_fields", [])
        } if isinstance(correction, dict) else set()
        rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
        for field, state in statuses.items():
            if str(state or "").strip().lower() != "accepted":
                continue
            if field in suppressed:
                continue
            column = PUBLIC_COLUMNS.get(field)
            if column and not str(fact.get(column) or "").strip():
                gaps.append(f"{fact.get('Item_ID', '')}:{field}")
            elif field in RICH_FIELDS and not rich.get(field):
                gaps.append(f"{fact.get('Item_ID', '')}:{field}")
            elif field == "threat_candidate" and not metadata.get("threat_tentative"):
                gaps.append(f"{fact.get('Item_ID', '')}:{field}")
    return sorted(set(gaps))


def _missing(field: str, fact: dict, metadata: dict, rich: dict) -> bool:
    column = PUBLIC_COLUMNS.get(field)
    return bool(
        (column and not str(fact.get(column) or "").strip())
        or (field in RICH_FIELDS and not rich.get(field))
        or (field == "threat_candidate" and not metadata.get("threat_tentative"))
    )


def _materialize_list(field: str, value: object, fact: dict, evidence: dict) -> bool:
    column = LIST_COLUMNS.get(field)
    if not column or str(fact.get(column) or "").strip() or not isinstance(value, list):
        return False
    values = [
        str(item.get("value") if isinstance(item, dict) else item).strip()
        for item in value
    ]
    values = [item for item in values if item]
    if not values:
        return False
    fact[column] = _dumps(values)
    evidence[column] = [item.get("evidence", "") if isinstance(item, dict) else "" for item in value]
    return True


def _materialize_scalar(field: str, value: object, fact: dict, evidence: dict) -> bool:
    column = PUBLIC_COLUMNS.get(field)
    if not column or str(fact.get(column) or "").strip():
        return False
    if isinstance(value, dict):
        scalar, proof = value.get("value"), value.get("evidence")
    else:
        scalar, proof = value, ""
    if scalar in (None, "", [], {}):
        return False
    fact[column] = str(scalar)
    if proof:
        evidence[column] = proof
    return True


def materialize_cached_llm_fields(
    facts: list[dict], cache_entries: list[dict]
) -> tuple[list[dict], list[str]]:
    """Réhydrate uniquement les valeurs acceptées par le contrat LLM courant."""
    expected_model = source_facts_ai.resolved_model()
    by_key: dict[tuple[str, str], dict] = {}
    priorities: dict[tuple[str, str], int] = {}
    for entry in cache_entries:
        if not isinstance(entry, dict) or not entry.get("item_id") or not entry.get("content_hash"):
            continue
        key = (str(entry["item_id"]), str(entry["content_hash"]))
        cached_model = str(entry.get("effective_model") or entry.get("model") or "")
        if cached_model and cached_model != expected_model:
            continue
        priority = 2 if cached_model == expected_model else 1
        if priority > priorities.get(key, 0):
            by_key[key] = entry
            priorities[key] = priority
    changed: list[str] = []
    for fact in facts:
        metadata = _loads(fact.get("Source_Metadata_JSON"))
        if not isinstance(metadata, dict):
            continue
        cache = by_key.get((
            str(fact.get("Item_ID") or ""),
            str(metadata.get("_source_facts_content_hash") or ""),
        ))
        fields = cache.get("fields") if isinstance(cache, dict) else None
        if not isinstance(fields, dict):
            continue
        evidence = _loads(fact.get("Evidence_JSON"))
        evidence = evidence if isinstance(evidence, dict) else {}
        rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}
        statuses = metadata.get("_source_facts_semantic_status")
        statuses = dict(statuses) if isinstance(statuses, dict) else {}
        materialized: list[str] = []
        stale: list[str] = []
        for field, record in fields.items():
            if not isinstance(record, dict):
                continue
            expected = source_facts_ai.FIELD_VERSIONS.get(field)
            if expected and str(record.get("version") or "") != expected:
                if _missing(field, fact, metadata, rich) and str(statuses.get(field) or "").lower() == "accepted":
                    statuses[field] = "stale_contract"
                    stale.append(field)
                continue
            if str(record.get("status") or "").lower() != "accepted":
                if _missing(field, fact, metadata, rich) and statuses.get(field) == "accepted":
                    statuses[field] = "cache_not_accepted"
                    stale.append(field)
                continue
            value = record.get("value")
            if field == "activity_sector_match":
                activity_record = fields.get("activity_description", {})
                if (activity_record.get("status") != "accepted"
                        or activity_record.get("version") != source_facts_ai.FIELD_VERSIONS["activity_description"]
                        or not activity_record.get("value")):
                    statuses[field] = "rejected_dependency"
                    stale.append(field)
                    continue
            done = _materialize_list(field, value, fact, evidence)
            if not done:
                done = _materialize_scalar(field, value, fact, evidence)
            if not done and field in RICH_FIELDS and not rich.get(field) and isinstance(value, list) and value:
                rich[field] = value
                done = True
            if not done and field == "threat_candidate" and not metadata.get("threat_tentative") and isinstance(value, dict):
                metadata["threat_tentative"] = value
                done = True
            if done:
                materialized.append(field)
        if materialized or stale:
            if materialized:
                metadata["rich_facts"] = rich
                metadata["_source_facts_materialized_fields"] = sorted(set(materialized))
            if stale:
                metadata["_source_facts_semantic_status"] = statuses
                metadata["_source_facts_stale_contracts"] = sorted(set(stale))
            fact["Source_Metadata_JSON"] = _dumps(metadata)
            fact["Evidence_JSON"] = _dumps(evidence)
            changed.append(str(fact.get("Item_ID") or ""))
    return facts, sorted(set(changed))
