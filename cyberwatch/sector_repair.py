"""Reprise hors ligne du seul secteur, sans reconstruire les incidents."""
from __future__ import annotations

import copy
import json

from . import sector_resolution
from .model import Item
from .normalize import organisation_key
from .sector_activity import ACTIVITY_FIELDS
from .source_facts_ai_activity import normalize_activity
from .source_facts_ai_contract import FIELD_VERSIONS


def repair_activity_facts(items: list[Item], facts: list[dict], cache: dict) -> list[str]:
    """Réexamine les citations acceptées du cache portant exactement le même hash."""
    by_id = {item.Item_ID: item for item in items}
    by_key = {(e.get("item_id"), e.get("content_hash")): e
              for e in cache.get("entries", {}).values()}
    changed = []
    for fact in facts:
        item = by_id.get(fact.get("Item_ID"))
        if item is None:
            continue
        metadata = json.loads(fact.get("Source_Metadata_JSON") or "{}")
        entry = by_key.get((item.Item_ID, metadata.get("_source_facts_content_hash")))
        if not entry:
            continue
        records = entry.get("fields", {})
        raw = {field: records.get(field, {}).get("value") for field in ACTIVITY_FIELDS
               if records.get(field, {}).get("status") == "accepted"}
        context = "\n".join(str(value.get("evidence") or "") for value in raw.values()
                            if isinstance(value, dict))
        normalized, reasons = normalize_activity(raw, context, item.Organisation_Raw)
        for field in ACTIVITY_FIELDS:
            record = records.get(field, {})
            if record.get("status") == "rejected_validation" and record.get("rejection_reason"):
                reasons[field] = record["rejection_reason"]
        evidence = json.loads(fact.get("Evidence_JSON") or "{}")
        statuses = metadata.setdefault("_source_facts_semantic_status", {})
        before = copy.deepcopy(fact)
        for field, column in (("activity_description", "Activity_Description"),
                              ("activity_sector_match", "Activity_Sector_Match")):
            value = normalized.get(field)
            if value:
                fact[column] = value["value"]
                evidence[column] = value["evidence"]
                statuses[field] = "accepted"
                records[field] = {"version": FIELD_VERSIONS[field], "status": "accepted",
                                  "misses": 0, "value": value, "validation": "CACHE_EVIDENCE_REVIEW"}
            elif field in raw:
                fact[column] = ""
                evidence.pop(column, None)
                statuses[field] = "rejected_validation"
                # Une reprise hors ligne n'est pas un nouvel essai LLM.
                records[field] = {**records[field], "status": "rejected_validation",
                                  "rejection_reason": reasons.get(field, "NO_VALID_ACTIVITY_PAIR")}
        metadata["_sector_repair"] = {"version": sector_resolution.POLICY_VERSION,
                                      "method": "ACCEPTED_CACHE_CITATIONS", "rejections": reasons}
        fact["Evidence_JSON"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True)
        fact["Source_Metadata_JSON"] = json.dumps(metadata, ensure_ascii=False, sort_keys=True)
        if fact != before:
            changed.append(item.Item_ID)
    return changed


def incident_members(items: list[Item], incidents: list) -> dict[str, list[Item]]:
    """Retrouve les membres par les URL déjà publiées ; refuse toute ambiguïté."""
    result = {}
    assigned: dict[str, str] = {}
    for incident in incidents:
        urls = set(incident.Source_URLs.split(" | "))
        members = [item for item in items if item.URL and item.URL in urls or (
            not item.URL and item.best_date == incident.Date
            and item.Source_ID in incident.Sources.split(" | ")
            and organisation_key(item.Organisation_Raw) == organisation_key(incident.Organisation)
        )]
        if len(members) != incident.Items_Count:
            raise ValueError(f"sector_repair_membership_ambiguous:{incident.Incident_ID}")
        for item in members:
            if item.Item_ID in assigned:
                raise ValueError(f"sector_repair_shared_item:{item.Item_ID}")
            assigned[item.Item_ID] = incident.Incident_ID
        result[incident.Incident_ID] = members
    if len(assigned) != len(items):
        raise ValueError("sector_repair_unassigned_items")
    return result


def repair_snapshot(items: list[Item], incidents: list, facts: list[dict], cache: dict,
                    reference: dict, previous: list[dict]) -> tuple[list[dict], dict]:
    members = incident_members(items, incidents)
    before = {incident.Incident_ID: incident.to_row() for incident in incidents}
    changed_facts = repair_activity_facts(items, facts, cache)
    decisions = sector_resolution.resolve_items(items, facts, reference, previous_rows=previous)
    for incident in incidents:
        incident.Secteur = sector_resolution.component_sector(members[incident.Incident_ID])
        for key, value in incident.to_row().items():
            if key != "Secteur" and value != before[incident.Incident_ID][key]:
                raise AssertionError(f"Non-sector field changed: {key}")
    changes = [{"id": i.Incident_ID, "organisation": i.Organisation,
                "before": before[i.Incident_ID]["Secteur"], "after": i.Secteur}
               for i in incidents if i.Secteur != before[i.Incident_ID]["Secteur"]]
    report = {"items": len(items), "incidents": len(incidents), "changed_facts": changed_facts,
              "changes": changes, "unknown_before": sum(r["Secteur"] == "Inconnu" for r in before.values()),
              "unknown_after": sum(i.Secteur == "Inconnu" for i in incidents),
              "unresolved": [r for r in decisions if r["Resolved_Sector"] == "Inconnu"]}
    return decisions, report
