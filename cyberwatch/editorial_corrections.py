"""Corrections éditoriales sourcées et rejouables sur les snapshots.

Les extracteurs restent génériques. Lorsqu'un audit humain établit qu'un fait
appartient à un rappel historique, à une autre victime ou à une négation, la
correction est enregistrée par Item_ID dans ``data/editorial_corrections.json``.
Elle est ainsi réappliquée après chaque collecte et reste lisible en revue.
"""
from __future__ import annotations

import json
import unicodedata
from pathlib import Path


CORRECTIONS_PATH = Path(__file__).resolve().parents[1] / "data" / "editorial_corrections.json"

_SEMANTIC_FIELD_BY_COLUMN = {
    "Summary": "summary",
    "Initial_Access": "initial_access",
    "Attack_Flow_JSON": "attack_flow",
    "Impact": "impact",
    "Threat_Actor": "threat_actor",
    "Third_Party": "third_party",
    "Fine_Location": "fine_location",
    "Attack_Date": "attack_date",
    "Discovered_Date": "discovered_date",
    "Evolution": "evolution",
    "Vulnerabilities_JSON": "vulnerabilities",
    "Data_Types_JSON": "data_types",
    "Activity_Description": "activity_description",
    "Activity_Sector_Match": "activity_sector_match",
}


def _norm(value: object) -> str:
    text = unicodedata.normalize("NFD", str(value or ""))
    text = "".join(char for char in text if unicodedata.category(char) != "Mn")
    return " ".join(text.casefold().split())


def load(path: Path = CORRECTIONS_PATH) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"items": {}, "source_facts": {}}
    if not isinstance(payload, dict):
        raise ValueError("Invalid editorial corrections registry")
    for key in ("items", "source_facts"):
        if not isinstance(payload.get(key, {}), dict):
            raise ValueError(f"Invalid editorial corrections section: {key}")
    return payload


def apply_items(items: list, corrections: dict | None = None) -> list[str]:
    rules = (corrections or load()).get("items", {})
    changed: list[str] = []
    for item in items:
        rule = rules.get(str(getattr(item, "Item_ID", "")))
        if not isinstance(rule, dict):
            continue
        touched = False
        for field, value in rule.get("set", {}).items():
            if hasattr(item, field) and getattr(item, field) != value:
                setattr(item, field, value)
                touched = True
        if touched:
            changed.append(item.Item_ID)
    return sorted(changed)


def apply_source_facts(rows: list[dict], corrections: dict | None = None) -> list[str]:
    rules = (corrections or load()).get("source_facts", {})
    changed: list[str] = []
    for row in rows:
        item_id = str(row.get("Item_ID") or "")
        rule = rules.get(item_id)
        if not isinstance(rule, dict):
            continue
        before = json.dumps(row, ensure_ascii=False, sort_keys=True)
        try:
            evidence = json.loads(str(row.get("Evidence_JSON") or "{}"))
        except (TypeError, ValueError):
            evidence = {}
        evidence = evidence if isinstance(evidence, dict) else {}
        try:
            metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
        except (TypeError, ValueError):
            metadata = {}
        metadata = metadata if isinstance(metadata, dict) else {}
        rich = metadata.get("rich_facts") if isinstance(metadata.get("rich_facts"), dict) else {}

        for field in rule.get("clear", []):
            row[field] = ""
            evidence.pop(field, None)
        for field, value in rule.get("set", {}).items():
            row[field] = value
        for field, value in rule.get("evidence_set", {}).items():
            evidence[field] = value
        for field, value in rule.get("metadata_set", {}).items():
            metadata[field] = value

        rejected_terms = [_norm(term) for term in rule.get("rich_remove_evidence_contains", [])]
        remove_values = {
            collection: {_norm(value) for value in values}
            for collection, values in rule.get("rich_remove_values", {}).items()
        }
        for collection, values in list(rich.items()):
            if not isinstance(values, list):
                continue
            blocked_values = remove_values.get(collection, set())
            rich[collection] = [
                value for value in values
                if not isinstance(value, dict) or (
                    not any(term in _norm(value.get("evidence")) for term in rejected_terms)
                    and _norm(value.get("value")) not in blocked_values
                )
            ]
        if rich:
            metadata["rich_facts"] = rich
        suppressed_fields = sorted({
            _SEMANTIC_FIELD_BY_COLUMN[field]
            for field in rule.get("clear", [])
            if field in _SEMANTIC_FIELD_BY_COLUMN
        })
        metadata["editorial_correction"] = {
            "audit": str(rule.get("audit") or ""),
            "reason": str(rule.get("reason") or ""),
            "suppressed_semantic_fields": suppressed_fields,
        }
        row["Evidence_JSON"] = json.dumps(evidence, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if evidence else ""
        row["Source_Metadata_JSON"] = json.dumps(metadata, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        if json.dumps(row, ensure_ascii=False, sort_keys=True) != before:
            changed.append(item_id)
    return sorted(set(changed))
