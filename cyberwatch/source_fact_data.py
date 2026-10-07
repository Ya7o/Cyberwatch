"""Revalidation hors réseau des catégories de données et de leurs démentis."""
from __future__ import annotations

import json

from .source_facts_ai_contract import _NEGATED_DATA_VALUE_SENTENCE
from .source_facts_ai_normalize import data_evidence_clause


def _denied(value: str, proof: str, context: str) -> bool:
    return bool(proof and _NEGATED_DATA_VALUE_SENTENCE.search(
        data_evidence_clause(value, proof, context),
    ))


def sanitize_data_types(fact: dict, metadata: dict, evidence: dict) -> bool:
    """Retire les projections positives ; conserve les preuves riches niées."""
    context = str(metadata.get("editorial_context") or "")
    touched = False
    try:
        values = json.loads(fact.get("Data_Types_JSON") or "[]")
    except (TypeError, ValueError):
        values = []
    proofs = evidence.get("Data_Types_JSON")
    if isinstance(values, list) and isinstance(proofs, dict):
        rejected = [value for value in values if _denied(
            str(value), str(proofs.get(value) or ""), context,
        )]
        if rejected:
            metadata["rejected_data_types"] = [
                {"value": value, "evidence": proofs.get(value, ""),
                 "reason": "DATA_TYPE_NOT_EXPOSED"} for value in rejected
            ]
            kept = [value for value in values if value not in rejected]
            fact["Data_Types_JSON"] = json.dumps(kept, ensure_ascii=False) if kept else ""
            evidence["Data_Types_JSON"] = {
                value: proof for value, proof in proofs.items() if value not in rejected
            }
            touched = True
    rich = metadata.get("rich_facts")
    if isinstance(rich, dict):
        for name in ("data_types", "claims"):
            for row in rich.get(name, []) or []:
                if not isinstance(row, dict) or (
                    name == "claims" and row.get("type") != "data_type"
                ):
                    continue
                if row.get("status") in {"denied", "negated", "hypothesis", "unconfirmed"}:
                    continue
                if _denied(str(row.get("value") or ""), str(row.get("evidence") or ""), context):
                    row["status"] = "negated"
                    touched = True
    return touched
