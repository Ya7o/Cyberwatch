"""Invariants de sûreté du chantier Performance/Incrémental."""
from __future__ import annotations


def validate_performance_row(row: dict) -> list[str]:
    """Retourne les violations de contrat sans dépendre d'un temps absolu."""
    errors: list[str] = []
    mode = str(row.get("qualification_mode") or "")
    new = int(row.get("prequal_new") or 0)
    dirty = int(row.get("prequal_dirty") or 0)
    if mode == "delta" and (new or dirty):
        errors.append(f"delta_with_work:new={new},dirty={dirty}")
    if mode == "delta" and int(row.get("sourcefacts_llm_calls") or 0) > 0:
        errors.append("delta_with_sourcefacts_llm")
    if int(row.get("shadow_mismatches") or 0) > 0:
        errors.append("shadow_mismatch")
    return errors


def validate_history(rows: list[dict]) -> list[str]:
    errors: list[str] = []
    for row in rows:
        run_id = str(row.get("run_id") or row.get("Run_ID") or "unknown")
        errors.extend(f"{run_id}:{error}" for error in validate_performance_row(row))
    return errors
