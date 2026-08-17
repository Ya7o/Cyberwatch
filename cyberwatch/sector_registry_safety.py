"""Gardes supplémentaires du registre Sector.

Toute contradiction entre preuves connues bloque l'auto-propagation, même si
le canal contradictoire n'est pas lui-même activé. Un signal fort ne doit pas
écraser silencieusement une autre valeur déjà observée pour la même identité.
"""
from __future__ import annotations

from . import config, sector_registry


def enforce_candidate_conflicts(rows: list[dict]) -> list[dict]:
    for row in rows:
        candidates = {
            part.strip()
            for part in (row.get("Candidate_Sectors") or "").split(" | ")
            if part.strip() and part.strip() != config.SECTOR_UNKNOWN
        }
        if len(candidates) <= 1:
            continue
        row["Decision"] = sector_registry.DECISION_CONFLICT
        row["Sector"] = config.SECTOR_UNKNOWN
        row["Confidence"] = ""
        row["Policy_Auto_Enabled"] = "0"
    return rows
