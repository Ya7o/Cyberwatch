"""Qualification incrémentale expérimentale avec repli canonique.

Le fast-path n'est autorisé que lorsque le snapshot canonique entrant est
strictement identique au snapshot déjà qualifié et qu'aucun item n'est marqué
NEW/DIRTY. Dans ce cas, la qualification des items est réutilisée mais les
incidents sont toujours reconstruits avec la déduplication courante. Tout autre
cas repasse par ``qualification.qualify``.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable

from . import identity, store
from .dedup import build_incidents_with_registry
from .model import Incident, Item
from .qualification import QualificationReport, qualify


@dataclass(frozen=True)
class DeltaQualificationResult:
    report: QualificationReport
    reused_snapshot: bool
    fallback_reason: str


def can_reuse_snapshot(
    items: list[Item],
    previous_items: list[Item],
    *,
    work_item_ids: Iterable[str],
) -> tuple[bool, str]:
    work = tuple(sorted(set(work_item_ids)))
    if work:
        return False, "work_items_present"
    if len(items) != len(previous_items):
        return False, "item_count_changed"
    if identity.items_hash(items) != identity.items_hash(previous_items):
        return False, "items_hash_changed"
    return True, "exact_snapshot_match"


def qualify_delta(
    items: list[Item],
    *,
    previous_items: list[Item],
    previous_incidents: list[Incident],
    previous_provenance: list[dict[str, str]],
    previous_incident_id_registry: list[dict[str, str]],
    work_item_ids: Iterable[str],
) -> DeltaQualificationResult:
    """Réutilise les items qualifiés inchangés, sinon exécute le canonique complet.

    ``previous_incidents`` reste dans la signature pour documenter explicitement
    le snapshot précédent, mais il n'est jamais réutilisé : une évolution de la
    politique de déduplication doit pouvoir reconstruire les incidents même sans
    changement des items.
    """
    reusable, reason = can_reuse_snapshot(
        items,
        previous_items,
        work_item_ids=work_item_ids,
    )
    if not reusable:
        return DeltaQualificationResult(qualify(items), False, reason)

    ordered_items = identity.sort_items(previous_items)
    incidents, incident_id_registry = build_incidents_with_registry(
        ordered_items,
        previous_incident_id_registry,
        store.load_incident_dedup_registry(),
    )
    ordered_incidents = identity.sort_incidents(incidents)
    report = QualificationReport(
        items=ordered_items,
        incidents=ordered_incidents,
        changes={
            "incremental_snapshot_reused": 1,
            "incremental_incidents_rebuilt": 1,
        },
        provenance=list(previous_provenance),
        decisions=[],
        decision_summary=[],
        incident_id_registry=incident_id_registry,
        items_hash=identity.items_hash(ordered_items),
        incidents_hash=identity.incidents_hash(ordered_incidents),
    )
    return DeltaQualificationResult(report, True, reason)


def _rows_hash(rows: Iterable[dict]) -> str:
    normalized = [
        {str(key): str(value or "") for key, value in sorted(row.items())}
        for row in rows
    ]
    normalized.sort(
        key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True)
    )
    raw = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def parity_signature(report: QualificationReport) -> dict[str, object]:
    """Signature stricte pour comparer un chemin delta au canonique.

    Les hashes métier restent centraux, mais la parité couvre aussi la
    provenance et le registre d'identité : un fast-path n'est pas sûr si les
    mêmes items/incidents masquent une décision ou une identité différente.
    """
    return {
        "items_hash": report.items_hash,
        "incidents_hash": report.incidents_hash,
        "items_count": len(report.items),
        "incidents_count": len(report.incidents),
        "provenance_hash": _rows_hash(report.provenance),
        "incident_registry_hash": _rows_hash(report.incident_id_registry),
    }


def parity_failures(delta: QualificationReport, canonical: QualificationReport) -> list[str]:
    failures: list[str] = []
    left = parity_signature(delta)
    right = parity_signature(canonical)
    for key in (
        "items_hash",
        "incidents_hash",
        "items_count",
        "incidents_count",
        "provenance_hash",
        "incident_registry_hash",
    ):
        if left[key] != right[key]:
            failures.append(f"{key}: delta={left[key]} canonical={right[key]}")
    return failures
