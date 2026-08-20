"""Qualification incrémentale expérimentale avec repli canonique.

Le fast-path n'est autorisé que lorsque le snapshot canonique entrant est
strictement identique au snapshot déjà qualifié et qu'aucun item n'est marqué
NEW/DIRTY. Tout autre cas repasse par ``qualification.qualify``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from . import identity
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
    """Exécute le fast-path sûr, sinon délègue au pipeline canonique complet."""
    reusable, reason = can_reuse_snapshot(
        items,
        previous_items,
        work_item_ids=work_item_ids,
    )
    if not reusable:
        return DeltaQualificationResult(qualify(items), False, reason)

    ordered_items = identity.sort_items(previous_items)
    ordered_incidents = identity.sort_incidents(previous_incidents)
    report = QualificationReport(
        items=ordered_items,
        incidents=ordered_incidents,
        changes={"incremental_snapshot_reused": 1},
        provenance=list(previous_provenance),
        decisions=[],
        decision_summary=[],
        incident_id_registry=list(previous_incident_id_registry),
        items_hash=identity.items_hash(ordered_items),
        incidents_hash=identity.incidents_hash(ordered_incidents),
    )
    return DeltaQualificationResult(report, True, reason)


def parity_signature(report: QualificationReport) -> dict[str, object]:
    """Signature minimale pour comparer un chemin delta au canonique."""
    return {
        "items_hash": report.items_hash,
        "incidents_hash": report.incidents_hash,
        "items_count": len(report.items),
        "incidents_count": len(report.incidents),
    }


def parity_failures(delta: QualificationReport, canonical: QualificationReport) -> list[str]:
    failures: list[str] = []
    left = parity_signature(delta)
    right = parity_signature(canonical)
    for key in ("items_hash", "incidents_hash", "items_count", "incidents_count"):
        if left[key] != right[key]:
            failures.append(f"{key}: delta={left[key]} canonical={right[key]}")
    return failures
