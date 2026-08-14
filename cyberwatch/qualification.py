"""Phase canonique, offline et idempotente de qualification d'un snapshot."""

from __future__ import annotations

from dataclasses import dataclass

from . import enrichment, identity
from .dedup import build_incidents
from .model import Incident, Item


@dataclass(frozen=True)
class QualificationReport:
    items: list[Item]
    incidents: list[Incident]
    changes: dict[str, int]
    items_hash: str
    incidents_hash: str


def qualify(items: list[Item]) -> QualificationReport:
    """Apply all deterministic enrichment before incident reconstruction.

    This function deliberately performs no I/O.  It is the single shared path
    for collected data, replay and local repairs, so its output is safe to
    compare or persist only after the caller has completed its checks.
    """
    ordered = identity.sort_items(items)
    reference = enrichment.load_reference()
    changes = enrichment.enrich_items(ordered, reference)
    changes.update(enrichment.backfill_unknowns(ordered, reference))
    incidents = build_incidents(ordered)
    return QualificationReport(
        items=ordered,
        incidents=incidents,
        changes=changes,
        items_hash=identity.items_hash(ordered),
        incidents_hash=identity.incidents_hash(incidents),
    )
