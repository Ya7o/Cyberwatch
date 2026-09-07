"""Qualification prudente du territoire à partir des faits de localisation."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from . import config, sources
from .model import Item
from .normalize import classify_location
from .sector_activity import organisation_span

_THIRD_PARTY_RE = re.compile(
    r"\b(?:prestataire|fournisseur|partenaire|client|filiale|sous[- ]traitant|tiers)\b",
    re.I,
)


@dataclass(frozen=True)
class LocationDecision:
    value: str
    status: str
    reason: str
    evidence: str = ""


def _evidence(fact: dict) -> str:
    try:
        evidence = json.loads(str(fact.get("Evidence_JSON") or "{}"))
    except (TypeError, ValueError):
        return ""
    value = evidence.get("Fine_Location", "") if isinstance(evidence, dict) else ""
    if isinstance(value, list):
        return " ".join(str(part) for part in value if str(part).strip())
    return str(value or "").strip()


def resolve_fact_location(item: Item, fact: dict) -> LocationDecision | None:
    """Accepte un lieu fin seulement s'il désigne la victime dans sa preuve."""
    fine = str(fact.get("Fine_Location") or "").strip()
    territory = classify_location(given=fine)
    if territory == config.LOC_INCONNU:
        return None
    proof = _evidence(fact)
    if not proof or organisation_span(item.Organisation_Raw, proof) is None:
        return None
    if _THIRD_PARTY_RE.search(proof):
        return None
    if classify_location(proof) != territory:
        return None
    return LocationDecision(territory, "reported", "FINE_LOCATION_EVIDENCE", proof)


def apply_fine_locations(items: list[Item], facts: list[dict] | None) -> int:
    """Remplace uniquement un inconnu ou le défaut géographique de la source."""
    by_id = {str(row.get("Item_ID") or ""): row for row in facts or []}
    changed = 0
    for item in items:
        decision = resolve_fact_location(item, by_id.get(item.Item_ID, {}))
        if decision is None:
            continue
        spec = sources.by_id(item.Source_ID)
        source_default = spec.location_rule if spec else ""
        if item.Location not in {"", config.LOC_INCONNU, source_default}:
            continue
        before = item.Location
        item.Location = decision.value
        item._location_decision = decision
        changed += item.Location != before
    return changed
