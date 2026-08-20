"""Primitives déterministes pour l'exécution incrémentale de la qualification.

Ce module ne court-circuite encore aucune étape métier. Il fournit le contrat
stable permettant d'identifier les items nouveaux, modifiés et inchangés avant
d'activer progressivement la réutilisation des qualifications existantes.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Mapping

from .model import Item

QUALIFICATION_FINGERPRINT_VERSION = "QUAL-FP-1"

# Collected_As_Of est volontairement absent : sa variation à chaque collecte
# ne représente pas une modification métier et rendrait tous les items dirty.
_ITEM_FIELDS = (
    "Item_ID",
    "Source_ID",
    "Source_Item_ID",
    "Published_Date",
    "Event_Date",
    "Organisation_Raw",
    "Organisation_Key",
    "Threat_Raw",
    "Threat",
    "Sector",
    "Location",
    "Title",
    "URL",
)


@dataclass(frozen=True)
class DirtySet:
    """Partition d'un corpus selon son état vis-à-vis du snapshot précédent."""

    new: tuple[str, ...]
    dirty: tuple[str, ...]
    unchanged: tuple[str, ...]
    fingerprints: dict[str, str]

    @property
    def work_item_ids(self) -> tuple[str, ...]:
        return self.new + self.dirty

    @property
    def reuse_ratio(self) -> float:
        total = len(self.new) + len(self.dirty) + len(self.unchanged)
        return (len(self.unchanged) / total) if total else 1.0


def _stable_fact_rows(rows: Iterable[Mapping[str, object]]) -> list[dict[str, str]]:
    """Normalise les faits source indépendamment de leur ordre d'entrée."""
    normalized = []
    for row in rows:
        normalized.append({
            str(key): str(value or "")
            for key, value in sorted(row.items())
            if key not in {"Item_ID", "Collected_As_Of"}
        })
    return sorted(normalized, key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True))


def qualification_fingerprint(
    item: Item,
    source_facts: Iterable[Mapping[str, object]] = (),
    *,
    policy_version: str,
) -> str:
    """Empreinte des seules entrées capables d'invalider une qualification."""
    payload = {
        "fingerprint_version": QUALIFICATION_FINGERPRINT_VERSION,
        "policy_version": policy_version,
        "item": {field: str(getattr(item, field, "") or "") for field in _ITEM_FIELDS},
        "source_facts": _stable_fact_rows(source_facts),
    }
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def classify_items(
    items: Iterable[Item],
    previous_fingerprints: Mapping[str, str],
    *,
    facts_by_item: Mapping[str, Iterable[Mapping[str, object]]] | None = None,
    policy_version: str,
) -> DirtySet:
    """Classe les items en NEW / DIRTY / UNCHANGED de façon déterministe."""
    facts_by_item = facts_by_item or {}
    new: list[str] = []
    dirty: list[str] = []
    unchanged: list[str] = []
    fingerprints: dict[str, str] = {}

    for item in sorted(items, key=lambda value: value.Item_ID):
        fingerprint = qualification_fingerprint(
            item,
            facts_by_item.get(item.Item_ID, ()),
            policy_version=policy_version,
        )
        fingerprints[item.Item_ID] = fingerprint
        previous = previous_fingerprints.get(item.Item_ID)
        if previous is None:
            new.append(item.Item_ID)
        elif previous == fingerprint:
            unchanged.append(item.Item_ID)
        else:
            dirty.append(item.Item_ID)

    return DirtySet(
        new=tuple(new),
        dirty=tuple(dirty),
        unchanged=tuple(unchanged),
        fingerprints=fingerprints,
    )
