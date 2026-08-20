"""Primitives déterministes pour l'exécution incrémentale de la qualification.

Ce module ne court-circuite aucune étape métier. Il fournit le contrat stable
permettant d'identifier les items nouveaux, modifiés et inchangés et de
persister cet état pour mesurer la réutilisation possible avant optimisation.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable, Mapping

from .model import Item

QUALIFICATION_FINGERPRINT_VERSION = "QUAL-FP-1"

PROCESSING_STATE_COLUMNS = [
    "Item_ID",
    "Qualification_Fingerprint",
    "Policy_Version",
    "Last_Processed_Run_ID",
    "Last_Processed_As_Of",
]

INCREMENTAL_METRIC_COLUMNS = [
    "Run_ID",
    "As_Of",
    "Mode",
    "Policy_Version",
    "Items_Count",
    "New_Items",
    "Dirty_Items",
    "Unchanged_Items",
    "Reuse_Rate",
]

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
    normalized = []
    for row in rows:
        normalized.append({
            str(key): str(value or "")
            for key, value in sorted(row.items())
            if key not in {"Item_ID", "Collected_As_Of"}
        })
    return sorted(
        normalized,
        key=lambda row: json.dumps(row, ensure_ascii=False, sort_keys=True),
    )


def qualification_fingerprint(
    item: Item,
    source_facts: Iterable[Mapping[str, object]] = (),
    *,
    policy_version: str,
) -> str:
    payload = {
        "fingerprint_version": QUALIFICATION_FINGERPRINT_VERSION,
        "policy_version": policy_version,
        "item": {
            field: str(getattr(item, field, "") or "")
            for field in _ITEM_FIELDS
        },
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


def fingerprints_from_state(rows: Iterable[Mapping[str, object]]) -> dict[str, str]:
    return {
        str(row.get("Item_ID") or ""): str(
            row.get("Qualification_Fingerprint") or ""
        )
        for row in rows
        if row.get("Item_ID") and row.get("Qualification_Fingerprint")
    }


def state_rows(
    dirty_set: DirtySet,
    *,
    policy_version: str,
    run_id: str,
    as_of: str,
) -> list[dict[str, str]]:
    return [
        {
            "Item_ID": item_id,
            "Qualification_Fingerprint": fingerprint,
            "Policy_Version": policy_version,
            "Last_Processed_Run_ID": run_id,
            "Last_Processed_As_Of": as_of,
        }
        for item_id, fingerprint in sorted(dirty_set.fingerprints.items())
    ]


def metric_row(
    dirty_set: DirtySet,
    *,
    run_id: str,
    as_of: str,
    mode: str,
    policy_version: str,
) -> dict[str, str]:
    total = len(dirty_set.fingerprints)
    return {
        "Run_ID": run_id,
        "As_Of": as_of,
        "Mode": mode,
        "Policy_Version": policy_version,
        "Items_Count": str(total),
        "New_Items": str(len(dirty_set.new)),
        "Dirty_Items": str(len(dirty_set.dirty)),
        "Unchanged_Items": str(len(dirty_set.unchanged)),
        "Reuse_Rate": f"{dirty_set.reuse_ratio:.6f}",
    }
