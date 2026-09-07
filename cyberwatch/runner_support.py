"""Provenance et réparation des snapshots du pipeline quotidien."""

from __future__ import annotations

import os
import subprocess
from collections import defaultdict

from . import identity, sources, store
from .model import Incident, Item


def code_commit() -> str:
    """Retourne le commit exécuté, y compris dans GitHub Actions."""
    if os.getenv("GITHUB_SHA"):
        return os.environ["GITHUB_SHA"]
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=store.ROOT, text=True
        ).strip()
    except Exception:
        return ""


def save_snapshot_provenance(
    items: list[Item],
    incidents: list[Incident],
    *,
    operation: str,
    run_id: str = "",
    mode: str = "",
    as_of: str = "",
    target_start: str = "",
    target_end: str = "",
) -> dict:
    """Enregistre la provenance du snapshot déjà écrit sur disque."""
    payload = {
        "As_Of": as_of,
        "Operation": operation,
        "Run_ID": run_id,
        "Mode": mode,
        "Target_Start": target_start,
        "Target_End": target_end,
        "Items_Count": len(items),
        "Incidents_Count": len(incidents),
        "Items_Hash": identity.items_hash(items),
        "Incidents_Hash": identity.incidents_hash(incidents),
        "Code_Commit": code_commit(),
        "Sources_Active": sorted(
            spec.source_id for spec in sources.ALL_SOURCES if spec.active
        ),
        "Baseline": False,
    }
    store.save_snapshot(payload)
    return payload


def repair_item_integrity(items: list[Item]) -> tuple[list[Item], dict[str, int]]:
    """Répare les IDs et élimine seulement les doublons de clé exacte."""
    groups: dict[tuple[str, str, str, str], list[Item]] = defaultdict(list)
    for item in items:
        key = (item.Source_ID, item.Published_Date, item.Organisation_Key, item.URL)
        groups[key].append(item)

    repaired: list[Item] = []
    dropped = 0
    changed = 0
    for key in sorted(groups):
        candidates = groups[key]
        if len(candidates) > 1:
            dropped += len(candidates) - 1

        def quality(item: Item) -> tuple:
            values = item.to_row()
            populated = sum(
                bool(value) for name, value in values.items() if name != "Item_ID"
            )
            return (-populated, tuple(values[name] for name in sorted(values)))

        item = sorted(candidates, key=quality)[0]
        expected = identity.item_id(
            item.Source_ID,
            item.Published_Date,
            item.Organisation_Key,
            item.URL,
            item.Source_Item_ID,
        )
        if item.Item_ID != expected:
            changed += 1
            item.Item_ID = expected
        repaired.append(item)
    return identity.sort_items(repaired), {
        "ids_repaired": changed,
        "duplicates_removed": dropped,
    }
