"""Provenance et réparation des snapshots du pipeline quotidien."""

from __future__ import annotations

import os
import subprocess
from collections import defaultdict
from typing import TYPE_CHECKING

from . import identity, sources, store
from .model import Incident, Item

if TYPE_CHECKING:  # pragma: no cover - typage seul
    from .runner import RunReport


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


def run_log_row(report: RunReport, counts: dict[str, int]) -> dict[str, object]:
    """Ligne du journal de run, dérivée du rapport et du décompte de sources.

    Isolée de :func:`cyberwatch.runner._persist` pour que la composition du
    journal reste lisible indépendamment de l'ordre d'écriture des fichiers
    canoniques.
    """
    from . import sources, status

    context = report.context
    return {
        "Run_ID": context.run_id,
        "As_Of": context.as_of,
        "Mode": context.mode,
        "Method_ID": context.method_id,
        "Target_Start": context.target_start,
        "Target_End": context.target_end,
        "Layers": ",".join(dict.fromkeys(
            spec.layer for spec in sources.active_sources(context.layers)
        )),
        "Items_Count": len(report.items),
        "Incidents_Count": len(report.incidents),
        "New_Items": report.new_items,
        "New_Incidents": report.new_incidents,
        "Source_Status": "OK" if report.overall == "OK" else status.FAIL,
        "Items_seen": sum(o.items_seen for o in report.outcomes),
        "Items_in_window": sum(o.items_in_window for o in report.outcomes),
        "Sources_OK": counts.get(status.OK, 0),
        "Sources_PARTIAL": counts.get(status.PARTIAL, 0),
        "Sources_FAIL": counts.get(status.FAIL, 0),
        "Sources_SKIPPED": counts.get(status.SKIPPED, 0),
        "Items_Hash": report.items_hash,
        "Incidents_Hash": report.incidents_hash,
        "Overall_Status": report.overall,
        "Duration_s": report.duration,
        "Requests": report.requests,
        "Trigger": os.getenv("CYBERWATCH_RUN_TRIGGER", "local"),
        "GitHub_Run_ID": os.getenv("GITHUB_RUN_ID", ""),
        "Base_Commit": os.getenv("CYBERWATCH_BASE_COMMIT", "") or code_commit(),
        "LLM_Calls": report.llm_calls,
        "LLM_Cost_USD": f"{report.llm_cost_usd:.6f}",
        "Notes": " ; ".join(report.problems),
    }


def save_canonical_snapshot(report: RunReport, *, operation: str, full: bool) -> None:
    """Écrit les données canoniques puis la provenance du snapshot.

    ``full=False`` correspond au rejeu sans collecte : ni SourceFacts, ni
    registres de déduplication, car aucun n'a été recalculé par ce passage.
    """
    from . import dedup_review, org_identity

    context = report.context
    store.save_items(report.items)
    store.save_incidents(report.incidents)
    store.save_sector_resolution(report.sector_resolution_rows)
    store.save_incident_id_registry(report.incident_id_registry)
    if full:
        store.save_source_facts(report.source_facts)
        # Les décisions du filet LLM deviennent canoniques uniquement avec le
        # snapshot final. Un run cassé ne peut donc plus polluer la MAJ suivante.
        store.save_incident_dedup_registry(report.incident_dedup_rows)
        store.save_organisation_identity_registry_rows(report.organisation_identity_rows)
        org_identity.reload_organisation_identity_registry(
            store.ORGANISATION_IDENTITY_REGISTRY_CSV
        )
        if report.dedup_ai_state is not None:
            dedup_review.save(report.dedup_ai_state)
    save_snapshot_provenance(
        store.load_items(), store.load_incidents(), operation=operation,
        run_id=context.run_id, mode=context.mode, as_of=context.as_of,
        target_start=context.target_start, target_end=context.target_end,
    )
