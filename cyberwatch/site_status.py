"""Construction du contrat de santé publié par le dashboard."""

from __future__ import annotations

from collections.abc import Callable

from . import config, production, qualification, site_window, status, store

_CANDIDATE_REASON_TEXT = {
    status.CANDIDATE_BLIND_SPOT: "Source active mais techniquement inaccessible (angle mort).",
    status.CANDIDATE_TO_CONFIRM: "Activité actuelle non confirmée.",
    status.CANDIDATE_CEASED: "Titre arrêté.",
}


def _to_int(value: object) -> int:
    try:
        return int(float(str(value)))
    except (TypeError, ValueError):
        return 0


def _labels() -> dict:
    return {
        "status": status.STATUS_LABELS,
        "run_status": status.RUN_STATUS_LABELS,
        "candidate_status": status.CANDIDATE_STATUS_LABELS,
        "sources": config.SOURCE_LABELS,
    }


def empty_payload(base_state: str, base_problems: list[str]) -> dict:
    message = (
        "Aucune collecte validée disponible."
        if base_state == store.BASE_UNINITIALIZED
        else "Base Cyberwatch incohérente : " + "; ".join(base_problems)
    )
    return {
        "initialized": False,
        "message": message,
        "run": {},
        "integrity": site_window.coverage_status([]),
        "production": production.snapshot_payload([], ""),
        "qualification": {
            "run_id": "", "state": qualification.STATE_UNKNOWN, "reasons": [],
            "pending_fields": 0, "pending_pairs": 0, "label": "",
        },
        "counts": {"ok": 0, "partial": 0, "fail": 0, "skipped": 0},
        "sources": [],
        "blind_spots": [],
        "entities": [],
        "history": [],
        "focus_locations": config.FOCUS_LOCATIONS,
        "labels": _labels(),
    }


def _source_row(row: dict, metadata: dict[str, dict], last_run: dict) -> dict:
    source_id = row.get("Source_ID", "")
    meta = metadata.get(source_id, {})
    row_status = row.get("Status", status.SKIPPED)
    items = _to_int(row.get("Items_collected"))
    return {
        "id": source_id,
        "layer": row.get("Layer", meta.get("layer", "")),
        "zone": meta.get("zone", ""),
        "url": meta.get("url", ""),
        "notes": meta.get("notes", ""),
        "candidate_status": meta.get("candidate_status", ""),
        "status": row_status,
        "coverage": _to_int(row.get("Coverage")),
        "reason_code": row.get("Reason_Code", ""),
        "reason": row.get("Reason", ""),
        "items": items,
        "items_seen": _to_int(row.get("Items_seen")),
        "items_collected": items,
        "items_in_window": _to_int(row.get("Items_in_window")),
        "units_done": _to_int(row.get("Units_Done")),
        "units_expected": _to_int(row.get("Units_Expected")),
        "calls": _to_int(row.get("Calls")),
        "latest_item": row.get("Latest_item_date", ""),
        "latest_item_org": row.get("Latest_Item_Org", ""),
        "access_method": row.get("Access_Method", ""),
        "duration": row.get("Duration_s", ""),
        "comment": row.get("Comment", ""),
        "history_status": row.get("History_Status") or status.HISTORY_UNKNOWN,
        "oldest_available_date": row.get("Oldest_Available_Date") or "",
        "last_run": last_run.get("As_Of", ""),
        "zero_is_trusted": row_status == status.OK and items == 0,
    }


def source_rows(current: list[dict], metadata: dict[str, dict], last_run: dict) -> list[dict]:
    rows = [_source_row(row, metadata, last_run) for row in current]
    present = {row["id"] for row in rows}
    for source_id, meta in metadata.items():
        if source_id in present or not meta.get("coverage_required"):
            continue
        candidate_status = meta.get("candidate_status", "")
        reason_code = (
            status.REASON_LAYER_NOT_SCHEDULED
            if meta.get("active")
            else status.REASON_SOURCE_INACTIVE
        )
        rows.append(
            {
                "id": source_id,
                "layer": meta["layer"],
                "zone": meta["zone"],
                "url": meta["url"],
                "candidate_status": candidate_status,
                "status": status.NOT_COVERED,
                "coverage": 0,
                "reason_code": reason_code,
                "reason": _CANDIDATE_REASON_TEXT.get(candidate_status)
                or status.reason_text(reason_code),
                "items": 0,
                "items_seen": 0,
                "items_collected": 0,
                "items_in_window": 0,
                "units_done": 0,
                "units_expected": 0,
                "calls": 0,
                "latest_item": "",
                "latest_item_org": "",
                "access_method": "",
                "duration": "",
                "comment": meta.get("notes", "")
                if not meta.get("active")
                else "Source locale requise mais absente du dernier run.",
                "history_status": status.HISTORY_UNKNOWN,
                "oldest_available_date": "",
                "last_run": last_run.get("As_Of", ""),
                "zero_is_trusted": False,
            }
        )
    return sorted(
        rows,
        key=lambda row: (-status.STATUS_SEVERITY.get(row["status"], 0), row["id"]),
    )


def blind_rows(rows: list[dict]) -> list[dict]:
    return [
        {
            "id": row["id"],
            "layer": row["layer"],
            "status": row["status"],
            "coverage": row["coverage"],
            "reason": row["reason"],
            "detail": (
                f"{row['units_done']}/{row['units_expected']} unités traitées"
                if row["units_expected"]
                else ""
            ),
        }
        for row in rows
        if row["status"] in (status.NOT_COVERED, status.PARTIAL, status.FAIL)
    ]


def history_rows(run_log: list[dict]) -> list[dict]:
    return [
        {
            "run_id": row.get("Run_ID", ""),
            "as_of": row.get("As_Of", ""),
            "mode": row.get("Mode", ""),
            "items": _to_int(row.get("Items_Count")),
            "incidents": _to_int(row.get("Incidents_Count")),
            "new_items": _to_int(row.get("New_Items")),
            "new_incidents": _to_int(row.get("New_Incidents")),
            "overall": row.get("Overall_Status", ""),
        }
        for row in run_log[-60:]
    ]


def entity_rows(entity_watch: list[dict]) -> list[dict]:
    return [
        {
            "entity": row.get("Entity", ""),
            "territory": row.get("Territory", ""),
            "kind": row.get("Type", ""),
            "sector": row.get("Sector_Hint", ""),
            "last_queried": row.get("Last_Queried", ""),
            "query_status": row.get("Query_Status", ""),
            "items": _to_int(row.get("Items_Found")),
            "last_incident": row.get("Last_Incident_Date", ""),
            "last_incident_id": row.get("Last_Incident_ID", ""),
        }
        for row in entity_watch
    ]


def _run_payload(last_run: dict, last_run_id: str) -> dict:
    return {
        "id": last_run_id,
        "as_of": last_run.get("As_Of", ""),
        "mode": last_run.get("Mode", ""),
        "target_start": last_run.get("Target_Start", ""),
        "target_end": last_run.get("Target_End", ""),
        "layers": last_run.get("Layers", ""),
        "overall": last_run.get("Overall_Status", ""),
        "items": _to_int(last_run.get("Items_Count")),
        "incidents": _to_int(last_run.get("Incidents_Count")),
        "new_items": _to_int(last_run.get("New_Items")),
        "new_incidents": _to_int(last_run.get("New_Incidents")),
        "duration": last_run.get("Duration_s", ""),
        "requests": _to_int(last_run.get("Requests")),
        "items_hash": last_run.get("Items_Hash", ""),
        "incidents_hash": last_run.get("Incidents_Hash", ""),
        "notes": last_run.get("Notes", ""),
    }


def build(
    metadata: dict[str, dict],
    coverage_groups: Callable[[list[dict], dict[str, dict]], dict[str, dict]],
) -> dict:
    """Assemble l'état courant à partir des journaux versionnés."""
    base_state, base_problems = store.snapshot_state()
    if base_state != store.BASE_VALID:
        return empty_payload(base_state, base_problems)

    if store.load_snapshot().get("Operation") == "PURGE":
        payload = empty_payload(store.BASE_UNINITIALIZED, [])
        payload["message"] = "Base vidée. Lancez MAJ pour collecter les dernières publications."
        return payload

    run_log = store.load_run_log()
    last_run = run_log[-1] if run_log else {}
    last_run_id = last_run.get("Run_ID", "")
    rows = source_rows(
        [row for row in store.load_run_sources() if row.get("Run_ID") == last_run_id],
        metadata,
        last_run,
    )
    counts = {
        "ok": _to_int(last_run.get("Sources_OK")),
        "partial": _to_int(last_run.get("Sources_PARTIAL")),
        "fail": _to_int(last_run.get("Sources_FAIL")),
        "skipped": _to_int(last_run.get("Sources_SKIPPED")),
    }
    return {
        "initialized": True,
        "method_id": last_run.get("Method_ID", config.METHOD_ID),
        "integrity": site_window.coverage_status(run_log),
        "production": production.snapshot_payload(run_log, last_run_id),
        # Verdict de qualification du dernier run : un run publié dont
        # l'extraction ou la déduplication est restée bloquée doit le dire.
        "qualification": qualification.payload(last_run_id),
        "run": _run_payload(last_run, last_run_id),
        "counts": counts,
        "sources": rows,
        "blind_spots": blind_rows(rows),
        "coverage_groups": coverage_groups(rows, metadata),
        "entities": entity_rows(store.load_entity_watch()),
        "history": history_rows(run_log),
        "focus_locations": config.FOCUS_LOCATIONS,
        "labels": _labels(),
    }
