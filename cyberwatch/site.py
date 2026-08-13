"""Génération des données consommées par le dashboard GitHub Pages.

Deux fichiers seulement, pour que la page reste simple et se charge d'un bloc :

- `incidents.json` : la liste des incidents, que le dashboard filtre et agrège
  côté navigateur ;
- `status.json`    : santé du dernier run, angles morts, état de veille par
  entité, historique des runs et état fonctionnel BonjourLaFuite V0.

Aucun agrégat métier n'est précalculé : les KPI et graphiques sont recalculés à
chaque changement de filtre dans le navigateur. Les métriques BonjourLaFuite
sont, elles, le compte rendu brut du collecteur du dernier run.
"""

from __future__ import annotations

from . import config, sources, status, store
from .model import Incident


def incidents_payload(incidents: list[Incident]) -> list[dict]:
    """Incidents au format compact attendu par le dashboard."""
    payload = []
    for incident in incidents:
        payload.append(
            {
                "id": incident.Incident_ID,
                "date": incident.Date,
                "basis": incident.Date_Basis,
                "org": incident.Organisation,
                "sector": incident.Secteur,
                "threat": incident.Menace,
                "location": incident.Localisation,
                "sources": [s for s in incident.Sources.split(" | ") if s],
                "urls": [u for u in incident.Source_URLs.split(" | ") if u],
                "items": incident.Items_Count,
                "first_seen": incident.First_seen,
                "last_seen": incident.Last_seen,
            }
        )
    return payload


def _source_metadata() -> dict[str, dict]:
    return {
        spec.source_id: {
            "layer": spec.layer,
            "zone": spec.zone,
            "url": spec.start_url,
            "notes": spec.notes,
            "success_test": spec.success_test,
        }
        for spec in sources.ALL_SOURCES
    }


def _comment_metric(comment: str, key: str) -> str:
    """Lit une métrique `cle=valeur` du commentaire machine du collecteur."""
    prefix = f"{key}="
    for part in (comment or "").split(";"):
        token = part.strip()
        if token.startswith(prefix):
            return token[len(prefix):].strip()
    return ""


def status_payload() -> dict:
    """Santé du dernier run, angles morts, veille et état BonjourLaFuite."""
    run_log = store.load_run_log()
    run_sources = store.load_run_sources()
    entity_watch = store.load_entity_watch()
    metadata = _source_metadata()

    last_run = run_log[-1] if run_log else {}
    last_run_id = last_run.get("Run_ID", "")

    current = [row for row in run_sources if row.get("Run_ID") == last_run_id]

    health_rows = []
    for row in current:
        source_id = row.get("Source_ID", "")
        meta = metadata.get(source_id, {})
        coverage = _to_int(row.get("Coverage"))
        items = _to_int(row.get("Items_collected"))
        row_status = row.get("Status", status.SKIPPED)
        comment = row.get("Comment", "")
        items_seen = _to_int(row.get("Items_seen"))
        units_done = _to_int(row.get("Units_Done"))

        health_rows.append(
            {
                "id": source_id,
                "layer": row.get("Layer", meta.get("layer", "")),
                "zone": meta.get("zone", ""),
                "url": meta.get("url", ""),
                "status": row_status,
                "coverage": coverage,
                "reason_code": row.get("Reason_Code", ""),
                "reason": row.get("Reason", ""),
                "items": items,
                "items_seen": items_seen,
                "items_collected": items,
                # Pour BonjourLaFuite V0, Units_Done transporte uniquement le
                # nombre reconnu dans la fenêtre. Il ne sert jamais au statut.
                "items_in_window": _to_int(row.get("Items_in_window")) if source_id == "BONJOURLAFUITE" else items,
                "units_done": units_done,
                "units_expected": _to_int(row.get("Units_Expected")),
                "calls": _to_int(row.get("Calls")),
                "latest_item": row.get("Latest_item_date", ""),
                "last_recognized_date": (
                    _comment_metric(comment, "last_recognized_date")
                    if source_id == "BONJOURLAFUITE"
                    else row.get("Latest_item_date", "")
                ),
                "last_recognized_org": (
                    _comment_metric(comment, "last_recognized_org")
                    if source_id == "BONJOURLAFUITE"
                    else ""
                ),
                "access_method": row.get("Access_Method", ""),
                "duration": row.get("Duration_s", ""),
                "comment": comment,
                "last_run": last_run.get("As_Of", ""),
                "error": (
                    (comment or row.get("Reason", ""))
                    if source_id == "BONJOURLAFUITE" and row_status == status.FAIL
                    else ""
                ),
                # Un zéro n'est un vrai zéro que si le protocole est allé au bout.
                "zero_is_trusted": row_status == status.OK and items == 0,
            }
        )

    health_rows.sort(
        key=lambda row: (-status.STATUS_SEVERITY.get(row["status"], 0), row["id"])
    )

    blind = [
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
        for row in health_rows
        if row["status"] in (status.PARTIAL, status.FAIL)
    ]

    history = [
        {
            "run_id": row.get("Run_ID", ""),
            "as_of": row.get("As_Of", ""),
            "mode": row.get("Mode", ""),
            "items": _to_int(row.get("Items_Count")),
            "incidents": _to_int(row.get("Incidents_Count")),
            "new_items": _to_int(row.get("New_Items")),
            "new_incidents": _to_int(row.get("New_Incidents")),
            "health": _to_int(row.get("Health_Score")),
            "overall": row.get("Overall_Status", ""),
        }
        for row in run_log[-60:]
    ]

    watch = [
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

    bonjour = next(
        (row for row in health_rows if row["id"] == "BONJOURLAFUITE"), None
    )
    bonjour_payload = {}
    if bonjour:
        bonjour_payload = {
            "status": bonjour["status"],
            "items_seen": bonjour["items_seen"],
            "items_in_window": bonjour["items_in_window"],
            "items_collected": bonjour["items_collected"],
            "last_recognized_date": bonjour["last_recognized_date"],
            "last_recognized_org": bonjour["last_recognized_org"],
            "last_run": bonjour["last_run"],
            "error": bonjour["error"],
        }

    return {
        "method_id": last_run.get("Method_ID", config.METHOD_ID),
        "run": {
            "id": last_run_id,
            "as_of": last_run.get("As_Of", ""),
            "mode": last_run.get("Mode", ""),
            "target_start": last_run.get("Target_Start", ""),
            "target_end": last_run.get("Target_End", ""),
            "layers": last_run.get("Layers", ""),
            "overall": last_run.get("Overall_Status", ""),
            "health": _to_int(last_run.get("Health_Score")),
            "items": _to_int(last_run.get("Items_Count")),
            "incidents": _to_int(last_run.get("Incidents_Count")),
            "new_items": _to_int(last_run.get("New_Items")),
            "new_incidents": _to_int(last_run.get("New_Incidents")),
            "duration": last_run.get("Duration_s", ""),
            "requests": _to_int(last_run.get("Requests")),
            "items_hash": last_run.get("Items_Hash", ""),
            "incidents_hash": last_run.get("Incidents_Hash", ""),
            "notes": last_run.get("Notes", ""),
        },
        "counts": {
            "ok": _to_int(last_run.get("Sources_OK")),
            "partial": _to_int(last_run.get("Sources_PARTIAL")),
            "fail": _to_int(last_run.get("Sources_FAIL")),
            "skipped": _to_int(last_run.get("Sources_SKIPPED")),
        },
        "bonjourlafuite": bonjour_payload,
        "sources": health_rows,
        "blind_spots": blind,
        "entities": watch,
        "history": history,
        "focus_locations": config.FOCUS_LOCATIONS,
        "labels": {
            "status": status.STATUS_LABELS,
            "run_status": status.RUN_STATUS_LABELS,
        },
    }


def _to_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


def build() -> tuple[int, int]:
    """Écrit les données du site. Renvoie (nb incidents, nb sources)."""
    incidents = store.load_incidents()
    payload = incidents_payload(incidents)
    state = status_payload()

    store.write_json(store.SITE_DATA_DIR / "incidents.json", payload)
    store.write_json(store.SITE_DATA_DIR / "status.json", state)
    return len(payload), len(state["sources"])
