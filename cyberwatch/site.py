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

from . import config, identity, sources, status, store
from .dedup import group_components
from .model import Incident, Item


def incidents_payload(incidents: list[Incident], provenance_tags: dict[str, list[str]] | None = None) -> list[dict]:
    """Incidents au format compact attendu par le dashboard."""
    provenance_tags = provenance_tags or {}
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
                "provenance_tags": provenance_tags.get(incident.Incident_ID, []),
            }
        )
    return payload


def _provenance_tags_by_incident(items: list[Item]) -> dict[str, list[str]]:
    """Expose les imports analytiques sans les transformer en corroboration."""
    payload: dict[str, list[str]] = {}
    for component in group_components(items):
        ordered = identity.sort_items(component)
        if not ordered:
            continue
        incident_id = identity.incident_id(
            ordered[0].Organisation_Key, ordered[0].Item_ID
        )
        tags = set()
        for item in ordered:
            spec = sources.by_id(item.Source_ID)
            tag = spec.params.get("dashboard_filter") if spec else ""
            if tag:
                tags.add(str(tag))
        if tags:
            payload[incident_id] = sorted(tags)
    return payload

def _source_metadata() -> dict[str, dict]:
    return {
        spec.source_id: {
            "layer": spec.layer,
            "zone": spec.zone,
            "url": spec.start_url,
            "notes": spec.notes,
            "success_test": spec.success_test,
            "active": spec.active,
            "coverage_required": bool(spec.params.get("coverage_required")),
            "coverage_group": spec.params.get("coverage_group", ""),
            "candidate_status": spec.params.get("candidate_status", ""),
            "publication_contract": spec.params.get("publication_contract", "historical_required"),
        }
        for spec in sources.ALL_SOURCES
    }


#: Une source candidate non activée n'est pas un échec de collecte (§13 Lot 1
#: Mayotte) : un angle mort technique, une activité à confirmer et un titre
#: arrêté sont trois situations distinctes, jamais confondues avec un run cassé.
_CANDIDATE_REASON_TEXT = {
    status.CANDIDATE_BLIND_SPOT: "Source active mais techniquement inaccessible (angle mort).",
    status.CANDIDATE_TO_CONFIRM: "Activité actuelle non confirmée.",
    status.CANDIDATE_CEASED: "Titre arrêté.",
}


def _comment_metric(comment: str, key: str) -> str:
    """Lit une métrique `cle=valeur` du commentaire machine du collecteur."""
    prefix = f"{key}="
    for part in (comment or "").split(";"):
        token = part.strip()
        if token.startswith(prefix):
            return token[len(prefix):].strip()
    return ""


def _coverage_groups(rows: list[dict], metadata: dict[str, dict]) -> dict[str, dict]:
    """Agrège les sources requises sans masquer celles absentes du run.

    Un titre arrêté ou à activité incertaine n'est pas un échec de couverture
    (§13 Lot 1 Mayotte) : seule une source réellement active et cassée compte
    contre `coverage`. Les candidates non activées sont réparties par
    `candidate_status` (angle mort technique / à confirmer / arrêté), affichées
    à titre informatif sans jamais faire passer le groupe en `PARTIAL`.
    """
    groups: dict[str, list[dict]] = {}
    for row in rows:
        group = metadata.get(row["id"], {}).get("coverage_group", "")
        if group:
            groups.setdefault(group, []).append(row)
    payload = {}
    for group, members in groups.items():
        candidate_of = lambda row: metadata.get(row["id"], {}).get("candidate_status", "")
        collected = sum(row["status"] == status.OK for row in members)
        blind_spot = sum(candidate_of(row) == status.CANDIDATE_BLIND_SPOT for row in members)
        to_confirm = sum(candidate_of(row) == status.CANDIDATE_TO_CONFIRM for row in members)
        ceased = sum(candidate_of(row) == status.CANDIDATE_CEASED for row in members)
        broken = sum(
            row["status"] in (status.FAIL, status.PARTIAL)
            or (row["status"] == status.NOT_COVERED and not candidate_of(row))
            for row in members
        )
        payload[group] = {
            "expected": len(members),
            "collected": collected,
            "blind_spot": blind_spot,
            "to_confirm": to_confirm,
            "ceased": ceased,
            "broken": broken,
            "coverage": "COMPLETE" if not broken else "PARTIAL",
        }
    return payload


def status_payload() -> dict:
    """Santé du dernier run, angles morts, veille et état BonjourLaFuite."""
    base_state, base_problems = store.snapshot_state()
    if base_state != store.BASE_VALID:
        message = (
            "Aucune collecte validée disponible."
            if base_state == store.BASE_UNINITIALIZED
            else "Base Cyberwatch incohérente : " + "; ".join(base_problems)
        )
        return {
            "initialized": False,
            "message": message,
            "run": {},
            "counts": {"ok": 0, "partial": 0, "fail": 0, "skipped": 0},
            "sources": [],
            "blind_spots": [],
            "entities": [],
            "history": [],
            "focus_locations": config.FOCUS_LOCATIONS,
            "labels": {
                "status": status.STATUS_LABELS,
                "run_status": status.RUN_STATUS_LABELS,
                "candidate_status": status.CANDIDATE_STATUS_LABELS,
            },
        }

    run_log = store.load_run_log()
    run_sources = store.load_run_sources()
    entity_watch = store.load_entity_watch()
    metadata = _source_metadata()

    last_run = run_log[-1] if run_log else {}
    last_run_id = last_run.get("Run_ID", "")

    current = [row for row in run_sources if row.get("Run_ID") == last_run_id]

    source_rows = []
    for row in current:
        source_id = row.get("Source_ID", "")
        meta = metadata.get(source_id, {})
        coverage = _to_int(row.get("Coverage"))
        items = _to_int(row.get("Items_collected"))
        row_status = row.get("Status", status.SKIPPED)
        comment = row.get("Comment", "")
        items_seen = _to_int(row.get("Items_seen"))
        units_done = _to_int(row.get("Units_Done"))

        source_rows.append(
            {
                "id": source_id,
                "layer": row.get("Layer", meta.get("layer", "")),
                "zone": meta.get("zone", ""),
                "url": meta.get("url", ""),
                "notes": meta.get("notes", ""),
                "candidate_status": meta.get("candidate_status", ""),
                "status": row_status,
                "coverage": coverage,
                "reason_code": row.get("Reason_Code", ""),
                "reason": row.get("Reason", ""),
                "items": items,
                "items_seen": items_seen,
                "items_collected": items,
                "items_in_window": _to_int(row.get("Items_in_window")),
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

    # Une veille régionale déclarée mais désactivée est un angle mort produit,
    # pas un silence : le dashboard doit pouvoir le rendre visible.
    present = {row["id"] for row in source_rows}
    for source_id, meta in metadata.items():
        if source_id in present or not meta.get("coverage_required"):
            continue
        candidate_status = meta.get("candidate_status", "")
        reason_code = status.REASON_LAYER_NOT_SCHEDULED if meta.get("active") else status.REASON_SOURCE_INACTIVE
        reason = _CANDIDATE_REASON_TEXT.get(candidate_status) or status.reason_text(reason_code)
        source_rows.append({
            "id": source_id, "layer": meta["layer"], "zone": meta["zone"], "url": meta["url"],
            "candidate_status": candidate_status,
            "status": status.NOT_COVERED, "coverage": 0, "reason_code": reason_code,
            "reason": reason, "items": 0, "items_seen": 0,
            "items_collected": 0, "items_in_window": 0, "units_done": 0, "units_expected": 0,
            "calls": 0, "latest_item": "", "last_recognized_date": "", "last_recognized_org": "",
            "access_method": "", "duration": "", "comment": (
                meta.get("notes", "") if not meta.get("active") else "Source locale requise mais absente du dernier run."
            ),
            "last_run": last_run.get("As_Of", ""), "error": "", "zero_is_trusted": False,
        })

    source_rows.sort(
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
        for row in source_rows
        if row["status"] in (status.NOT_COVERED, status.PARTIAL, status.FAIL)
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
        (row for row in source_rows if row["id"] == "BONJOURLAFUITE"), None
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
        "initialized": True,
        "method_id": last_run.get("Method_ID", config.METHOD_ID),
        "run": {
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
        },
        "counts": {
            "ok": _to_int(last_run.get("Sources_OK")),
            "partial": _to_int(last_run.get("Sources_PARTIAL")),
            "fail": _to_int(last_run.get("Sources_FAIL")),
            "skipped": _to_int(last_run.get("Sources_SKIPPED")),
        },
        "bonjourlafuite": bonjour_payload,
        "sources": source_rows,
        "blind_spots": blind,
        "coverage_groups": _coverage_groups(source_rows, metadata),
        "entities": watch,
        "history": history,
        "focus_locations": config.FOCUS_LOCATIONS,
        "labels": {
            "status": status.STATUS_LABELS,
            "run_status": status.RUN_STATUS_LABELS,
            "candidate_status": status.CANDIDATE_STATUS_LABELS,
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
    items = store.load_items()
    payload = incidents_payload(incidents, _provenance_tags_by_incident(items))
    state = status_payload()

    store.write_json(store.SITE_DATA_DIR / "incidents.json", payload)
    store.write_json(store.SITE_DATA_DIR / "status.json", state)
    return len(payload), len(state["sources"])
