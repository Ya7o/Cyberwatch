"""Génération des données consommées par le dashboard GitHub Pages.

Deux fichiers seulement, pour que la page reste simple et se charge d'un bloc :

- `incidents.json` : la liste des incidents, que le dashboard filtre et agrège
  côté navigateur ;
- `status.json`    : santé du dernier run, angles morts, état de veille par
  entité, historique des runs et état de chaque source (mêmes champs pour
  toutes, sans traitement spécial par source).

Aucun agrégat métier n'est précalculé : les KPI et graphiques sont recalculés à
chaque changement de filtre dans le navigateur.
"""

from __future__ import annotations

import json

from . import config, identity, sources, status, store
from .dedup import group_components
from .model import Incident, Item
from .normalize import organisation_key


_FACT_TEXT_FIELDS = {
    "Claim_Status": "claim_status",
    "Threat_Actor": "threat_actor",
    "Third_Party": "third_party",
    "Fine_Location": "fine_location",
    "Affected_Unit": "affected_unit",
    "Affected_Count_Raw": "affected_count_raw",
    "Data_Volume_Raw": "data_volume",
    "CVSS_Raw": "cvss",
    "Attack_Date": "attack_date",
    "Discovered_Date": "discovered_date",
    "Victim_Website": "victim_website",
    "Impact": "impact",
    "Summary": "summary",
    "Evolution": "evolution",
}
_FACT_INT_FIELDS = {
    "Affected_Count": "affected_count",
    "File_Count": "file_count",
    "Cyberattack_Score": "cyberattack_score",
}
_FACT_LIST_FIELDS = {
    "Data_Types_JSON": "data_types",
    "Vulnerabilities_JSON": "vulnerabilities",
    "Evidence_URLs_JSON": "evidence_urls",
}


def _source_fact_payload(row: dict) -> dict | None:
    """Réduit une ligne technique `source_facts.csv` à sa partie publiable.

    La provenance (`source`, `item_id`) reste obligatoire et les propriétés
    vides sont omises : le frontend peut donc appliquer littéralement la règle
    « donnée disponible = visible, donnée absente = masquée ». Les champs de
    debug/extraction et le secteur brut ne franchissent pas cette frontière.

    Veille LLM est volontairement laissée au renderer historique pour cette
    release de stabilisation afin d'éviter tout double affichage.
    """
    source_id = str(row.get("Source_ID") or "").strip()
    item_id = str(row.get("Item_ID") or "").strip()
    if not source_id or not item_id or source_id == "VEILLE_LLM":
        return None

    payload: dict[str, object] = {"source": source_id, "item_id": item_id}

    for column, key in _FACT_TEXT_FIELDS.items():
        value = str(row.get(column) or "").strip()
        if value:
            payload[key] = value

    for column, key in _FACT_INT_FIELDS.items():
        value = str(row.get(column) or "").strip()
        if not value:
            continue
        try:
            payload[key] = int(value)
        except ValueError:
            continue

    for column, key in _FACT_LIST_FIELDS.items():
        raw = str(row.get(column) or "").strip()
        if not raw:
            continue
        try:
            values = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if not isinstance(values, list):
            continue
        cleaned = [str(value).strip() for value in values if str(value).strip()]
        if cleaned:
            payload[key] = cleaned

    return payload if len(payload) > 2 else None


def _source_facts_by_incident(items: list[Item], fact_rows: list[dict]) -> dict[str, list[dict]]:
    """Joint les faits aux incidents via `Item_ID`, jamais via nom/date/URL.

    Le regroupement réutilise exactement la composante de déduplication qui
    produit les incidents ; une contradiction entre deux sources reste donc
    deux objets séparés dans la liste et n'est jamais résolue ici.
    """
    by_item: dict[str, list[dict]] = {}
    for row in fact_rows:
        fact = _source_fact_payload(row)
        if fact:
            by_item.setdefault(str(fact["item_id"]), []).append(fact)

    payload: dict[str, list[dict]] = {}
    for component in group_components(items):
        ordered = identity.sort_items(component)
        if not ordered:
            continue
        incident_id = identity.incident_id(
            ordered[0].Organisation_Key, ordered[0].Item_ID
        )
        facts: list[dict] = []
        for item in ordered:
            facts.extend(by_item.get(item.Item_ID, []))
        if facts:
            facts.sort(key=lambda fact: (str(fact.get("source", "")), str(fact.get("item_id", ""))))
            payload[incident_id] = facts
    return payload


def incidents_payload(
    incidents: list[Incident],
    local_analysis: dict[str, dict] | None = None,
    source_facts: dict[str, list[dict]] | None = None,
) -> list[dict]:
    """Incidents au format compact attendu par le dashboard."""
    local_analysis = local_analysis or {}
    source_facts = source_facts or {}
    payload = []
    for incident in incidents:
        row = {
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
        analysis = local_analysis.get(incident.Incident_ID)
        if analysis:
            row["local"] = analysis
        facts = source_facts.get(incident.Incident_ID)
        if facts:
            row["facts"] = facts
        payload.append(row)
    return payload


def _local_analysis_by_incident(items: list[Item]) -> dict[str, dict]:
    """Joint le snapshot Veille LLM aux incidents sans en faire une preuve éditoriale."""
    spec = sources.by_id("VEILLE_LLM")
    if spec is None:
        return {}
    relative = str(spec.params.get("path") or "").strip()
    if not relative:
        return {}
    path = (store.ROOT / relative).resolve()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {}

    records = data.get("incidents") or []
    by_key: dict[tuple[str, str], dict] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        try:
            score = int(record.get("score_cyberattaque"))
        except (TypeError, ValueError):
            continue
        # Le score reste une information affichable, jamais un critère
        # d'exclusion : tous les dossiers valides sont importés et joints.
        organisation = str(record.get("organisation") or "").strip()
        date = str(record.get("date") or "").strip()
        summary = str(record.get("synthese") or "").strip()
        refs = record.get("sources") or []
        references = [
            str(url).strip() for url in refs
            if str(url).strip().startswith(("https://", "http://"))
        ]
        if not organisation or not date or not summary:
            continue
        by_key[(organisation_key(organisation), date)] = {
            "score": score,
            "summary": summary,
            "references": references,
        }

    payload: dict[str, dict] = {}
    for component in group_components(items):
        ordered = identity.sort_items(component)
        if not ordered:
            continue
        llm_items = [item for item in ordered if item.Source_ID == "VEILLE_LLM"]
        if not llm_items:
            continue
        incident_id = identity.incident_id(
            ordered[0].Organisation_Key, ordered[0].Item_ID
        )
        matches = []
        for item in llm_items:
            key = (item.Organisation_Key, item.Event_Date or item.Published_Date)
            analysis = by_key.get(key)
            if analysis:
                matches.append(analysis)
        if matches:
            payload[incident_id] = max(
                matches,
                key=lambda value: (value["score"], value["summary"]),
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
    """Santé du dernier run, angles morts, veille et état de chaque source."""
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
                "latest_item_org": row.get("Latest_Item_Org", ""),
                "access_method": row.get("Access_Method", ""),
                "duration": row.get("Duration_s", ""),
                "comment": comment,
                # `or` plutôt que `.get(col, default)` : une ligne déjà
                # écrite avec la colonne présente mais vide (avant que ce
                # run ne calcule réellement History_Status) doit retomber
                # sur UNKNOWN au même titre qu'une colonne absente d'un
                # ancien run_sources.csv antérieur à ce chantier.
                "history_status": row.get("History_Status") or status.HISTORY_UNKNOWN,
                "oldest_available_date": row.get("Oldest_Available_Date") or "",
                "last_run": last_run.get("As_Of", ""),
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
            "calls": 0, "latest_item": "", "latest_item_org": "",
            "access_method": "", "duration": "", "comment": (
                meta.get("notes", "") if not meta.get("active") else "Source locale requise mais absente du dernier run."
            ),
            "history_status": status.HISTORY_UNKNOWN, "oldest_available_date": "",
            "last_run": last_run.get("As_Of", ""), "zero_is_trusted": False,
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
    facts = _source_facts_by_incident(items, store.load_source_facts())
    payload = incidents_payload(
        incidents,
        _local_analysis_by_incident(items),
        facts,
    )
    state = status_payload()

    store.write_json(store.SITE_DATA_DIR / "incidents.json", payload)
    store.write_json(store.SITE_DATA_DIR / "status.json", state)
    return len(payload), len(state["sources"])
