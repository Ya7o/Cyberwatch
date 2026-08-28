"""Génération des données consommées par le dashboard GitHub Pages.

Le découpage suit la fréquence d'usage des parcours, pas la structure interne :

- `latest.json`    : les 30 derniers jours sans les faits détaillés (~90 Ko),
  seul fichier nécessaire à la consultation de veille, la plus fréquente ;
- `incidents.json` : tous les incidents sans les faits détaillés (~450 Ko),
  chargé en tâche de fond pour la recherche et l'analyse ;
- `facts.json`     : les faits par incident (~970 Ko), chargé uniquement à
  l'ouverture d'une fiche ;
- `status.json`    : santé du dernier run, angles morts, état de chaque source,
  et les analytics déterministes calculées ici (§Analytics) ;
- `reunion-mayotte.xml` : flux Atom du périmètre prioritaire, pour être alerté
  sans visiter le site.

Les agrégats de *signal* (tendances, signaux, indicateurs) sont calculés ici,
en Python, où ils sont testés et déterministes. Le navigateur ne recalcule que
le filtrage et les comptages de la sélection courante : deux implémentations
d'une même règle finiraient toujours par diverger.
"""

from __future__ import annotations

import json

from collections import defaultdict
from datetime import date, timedelta
from xml.sax.saxutils import escape as xml_escape

from . import analytics, config, identity, incident_identity, sources, status, store
from .dedup import group_components
from .model import Incident, Item
from .normalize import organisation_key
from .org_identity import effective_organisation_key


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
    "Initial_Access": "initial_access",
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
_SUMMARY_RICHNESS_KEYS = (
    "initial_access", "attack_flow", "impact", "threat_actor",
    "data_types", "vulnerabilities", "affected_count", "rich_facts",
)
_RICH_STATUSES = {"confirmed", "reported", "claimed", "hypothesis", "denied", "negated", "unknown"}
_RICH_UNITS = {"people", "accounts", "users", "clients", "records", "files"}
_RICH_VOLUME_UNITS = {"B", "KB", "MB", "GB", "TB", "PB"}
_RICH_CLAIM_TYPES = {
    "affected_count", "data_volume", "data_type", "system", "dataset", "initial_access",
    "attack_action", "impact", "remediation", "actor", "third_party", "vulnerability",
    "publication", "statement",
}


def _component_incident_id(ordered: list[Item]) -> str:
    """Reproduit exactement la politique d'identité de `dedup.build_incidents`."""
    component_key = effective_organisation_key(
        ordered[0].Organisation_Raw, ordered[0].Organisation_Key
    )
    incident_key = (
        ordered[0].Organisation_Key or component_key
        if len(ordered) == 1
        else component_key
    )
    return identity.incident_id(incident_key, ordered[0].Item_ID)


def _clean_rich_record(value: object, *, count: bool = False) -> dict | None:
    if not isinstance(value, dict):
        return None
    result: dict[str, object] = {}
    status_value = str(value.get("status") or "unknown").strip().lower()
    result["status"] = status_value if status_value in _RICH_STATUSES else "unknown"
    placeholders = {"null", "none", "unknown", "inconnu", "n/a", "na"}
    for key in ("type", "kind", "scope", "date", "actor", "subject", "relation", "object", "event", "evidence", "raw"):
        text = str(value.get(key) or "").strip()
        if text.casefold() in placeholders:
            continue
        if key == "type" and text not in _RICH_CLAIM_TYPES:
            continue
        if text:
            result[key] = text[:500]
    if count:
        try:
            result["value"] = int(value.get("value"))
        except (TypeError, ValueError):
            return None
        unit = str(value.get("unit") or "").strip().lower()
        if unit not in _RICH_UNITS:
            return None
        result["unit"] = unit
    else:
        text_value = str(value.get("value") or "").strip()
        if text_value.casefold() in placeholders:
            text_value = ""
        if text_value:
            result["value"] = text_value[:160]
        numeric = value.get("value")
        if not text_value and isinstance(numeric, (int, float)):
            result["value"] = int(numeric)
        unit = str(value.get("unit") or "").strip().lower()
        if unit in _RICH_UNITS or unit.upper() in _RICH_VOLUME_UNITS:
            result["unit"] = unit
    return result if len(result) > 1 else None


def _rich_facts_from_metadata(row: dict) -> dict | None:
    raw = str(row.get("Source_Metadata_JSON") or "").strip()
    if not raw:
        return None
    try:
        metadata = json.loads(raw)
    except (TypeError, ValueError):
        return None
    rich = metadata.get("rich_facts") if isinstance(metadata, dict) else None
    if not isinstance(rich, dict):
        return None

    payload: dict[str, object] = {"version": str(rich.get("version") or "1")}
    collections = (
        ("affected_counts", True),
        ("claims", False),
        ("affected_systems", False),
        ("affected_datasets", False),
        ("data_types", False),
        ("data_volumes", False),
        ("vulnerabilities", False),
        ("timeline", False),
        ("relations", False),
    )
    for key, is_count in collections:
        values = rich.get(key)
        if not isinstance(values, list):
            continue
        cleaned = []
        for value in values[:24]:
            record = _clean_rich_record(value, count=is_count)
            if record:
                cleaned.append(record)
        if cleaned:
            payload[key] = cleaned
    return payload if len(payload) > 1 else None


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

    # Le résolveur a besoin de la preuve du scalaire pour distinguer un
    # vecteur effectivement documenté d'une hypothèse ou d'un simple rappel
    # technique. La preuve reste bornée et ne remplace jamais la valeur.
    try:
        evidence_map = json.loads(str(row.get("Evidence_JSON") or "{}"))
    except (TypeError, ValueError):
        evidence_map = {}
    if isinstance(evidence_map, dict):
        for column, key in _FACT_TEXT_FIELDS.items():
            proof = evidence_map.get(column)
            if isinstance(proof, dict):
                proof = proof.get("text") or proof.get("evidence") or ""
            if isinstance(proof, list):
                proof = " ".join(str(value) for value in proof if value)
            proof_text = str(proof or "").strip()
            if proof_text and key in payload:
                payload[f"{key}_evidence"] = proof_text[:600]

    raw_flow = str(row.get("Attack_Flow_JSON") or "").strip()
    if raw_flow:
        try:
            flow = json.loads(raw_flow)
        except (TypeError, ValueError):
            flow = []
        if isinstance(flow, list):
            cleaned_flow = []
            for step in flow[:4]:
                if not isinstance(step, dict):
                    continue
                action = str(step.get("action") or "").strip()
                evidence = str(step.get("evidence") or "").strip()
                if action and evidence:
                    cleaned_flow.append({"action": action, "evidence": evidence})
            if cleaned_flow:
                payload["attack_flow"] = cleaned_flow

    rich_facts = _rich_facts_from_metadata(row)
    if rich_facts:
        payload["rich_facts"] = rich_facts
    try:
        metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
    except (TypeError, ValueError):
        metadata = {}
    tentative = metadata.get("threat_tentative") if isinstance(metadata, dict) else None
    if isinstance(tentative, dict) and str(tentative.get("value") or "").strip():
        payload["threat_tentative"] = {
            "value": str(tentative["value"]).strip(),
            "evidence": str(tentative.get("evidence") or "").strip()[:300],
            "confidence": tentative.get("confidence", ""),
        }

    return payload if len(payload) > 2 else None


def _components_with_stable_incident_ids(items: list[Item]) -> list[tuple[list[Item], str]]:
    from .incident_dedup import decision_map

    components = group_components(
        items,
        decision_map(store.load_incident_dedup_registry()),
    )
    assigned, _ = incident_identity.assign_incident_ids(
        components, store.load_incident_id_registry()
    )
    return list(zip(components, assigned))


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
    for component, incident_id in _components_with_stable_incident_ids(items):
        ordered = identity.sort_items(component)
        if not ordered:
            continue
        facts: list[dict] = []
        for item in ordered:
            facts.extend(by_item.get(item.Item_ID, []))
        if facts:
            facts.sort(key=lambda fact: (str(fact.get("source", "")), str(fact.get("item_id", ""))))
            payload[incident_id] = facts
    return payload


_TENTATIVE_SECTOR_DECISIONS = frozenset({
    "REJECTED_IDENTITY_EVIDENCE",
    "REJECTED_NO_STRONG_EVIDENCE",
    "REJECTED_NO_ACTIVITY_EVIDENCE",
})


def _qualification_provenance_by_incident(
    items: list[Item], provenance_rows: list[dict]
) -> dict[str, str]:
    """Secteur suggéré (rejeté faute de preuve suffisante), par incident.

    Liste blanche de raisons de rejet plutôt que liste noire : une raison
    inconnue reste par défaut non affichée. `REJECTED_SECTOR_CONFLICT` est
    délibérément exclu — ce n'est pas une preuve insuffisante mais une
    contradiction interne entre l'activité trouvée et le secteur déclaré par
    la même source. Un incident agrège plusieurs items ; si leurs candidats
    ne sont pas tous identiques, aucun secteur suggéré n'est retenu — jamais
    de désaccord affiché comme une suggestion unique.
    """
    candidates_by_item: dict[str, set[str]] = defaultdict(set)
    for row in provenance_rows:
        if row.get("Field") != "Sector" or row.get("Decision") not in _TENTATIVE_SECTOR_DECISIONS:
            continue
        candidate = str(row.get("Candidate_Value") or "").strip()
        item_id = str(row.get("Item_ID") or "").strip()
        if candidate and item_id:
            candidates_by_item[item_id].add(candidate)
    # Un item dont les propres candidats se contredisent ne contribue rien :
    # le désaccord n'est jamais réduit à une valeur choisie arbitrairement.
    by_item = {item_id: next(iter(values)) for item_id, values in candidates_by_item.items() if len(values) == 1}

    payload: dict[str, str] = {}
    for component, incident_id in _components_with_stable_incident_ids(items):
        candidates = {by_item[item.Item_ID] for item in component if item.Item_ID in by_item}
        if len(candidates) == 1:
            payload[incident_id] = next(iter(candidates))
    return payload


def _best_source_summary(facts: list[dict]) -> str:
    """Choisit sans LLM la synthèse de la source la mieux documentée.

    La richesse ne sert qu'à départager des synthèses déjà présentes ; aucune
    fusion ni réécriture n'est faite ici. Les critères de départage sont stables
    afin qu'un rebuild identique publie exactement la même synthèse.
    """
    candidates = [fact for fact in facts if str(fact.get("summary") or "").strip()]
    if not candidates:
        return ""

    def rank(fact: dict) -> tuple[int, str, str]:
        richness = sum(bool(fact.get(key)) for key in _SUMMARY_RICHNESS_KEYS)
        # `max` + ordre lexical rend l'égalité entièrement déterministe.
        return richness, str(fact.get("source", "")), str(fact.get("item_id", ""))

    selected = max(candidates, key=rank)
    return str(selected.get("summary") or "").strip()


def _source_links(incident: Incident) -> list[dict[str, str]]:
    """Associe chaque source à sa référence directe, sans homepage de repli."""
    hosts = {
        "CYBERATTAQUE_ORG": "cyberattaque.org",
        "FRENCHBREACHES": "frenchbreaches.com",
        "BONJOURLAFUITE": "bonjourlafuite.eu.org",
    }
    urls = [url for url in incident.Source_URLs.split(" | ") if url.startswith(("http://", "https://"))]
    used: set[str] = set()
    result = []
    for source in incident.Sources.split(" | "):
        expected = hosts.get(source, "")
        match = next((url for url in urls if url not in used and (not expected or expected in url)), "")
        if not match and source == "RANSOMWARE_LIVE":
            match = next((url for url in urls if url not in used and ".onion/" in url), "")
        if match:
            used.add(match)
            result.append({"source": source, "url": match})
    return result


def _source_link_status(incident: Incident, links: list[dict[str, str]]) -> list[dict[str, str]]:
    """Expose la raison d'absence d'un lien direct, sans inventer d'URL."""
    linked = {str(link.get("source") or "") for link in links}
    return [
        {
            "source": source,
            "status": "direct" if source in linked else "no_direct_url",
        }
        for source in incident.Sources.split(" | ")
        if source
    ]


def incidents_payload(
    incidents: list[Incident],
    local_analysis: dict[str, dict] | None = None,
    source_facts: dict[str, list[dict]] | None = None,
    tentative_sectors: dict[str, str] | None = None,
) -> list[dict]:
    """Incidents au format compact attendu par le dashboard."""
    local_analysis = local_analysis or {}
    source_facts = source_facts or {}
    tentative_sectors = tentative_sectors or {}
    payload = []
    for incident in incidents:
        source_links = _source_links(incident)
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
            "source_links": source_links,
            "source_link_status": _source_link_status(incident, source_links),
            "items": incident.Items_Count,
            "first_seen": incident.First_seen,
            "last_seen": incident.Last_seen,
        }
        if incident.Secteur == config.SECTOR_UNKNOWN:
            candidate = tentative_sectors.get(incident.Incident_ID)
            if candidate:
                row["sector_tentative"] = candidate
        analysis = local_analysis.get(incident.Incident_ID)
        if analysis:
            row["local"] = analysis
        facts = source_facts.get(incident.Incident_ID)
        if facts:
            row["facts"] = facts
            summary = _best_source_summary(facts)
            if summary:
                row["summary"] = summary
            if incident.Menace == config.THREAT_UNKNOWN:
                candidates = {
                    str(fact.get("threat_tentative", {}).get("value") or "").strip()
                    for fact in facts if isinstance(fact.get("threat_tentative"), dict)
                }
                if len(candidates) == 1 and next(iter(candidates)):
                    row["threat_tentative"] = next(iter(candidates))
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

    records = data.get("records") or []
    by_key: dict[tuple[str, str], dict] = {}
    for record in records:
        if not isinstance(record, dict):
            continue
        if str(record.get("admission") or "").strip().upper() != "ACCEPTED":
            continue
        try:
            score = int(record.get("score_cyberattaque"))
        except (TypeError, ValueError):
            continue
        # Le score reste une information affichable ; l'admission est décidée
        # en amont par le contrat de la routine et validée par le collecteur.
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
    for component, incident_id in _components_with_stable_incident_ids(items):
        ordered = identity.sort_items(component)
        if not ordered:
            continue
        llm_items = [item for item in ordered if item.Source_ID == "VEILLE_LLM"]
        if not llm_items:
            continue
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
                "sources": config.SOURCE_LABELS,
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
            "sources": config.SOURCE_LABELS,
        },
    }


def _to_int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


#: Fenêtre de la vue de veille. Assez large pour qu'un lecteur hebdomadaire
#: absent deux semaines ne rate rien, assez étroite pour rester légère.
LATEST_WINDOW_DAYS = 30

#: Un flux borné : au-delà, un lecteur de flux n'apporte plus rien.
FEED_MAX_ENTRIES = 50


def _without_facts(row: dict) -> dict:
    """Copie publiable sans les faits détaillés.

    Les faits représentent 86 % du poids du payload pour un contenu affiché
    seulement à l'ouverture d'une fiche ; `summary` et `local`, eux, sont lus
    dans les listes et restent donc ici.
    """
    return {key: value for key, value in row.items() if key != "facts"}


def _latest_payload(payload: list[dict]) -> list[dict]:
    days = [value for value in (_iso_day(row.get("date")) for row in payload) if value]
    if not days:
        return []
    cutoff = (max(days) - timedelta(days=LATEST_WINDOW_DAYS - 1)).isoformat()
    recent = [row for row in payload if str(row.get("date") or "") >= cutoff]
    recent.sort(key=lambda row: (str(row.get("date") or ""), str(row.get("id") or "")), reverse=True)
    return [_without_facts(row) for row in recent]


def _iso_day(value) -> date | None:
    try:
        return date.fromisoformat(str(value or "")[:10])
    except ValueError:
        return None


def _feed_timestamp(value: str, fallback: str) -> str:
    """Horodatage Atom, toujours dérivé des données — jamais de l'heure courante.

    Un flux regénéré sur les mêmes entrées doit être identique octet pour
    octet, sinon chaque run produirait une modification fantôme.
    """
    text = str(value or "").strip()
    if len(text) >= 20 and "T" in text:
        return text
    day = _iso_day(text) or _iso_day(fallback)
    return f"{day.isoformat()}T00:00:00Z" if day else "1970-01-01T00:00:00Z"


def _public_link(urls, fallback: str) -> str:
    """Première référence consultable publiquement.

    Les sites de revendication en `.onion` sont écartés : un lecteur de flux en
    ferait un lien cliquable vers l'infrastructure d'un groupe criminel. Le
    lien retombe alors sur le dashboard, où la référence reste consultable dans
    son contexte.
    """
    for url in (urls or []):
        text = str(url).strip()
        if not text.startswith(("http://", "https://")):
            continue
        host = text.split("/", 3)[2].lower() if text.count("/") >= 2 else ""
        if host.endswith(".onion"):
            continue
        return text
    return fallback


def focus_feed(payload: list[dict], *, as_of: str, site_url: str) -> str:
    """Flux Atom du périmètre prioritaire (Réunion / Mayotte).

    Sur un site statique, un flux est le seul mécanisme d'alerte réel : il
    prévient sans que l'utilisateur ait à venir vérifier. Le périmètre reprend
    `config.FOCUS_LOCATIONS`, jamais une liste écrite en dur ici.
    """
    focus = set(config.FOCUS_LOCATIONS)
    rows = [row for row in payload if str(row.get("location") or "") in focus]
    rows.sort(key=lambda row: (str(row.get("date") or ""), str(row.get("id") or "")), reverse=True)
    rows = rows[:FEED_MAX_ENTRIES]

    updated = _feed_timestamp(as_of, rows[0].get("date") if rows else "")
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<feed xmlns="http://www.w3.org/2005/Atom">',
        f"  <title>Cyberwatch — {xml_escape(' / '.join(config.FOCUS_LOCATIONS))}</title>",
        "  <subtitle>Incidents cyber publiquement documentés sur le périmètre prioritaire. "
        "Une absence signifie « aucun incident publiquement observé », jamais « aucun incident réel ».</subtitle>",
        f"  <id>{xml_escape(site_url)}#focus</id>",
        f'  <link rel="alternate" href="{xml_escape(site_url)}"/>',
        f"  <updated>{xml_escape(updated)}</updated>",
    ]
    for row in rows:
        incident_id = str(row.get("id") or "")
        title = f"{row.get('org') or 'Organisation inconnue'} — {row.get('threat') or 'Menace inconnue'}"
        detail = [
            f"{row.get('location') or 'Territoire inconnu'} · {row.get('date') or 'date inconnue'}",
            f"{len(row.get('sources') or [])} source(s) : {', '.join(row.get('sources') or []) or 'non documentée'}",
        ]
        detail[1] = f"{len(row.get('sources') or [])} source(s) : " + (
            ", ".join(config.source_label(value) for value in (row.get("sources") or [])) or "non documentée"
        )
        summary = str(row.get("summary") or "").strip()
        if summary:
            detail.append(summary)
        local = row.get("local") or {}
        if local.get("summary"):
            detail.append(f"Analyse locale (score {local.get('score')}/100) : {local['summary']}")
        link = _public_link(row.get("urls"), site_url)
        lines += [
            "  <entry>",
            f"    <title>{xml_escape(title)}</title>",
            f"    <id>{xml_escape(f'{site_url}#{incident_id}')}</id>",
            f'    <link rel="alternate" href="{xml_escape(link)}"/>',
            f"    <updated>{xml_escape(_feed_timestamp(row.get('last_seen'), row.get('date')))}</updated>",
            f"    <summary>{xml_escape(' — '.join(detail))}</summary>",
            "  </entry>",
        ]
    lines.append("</feed>")
    return "\n".join(lines) + "\n"


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

    # Les signaux sont calculés ici, sur le payload complet (faits compris pour
    # l'ampleur des fuites), et publiés. Le navigateur ne les recalcule pas.
    state["analytics"] = analytics.build_analytics(
        payload,
        focus_locations=config.FOCUS_LOCATIONS,
        ocean_locations=config.OCEAN_LOCATIONS,
    )

    slim = [_without_facts(row) for row in payload]
    detail = {row["id"]: row["facts"] for row in payload if row.get("facts")}

    store.write_json(store.SITE_DATA_DIR / "incidents.json", slim)
    store.write_json(store.SITE_DATA_DIR / "latest.json", _latest_payload(payload))
    store.write_json(store.SITE_DATA_DIR / "facts.json", detail)
    store.write_json(store.SITE_DATA_DIR / "status.json", state)
    (store.SITE_DATA_DIR / "reunion-mayotte.xml").write_text(
        focus_feed(payload, as_of=str(state.get("run", {}).get("as_of") or ""), site_url=config.SITE_URL),
        encoding="utf-8",
    )
    return len(payload), len(state["sources"])
