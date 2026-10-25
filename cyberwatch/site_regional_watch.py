"""Qualification et suivi régional publiés depuis les faits collectés."""
from __future__ import annotations

import json
from pathlib import Path

from . import config, store


def qualification(row: dict) -> dict:
    if row.get("Source_ID") != "VEILLE_LLM":
        return {}
    try:
        metadata = json.loads(str(row.get("Source_Metadata_JSON") or "{}"))
    except (TypeError, ValueError):
        return {}
    if not isinstance(metadata, dict):
        return {}
    result: dict[str, object] = {
        key: str(metadata.get(key) or "").strip()
        for key in (
            "admission_reason", "statut", "score_definition", "localisation",
            "impact_connu", "acteur",
        )
        if str(metadata.get(key) or "").strip()
    }
    score = metadata.get("score_cyberattaque")
    if isinstance(score, int) and not isinstance(score, bool) and 0 <= score <= 100:
        result["score"] = score
    return result


def decorate_details(resolved: dict, raw_facts: dict[str, list[dict]]) -> None:
    for incident_id, detail in resolved.items():
        qualifications = [fact["regional_watch"] for fact in raw_facts.get(incident_id, [])
                          if fact.get("regional_watch")]
        if qualifications:
            detail["regional_watch"] = qualifications


def decorate_case_links(resolved: dict, payload: list[dict], items: list) -> None:
    """Lie seulement les suivis régionaux explicitement sourcés et curatés.

    Ces liens n'altèrent pas la déduplication : deux publications éloignées
    restent deux incidents jusqu'à preuve d'un même événement technique.
    """
    path = Path(store.ROOT) / "data" / "regional_case_links.json"
    if not path.is_file():
        return
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("version") != 1 or not isinstance(data.get("links"), list):
        raise ValueError("Registre des suivis régionaux invalide")

    from . import site_legacy

    incident_by_item = {
        item.Item_ID: incident_id
        for component, incident_id in site_legacy._components_with_stable_incident_ids(items)
        for item in component
    }
    by_id = {str(row.get("id") or ""): row for row in payload}
    for link in data["links"]:
        if not isinstance(link, dict):
            raise ValueError("Lien de suivi régional invalide")
        follow_up_id = incident_by_item.get(str(link.get("follow_up_item_id") or ""))
        case_id = incident_by_item.get(str(link.get("case_item_id") or ""))
        # Une purge ou une correction de déduplication peut retirer l'un des
        # dossiers : un lien devenu inactif ne bloque pas la publication.
        if not follow_up_id or not case_id or follow_up_id == case_id:
            continue
        follow_up, case = by_id[follow_up_id], by_id[case_id]
        if (follow_up.get("location") not in config.FOCUS_LOCATIONS
                or case.get("location") not in config.FOCUS_LOCATIONS):
            raise ValueError("Lien de suivi hors Réunion/Mayotte")
        note = str(link.get("note") or "").strip()
        evidence = link.get("evidence_urls")
        if not note or not isinstance(evidence, list) or not evidence or not all(
            isinstance(url, str) and url.startswith("https://") for url in evidence
        ):
            raise ValueError("Lien de suivi régional sans note ou preuve HTTPS")
        follow_up_detail = resolved[follow_up_id]
        if not follow_up_detail.get("summary_paragraphs"):
            follow_up_detail["summary_paragraphs"] = [note]
        for incident_id, related in ((follow_up_id, case), (case_id, follow_up)):
            resolved[incident_id].setdefault("related_cases", []).append({
                "id": related["id"],
                "org": related["org"],
                "date": related["date"],
                "note": note,
                "evidence_urls": evidence,
            })
