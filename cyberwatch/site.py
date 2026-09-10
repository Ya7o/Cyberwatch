"""Façade de publication du dashboard.

L'implémentation historique reste dans :mod:`cyberwatch.site_legacy` afin de
préserver ses contrats et helpers éprouvés. Cette façade centralise désormais
la frontière de publication des faits : les analytics continuent de recevoir
les faits bruts par source, tandis que ``facts.json`` reçoit uniquement la vue
canonique résolue par :mod:`cyberwatch.fact_resolution`.
"""
from __future__ import annotations

from . import (
    analytics,
    config,
    data_sensitivity,
    fact_resolution,
    org_identity,
    sector_resolution,
    site_legacy as _legacy,
    site_window,
    store,
    threat_resolution,
)
from .normalize import organisation_key

def _sensitive_types(detail: dict) -> list[str]:
    return list(data_sensitivity.classify(detail)["sensitive_data_types"])


def _sector_status(row: dict, decisions: dict[str, list[dict]] | None = None) -> dict:
    """Expose la preuve ou le niveau d'inférence du secteur publié."""
    candidates = (decisions or {}).get(str(row.get("id") or ""),
                 (decisions or {}).get(organisation_key(row.get("org", "")), []))
    if row.get("sector") != config.SECTOR_UNKNOWN:
        matching = [
            decision for decision in candidates
            if decision.get("Resolved_Sector") == row.get("sector")
        ]
        if matching:
            priority = {"confirmed": 4, "reported": 3, "referenced": 2, "inferred": 1, "inferred_low": 0}
            decision = max(
                matching,
                key=lambda value: (
                    priority.get(str(value.get("Status") or ""), -1),
                    float(value.get("Confidence") or 0),
                ),
            )
            result = {
                "status": decision.get("Status") or "inferred",
                "reason": decision.get("Reason") or "",
                "confidence": float(decision.get("Confidence") or 0),
                "evidence": decision.get("Evidence") or "",
            }
            if decision.get("Evidence_URL"):
                result["evidence_url"] = decision["Evidence_URL"]
            discarded = sorted({d.get("Resolved_Sector") for d in candidates
                                if d.get("Resolved_Sector") not in (None, "", config.SECTOR_UNKNOWN, row.get("sector"))})
            if discarded:
                result["reason"] = "ACTIVITY_OVERRIDES_SOURCE_LABEL"
                result["discarded_source_labels"] = discarded
            return result
        return {"status": "reported", "reason": "LEGACY_KNOWN_SECTOR"}
    sectors = {d.get("Resolved_Sector") for d in candidates
               if d.get("Resolved_Sector") not in (None, "", config.SECTOR_UNKNOWN)}
    if len(sectors) > 1:
        return {"status": "unknown", "reason": "SOURCE_SECTOR_CONFLICT",
                "evidence": " | ".join(sorted(sectors))}
    reasons = sorted({str(d.get("Reason")) for d in candidates if d.get("Reason")})
    return {"status": "unknown", "reason": " | ".join(reasons) or "NO_ACTIVITY_EVIDENCE"}

# Compatibilité stricte : les tests et outils internes utilisent plusieurs
# helpers privés de site.py. On les réexporte sans dupliquer leur code.
for _name in dir(_legacy):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_legacy, _name)


def _sector_decisions_by_organisation() -> dict[str, list[dict]]:
    decisions: dict[str, list[dict]] = {}
    for sector_decision in store.load_sector_resolution():
        decisions.setdefault(
            str(sector_decision.get("Organisation_Key") or ""), []
        ).append(sector_decision)
    return decisions


def _sector_decisions_by_incident(items: list) -> dict[str, list[dict]]:
    rows = {row.get("Item_ID"): row for row in store.load_sector_resolution()}
    return {incident_id: [rows[item.Item_ID] for item in component if item.Item_ID in rows]
            for component, incident_id in _legacy._components_with_stable_incident_ids(items)}


def _threat_decisions_by_incident(items: list, source_fact_rows: list[dict]) -> dict:
    facts_by_item = threat_resolution.index_source_facts(source_fact_rows)
    return {
        incident_id: threat_resolution.resolve_component(component, facts_by_item)
        for component, incident_id in _legacy._components_with_stable_incident_ids(items)
    }


def _resolved_details(payload: list[dict], raw_facts: dict[str, list[dict]]) -> dict:
    organisations = {
        str(row.get("id") or ""): str(row.get("org") or "")
        for row in payload
    }
    fallback_summaries = {
        incident_id: fact_resolution.best_publishable_summary(
            facts, organisation=organisations.get(incident_id, "")
        )
        for incident_id, facts in raw_facts.items()
    }
    return fact_resolution.resolve_all(raw_facts, fallback_summaries, organisations)


def _decorate_payload(
    payload: list[dict], resolved: dict, threat_decisions: dict,
    sectors: dict | None = None,
) -> None:
    sectors = sectors if sectors is not None else {}
    for row in payload:
        row["sector_status"] = _sector_status(row, sectors)
        threat_decision = threat_decisions.get(str(row.get("id") or ""))
        if threat_decision:
            row["threat_status"] = threat_decision.to_payload()
        detail = resolved.get(str(row.get("id") or ""))
        if detail is None:
            continue
        row["summary"] = str(detail.get("display_summary") or "")
        exposure = data_sensitivity.classify(detail)
        row.update({
            key: exposure[key]
            for key in (
                "personal_data_exposed",
                "high_sensitivity_data_exposed",
                "credentials_or_secrets_exposed",
                "vulnerable_people_data_exposed",
                "sensitive_data_exposed",
                "sensitive_data_types",
            )
        })
        row["data_exposure"] = exposure
        quality_alerts = list(detail.get("quality_alerts") or [])
        quality_alerts.extend(data_sensitivity.consistency_alerts(exposure))
        if threat_decision and threat_decision.conflict:
            unresolved = threat_decision.value == config.THREAT_UNKNOWN
            quality_alerts.append({
                "code": "THREAT_CONFLICT" if unresolved else "THREAT_CONFLICT_RESOLVED",
                "field": "threat",
                "severity": "error" if unresolved else "info",
            })
        row["quality_alerts"] = quality_alerts


def build() -> tuple[int, int]:
    """Écrit le site avec faits bruts pour analytics et faits résolus pour l'UI."""
    # `maj` persiste éventuellement de nouveaux alias juste avant d'appeler le
    # build dans le même processus. Toujours relire le registre sur disque évite
    # que les JSON publics soient construits avec l'ancien état en mémoire.
    org_identity.reload_organisation_identity_registry(
        store.ORGANISATION_IDENTITY_REGISTRY_CSV
    )
    incidents = store.load_incidents()
    items = store.load_items()
    source_fact_rows = store.load_source_facts()
    from . import enrichment
    gaps = sector_resolution.fact_transport_gaps(items, source_fact_rows, enrichment.load_reference())
    gaps.extend(sector_resolution.transport_gaps(items, store.load_sector_resolution()))
    if gaps:
        raise ValueError("sector_publication_transport_gap: " + ", ".join(sorted(set(gaps))))
    raw_facts = _legacy._source_facts_by_incident(items, source_fact_rows)
    payload = _legacy.incidents_payload(
        incidents,
        _legacy._local_analysis_by_incident(items),
        raw_facts,
        {},
    )
    threat_decisions = _threat_decisions_by_incident(items, source_fact_rows)
    resolved = _resolved_details(payload, raw_facts)
    sectors = _sector_decisions_by_incident(items)
    for row in payload:
        decisions = sectors.get(str(row.get("id") or ""), [])
        expected = sector_resolution.component_sector_rows(decisions)
        if decisions and row.get("sector") != expected:
            raise ValueError("sector_incident_projection_gap: " + str(row.get("id")))
    _decorate_payload(payload, resolved, threat_decisions, sectors)

    state = _legacy.status_payload()

    # Important : les analytics gardent les faits bruts attachés au payload.
    # Les métriques existantes ne changent donc pas de sémantique du seul fait
    # que le dashboard reçoit un JSON plus compact.
    state["analytics"] = analytics.build_analytics(
        payload,
        focus_locations=config.FOCUS_LOCATIONS,
        ocean_locations=config.OCEAN_LOCATIONS,
    )

    slim = [_legacy._without_facts(row) for row in payload]
    latest = site_window.latest_rows(
        payload,
        state.get("run", {}).get("as_of", ""),
        window_days=getattr(_legacy, "LATEST_WINDOW_DAYS", 30),
    )

    store.write_json(store.SITE_DATA_DIR / "incidents.json", slim)
    store.write_json(
        store.SITE_DATA_DIR / "latest.json",
        [_legacy._without_facts(row) for row in latest],
    )
    store.write_json(store.SITE_DATA_DIR / "facts.json", resolved)
    store.write_json(store.SITE_DATA_DIR / "status.json", state)
    (store.SITE_DATA_DIR / "reunion-mayotte.xml").write_text(
        _legacy.focus_feed(
            payload,
            as_of=str(state.get("run", {}).get("as_of") or ""),
            site_url=config.SITE_URL,
        ),
        encoding="utf-8",
    )
    return len(payload), len(state["sources"])
