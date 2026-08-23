"""Façade de publication du dashboard.

L'implémentation historique reste dans :mod:`cyberwatch.site_legacy` afin de
préserver ses contrats et helpers éprouvés. Cette façade centralise désormais
la frontière de publication des faits : les analytics continuent de recevoir
les faits bruts par source, tandis que ``facts.json`` reçoit uniquement la vue
canonique résolue par :mod:`cyberwatch.fact_resolution`.
"""
from __future__ import annotations

from . import fact_resolution, site_legacy as _legacy

# Compatibilité stricte : les tests et outils internes utilisent plusieurs
# helpers privés de site.py. On les réexporte sans dupliquer leur code.
for _name in dir(_legacy):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_legacy, _name)


def build() -> tuple[int, int]:
    """Écrit le site avec faits bruts pour analytics et faits résolus pour l'UI."""
    incidents = store.load_incidents()
    items = store.load_items()
    raw_facts = _legacy._source_facts_by_incident(items, store.load_source_facts())
    tentative_sectors = _legacy._qualification_provenance_by_incident(
        items, store.load_qualification_provenance()
    )
    payload = _legacy.incidents_payload(
        incidents,
        _legacy._local_analysis_by_incident(items),
        raw_facts,
        tentative_sectors,
    )

    # Le résolveur utilise comme fallback la synthèse historique sélectionnée
    # de façon déterministe. Dès que des faits structurés suffisent, une
    # display_summary compacte et canonique la remplace.
    fallback_summaries = {
        incident_id: fact_resolution.best_publishable_summary(facts)
        for incident_id, facts in raw_facts.items()
    }
    resolved = fact_resolution.resolve_all(raw_facts, fallback_summaries)
    for row in payload:
        detail = resolved.get(str(row.get("id") or ""))
        # Le résolveur est l'unique contrat de carte : une abstention qualité
        # doit retirer une ancienne fiche structurée, jamais la laisser fuir.
        if detail is not None:
            row["summary"] = str(detail.get("display_summary") or "")

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

    store.write_json(store.SITE_DATA_DIR / "incidents.json", slim)
    store.write_json(store.SITE_DATA_DIR / "latest.json", _legacy._latest_payload(payload))
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
