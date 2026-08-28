"""Phase canonique, offline et idempotente de qualification d'un snapshot."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from . import (
    config,
    enrichment,
    identity,
    incremental,
    org_enrichment,
    organisation_sector,
    organisation_sector_llm,
    qualification_policy,
    sector as sector_policy,
    sector_registry,
    sector_registry_safety,
    store,
)
from .dedup import build_incidents_with_registry
from .model import Incident, Item
from .qualification_decision import (
    QualificationDecision,
    decisions_from_provenance,
    record_mutations,
    snapshot_fields,
    summarize_decisions,
)
from .normalize import classify_threat, searchable
from .sector_fallback_migration import restore_legacy_sector_fallbacks

_AUTHORITATIVE_NATIVE_THREAT_SOURCES = frozenset({"VEILLE_LLM"})
_AUTHORITATIVE_DEFAULT_THREATS = {"RANSOMWARE_LIVE": config.THREAT_RANSOMWARE}
_SOURCE_SCOPE_THREATS = {
    "FRENCHBREACHES": config.THREAT_LEAK,
    "BONJOURLAFUITE": config.THREAT_LEAK,
}
_STRONG_SOURCE_SCOPE_OVERRIDES = frozenset({
    config.THREAT_RANSOMWARE,
    config.THREAT_DDOS,
    config.THREAT_MALWARE,
    config.THREAT_ACCOUNT,
    config.THREAT_LEAK,
    config.THREAT_PHISHING,
    config.THREAT_THIRD_PARTY,
})
PREQUAL_STATE_CSV = store.DATA_DIR / "prequalification_state.csv"


@dataclass(frozen=True)
class QualificationReport:
    items: list[Item]
    incidents: list[Incident]
    changes: dict[str, int]
    provenance: list[dict[str, str]]
    decisions: list[QualificationDecision]
    decision_summary: list[dict[str, object]]
    incident_id_registry: list[dict[str, str]]
    items_hash: str
    incidents_hash: str
    registry_rows: list[dict[str, str]] = field(default_factory=list)
    queue_rows: list[dict[str, str]] = field(default_factory=list)
    organisation_sector_decisions: dict[str, object] = field(default_factory=dict)
    organisation_sector_evidence: list[dict[str, str]] = field(default_factory=list)
    organisation_sector_llm_cache: list[dict[str, str]] = field(default_factory=list)


def stabilize_threats(items):
    changed = 0
    for item in items:
        before = item.Threat
        # Une fuite/exposition explicitement formulée dans le titre ou le
        # libellé source reste la menace principale. Un prestataire compromis
        # est alors un fait de contexte, jamais une catégorie qui l'écrase.
        explicit = classify_threat(item.Title, item.Threat_Raw)
        explicit_leak_words = ("fuite", "exposition de donnees", "donnees publiees", "donnees volees", "donnees exfiltrees")
        if explicit == config.THREAT_LEAK or any(word in searchable(f"{item.Title} {item.Threat_Raw}") for word in explicit_leak_words):
            item.Threat = config.THREAT_LEAK
            changed += item.Threat != before
            continue
        if item.Threat == config.THREAT_ACCOUNT:
            # Catégorie historique : un compte ou une messagerie compromis est
            # un vecteur, pas une menace principale.
            item.Threat = (
                config.THREAT_LEAK
                if item.Source_ID in _SOURCE_SCOPE_THREATS
                else config.THREAT_INTRUSION
            )
        elif item.Source_ID in _AUTHORITATIVE_NATIVE_THREAT_SOURCES:
            native = (item.Threat_Raw or "").strip()
            if native == config.THREAT_ACCOUNT:
                item.Threat = config.THREAT_INTRUSION
            elif native in config.THREATS:
                item.Threat = native
        elif item.Source_ID in _AUTHORITATIVE_DEFAULT_THREATS:
            item.Threat = _AUTHORITATIVE_DEFAULT_THREATS[item.Source_ID]
        elif item.Source_ID in _SOURCE_SCOPE_THREATS:
            scoped = _SOURCE_SCOPE_THREATS[item.Source_ID]
            if item.Threat not in _STRONG_SOURCE_SCOPE_OVERRIDES:
                item.Threat = scoped
        if item.Threat != before:
            changed += 1
    return changed


def backfill_structured_source_sectors(items, source_fact_rows=None):
    rows = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    raw_by_item = defaultdict(set)
    for row in rows:
        if row.get("Source_ID") == "RANSOMWARE_LIVE":
            raw = (row.get("Source_Sector_Raw") or "").strip()
            item_id = (row.get("Item_ID") or "").strip()
            if item_id and raw:
                raw_by_item[item_id].add(raw)
    changed = 0
    for item in items:
        if item.Source_ID != "RANSOMWARE_LIVE" or item.Sector != config.SECTOR_UNKNOWN:
            continue
        raw_values = raw_by_item.get(item.Item_ID, set())
        if len(raw_values) != 1:
            continue
        candidate = sector_policy.classify_source_sector(next(iter(raw_values)))
        if candidate != config.SECTOR_UNKNOWN:
            item.Sector = candidate
            changed += 1
    return changed


def apply_official_subject_activity_sectors(items, org_cache_rows=None):
    """Matérialise uniquement une preuve officielle forte et ré-validable.

    Le cache seul n'est pas une autorisation : le texte persistant doit encore
    satisfaire l'attribution au sujet et le seuil fort du classifieur de preuve.
    Cela permet à une preuve officielle nette d'écraser un hint structuré faible,
    sans promouvoir automatiquement les anciennes preuves officielles ambiguës.
    """
    from . import company_subject_evidence

    rows = org_cache_rows if org_cache_rows is not None else store.load_org_enrichment_cache()
    official = {}
    for row in rows:
        sector = (row.get("Validated_Sector") or "").strip()
        key = (row.get("Organisation_Key") or "").strip()
        if (
            key
            and row.get("Match_Status") == org_enrichment.MATCHED
            and row.get("Validated_Via") == "official_subject_activity"
            and sector in config.SECTORS
            and sector != config.SECTOR_UNKNOWN
        ):
            official[key] = row

    changed = 0
    provenance = []
    for item in items:
        row = official.get(item.Organisation_Key)
        if row is None:
            continue
        candidate = (row.get("Validated_Sector") or "").strip()
        activity = (row.get("Activity_Label") or "").strip()
        strong = company_subject_evidence.strong_subject_attributed_activity(
            item.Organisation_Raw,
            activity,
        )
        if strong is None or strong[0] != candidate:
            continue
        if item.Sector == candidate:
            continue
        previous = item.Sector
        item.Sector = candidate
        changed += 1
        evidence = " | ".join(
            value
            for value in (
                (row.get("Evidence_URL") or "").strip(),
                strong[1],
            )
            if value
        )[:2000]
        provenance.append({
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Field": "Sector",
            "Previous_Value": previous,
            "Candidate_Value": candidate,
            "Final_Value": candidate,
            "Origin": "OFFICIAL_SUBJECT_ACTIVITY",
            "Confidence": "HIGH",
            "Evidence": evidence,
            "Match_Strategy": "organisation_key_exact+strong_official_subject_activity",
            "Decision": "APPLIED",
        })
    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return changed, provenance


def _observe_layer(decisions, ordered, *, origin, confidence, mutate):
    before = snapshot_fields(ordered)
    result = mutate()
    decisions.extend(record_mutations(before, ordered, origin=origin, confidence=confidence))
    return result


def _capture_prequalification_state(ordered, source_facts, org_cache):
    facts_by_item = defaultdict(list)
    for row in source_facts:
        item_id = (row.get("Item_ID") or "").strip()
        if item_id:
            facts_by_item[item_id].append(row)
    dependency_digest_value = incremental.qualification_dependency_digest(
        store.ROOT,
        reference_rows=store.read_csv(store.ENRICHMENT_REFERENCE_CSV),
        org_cache_rows=org_cache,
    )
    previous = incremental.fingerprints_from_state(
        store.read_csv(PREQUAL_STATE_CSV), column="Prequalification_Fingerprint"
    )
    dirty_set = incremental.classify_prequalification_items(
        ordered,
        previous,
        facts_by_item=facts_by_item,
        policy_version=config.METHOD_ID,
        dependency_digest_value=dependency_digest_value,
    )
    incremental.write_prequalification_observation(
        dirty_set,
        policy_version=config.METHOD_ID,
        dependency_digest_value=dependency_digest_value,
    )


def qualify(
    items,
    *,
    source_fact_rows: list[dict] | None = None,
    org_cache_rows: list[dict] | None = None,
    domain_page_rows: list[dict] | None = None,
    allow_llm: bool = True,
    persist_llm_cache: bool = False,
):
    ordered = identity.sort_items(items)
    source_facts = source_fact_rows if source_fact_rows is not None else store.read_csv(store.SOURCE_FACTS_CSV)
    org_cache = org_cache_rows if org_cache_rows is not None else store.load_org_enrichment_cache()
    _capture_prequalification_state(ordered, source_facts, org_cache)
    previous_provenance = store.load_qualification_provenance()
    decisions = []
    restored = restore_legacy_sector_fallbacks(ordered, previous_provenance)
    registry_restored = sector_registry.restore_registry_applications(ordered, previous_provenance)
    org_sector_restored = organisation_sector.restore_organisation_sector_applications(ordered, previous_provenance)
    reference = enrichment.load_reference()
    changes = _observe_layer(
        decisions,
        ordered,
        origin="MANUAL_REFERENCE",
        confidence="HIGH",
        mutate=lambda: enrichment.enrich_items(ordered, reference, include_sector=False),
    )
    changes["llm_sector_restored"], changes["sector_registry_restored"] = restored, registry_restored
    changes["organisation_sector_restored"] = org_sector_restored

    # Refonte 2026-08-26 ("preuves partout, décision unique à la fin") :
    # backfill_structured_source_sectors, context_sector.resolve_contextual_sectors,
    # apply_official_subject_activity_sectors et backfill_safe_name_sectors ne
    # sont plus appelés ici — chacun appliquait directement Item.Sector en
    # concurrence avec organisation_sector.py, qui collecte déjà la même
    # preuve (structured_source/source_activity/official_subject_activity/
    # safe_name) de façon indépendante. Le premier qui s'exécutait gagnait
    # selon l'ordre du code, pas selon le mérite de la preuve (cas réel :
    # Klark AI classé "Services aux entreprises" par un mécanisme d'ingestion
    # séparé avant que ce module n'ait pu arbitrer). Les deux autorités
    # (référence humaine et NAF officiel validé) sont elles aussi appliquées
    # ici par le même résolveur, jamais pendant l'ingestion.

    org_sector_decisions = organisation_sector.resolve_all_organisation_sectors(
        ordered,
        reference=reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        domain_page_rows=domain_page_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=[],
    )
    org_sector_applied, org_sector_provenance = organisation_sector.apply_organisation_sector_decisions(
        ordered, org_sector_decisions
    )
    decisions.extend(decisions_from_provenance(org_sector_provenance))
    changes["organisation_sector_applied"] = org_sector_applied

    # Étape finale obligatoire : toute organisation qu'aucune des deux
    # autorités (référence manuelle, NAF précis) n'a résolue passe par le LLM
    # organisationnel, qui voit l'ensemble des preuves faibles déjà
    # collectées (structured_source, safe_name, official_subject_activity,
    # source_activity, domain_page, official_site) plutôt qu'un arbitrage
    # déterministe entre elles. Non bloquant : budget épuisé ou erreur API ->
    # l'organisation reste Inconnu, jamais d'échec de run.
    llm_report = organisation_sector_llm.enrich_unknown_organisation_sectors(
        ordered,
        reference=reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        domain_page_rows=domain_page_rows,
        previous_provenance=previous_provenance,
        no_llm=not allow_llm,
        persist=persist_llm_cache,
    )
    changes["organisation_sector_llm_selected"] = llm_report.organisations_selected
    changes["organisation_sector_llm_calls"] = llm_report.calls
    changes["organisation_sector_llm_candidates"] = llm_report.candidates
    changes["organisation_sector_llm_abstentions"] = llm_report.abstentions

    org_sector_decisions = organisation_sector.resolve_all_organisation_sectors(
        ordered,
        reference=reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        domain_page_rows=domain_page_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=llm_report.cache_rows,
    )
    org_sector_llm_applied, org_sector_llm_provenance = organisation_sector.apply_organisation_sector_decisions(
        ordered, org_sector_decisions
    )
    decisions.extend(decisions_from_provenance(org_sector_llm_provenance))
    changes["organisation_sector_applied"] += org_sector_llm_applied
    changes.update(organisation_sector.summary(org_sector_decisions))

    final_evidence_by_org = organisation_sector.collect_organisation_evidence(
        ordered,
        reference=reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        domain_page_rows=domain_page_rows,
        previous_provenance=previous_provenance,
        llm_cache_rows=llm_report.cache_rows,
    )
    org_sector_evidence = organisation_sector.evidence_audit_rows(
        ordered,
        final_evidence_by_org,
        org_cache_rows=org_cache,
        domain_page_rows=domain_page_rows,
        llm_outcomes=llm_report.outcomes,
    )

    registry_rows = sector_registry.build_registry(
        ordered,
        reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        previous_provenance=previous_provenance,
    )
    sector_registry_safety.enforce_candidate_conflicts(registry_rows)
    # apply_registry (auto-application) est retiré : 0 application réelle
    # constatée, entièrement supplanté par organisation_sector.py + le LLM
    # final ci-dessus. build_registry/build_enrichment_queue restent pour
    # alimenter la file de revue humaine (site.py lit sector_enrichment_queue.csv).
    changes["sector_registry_auto_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_AUTO for row in registry_rows)
    changes["sector_registry_review_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_REVIEW for row in registry_rows)
    changes["sector_registry_conflict_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_CONFLICT for row in registry_rows)
    changes.update(
        _observe_layer(
            decisions,
            ordered,
            origin="OFFLINE_BACKFILL",
            confidence="MEDIUM",
            mutate=lambda: enrichment.backfill_unknowns(ordered, reference),
        )
    )
    changes["threat_stabilized"] = _observe_layer(
        decisions,
        ordered,
        origin="THREAT_STABILIZATION",
        confidence="HIGH",
        mutate=lambda: stabilize_threats(ordered),
    )
    decisions = qualification_policy.reconcile(ordered, decisions)
    provenance = [decision.to_row() for decision in decisions]
    incidents, incident_id_registry = build_incidents_with_registry(
        ordered, store.load_incident_id_registry()
    )
    queue_rows = sector_registry.build_enrichment_queue(
        ordered,
        registry_rows,
        source_fact_rows=source_facts,
        challenger_provenance=previous_provenance,
    )
    return QualificationReport(
        ordered,
        incidents,
        changes,
        provenance,
        decisions,
        summarize_decisions(decisions),
        incident_id_registry,
        identity.items_hash(ordered),
        identity.incidents_hash(incidents),
        registry_rows,
        queue_rows,
        org_sector_decisions,
        org_sector_evidence,
        llm_report.cache_rows,
    )
