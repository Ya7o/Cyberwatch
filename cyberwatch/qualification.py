"""Phase canonique, offline et idempotente de qualification d'un snapshot."""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass, field
from . import (
    config,
    context_sector,
    enrichment,
    identity,
    incremental,
    org_enrichment,
    organisation_sector,
    qualification_policy,
    sector as sector_policy,
    sector_registry,
    sector_registry_safety,
    source_llm_fallback,
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
# Un export LLM peut fournir un candidat sourcé, jamais une confirmation.
_SECTOR_FALLBACK_AUTO_APPLY = False
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


def backfill_safe_name_sectors(items):
    changed = 0
    for item in items:
        if item.Sector != config.SECTOR_UNKNOWN:
            continue
        candidate = sector_policy.classify_sector_name(item.Organisation_Raw)
        if candidate == config.SECTOR_UNKNOWN:
            continue
        item.Sector = candidate
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


def neutralize_sector_fallback(items, changes, provenance):
    if _SECTOR_FALLBACK_AUTO_APPLY:
        return 0
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    neutralized = 0
    for row in provenance:
        if row.get("Origin") != "LLM_SOURCE_FALLBACK" or row.get("Field") != "Sector" or row.get("Decision") != "APPLIED":
            continue
        item = by_id.get(row.get("Item_ID", ""))
        applied = row.get("Final_Value", "")
        if item is None or not applied or item.Sector != applied:
            continue
        item.Sector = row.get("Previous_Value") or config.SECTOR_UNKNOWN
        row["Final_Value"], row["Confidence"], row["Decision"] = item.Sector, "", "REJECTED_NO_STRONG_EVIDENCE"
        neutralized += 1
    if neutralized:
        changes["llm_sector_fallback"] = max(0, changes.get("llm_sector_fallback", 0) - neutralized)
        changes["llm_sector_rejected"] = changes.get("llm_sector_rejected", 0) + neutralized
    changes["llm_sector_policy_rejected"] = neutralized
    provenance.sort(key=lambda row: (row["Item_ID"], row["Field"], row["Decision"]))
    return neutralized


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


def qualify(items):
    ordered = identity.sort_items(items)
    source_facts = store.read_csv(store.SOURCE_FACTS_CSV)
    org_cache = store.load_org_enrichment_cache()
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
        mutate=lambda: enrichment.enrich_items(ordered, reference),
    )
    changes["llm_sector_restored"], changes["sector_registry_restored"] = restored, registry_restored
    changes["organisation_sector_restored"] = org_sector_restored

    changes["sector_structured_source_backfill"] = _observe_layer(
        decisions,
        ordered,
        origin="STRUCTURED_SOURCE",
        confidence="HIGH",
        mutate=lambda: backfill_structured_source_sectors(ordered, source_facts),
    )
    context_applied, context_provenance, context_conflicts = context_sector.resolve_contextual_sectors(
        ordered, source_facts, org_cache
    )
    decisions.extend(decisions_from_provenance(context_provenance))
    changes["sector_context_applied"], changes["sector_context_conflicts"] = context_applied, context_conflicts

    official_applied, official_provenance = apply_official_subject_activity_sectors(ordered, org_cache)
    decisions.extend(decisions_from_provenance(official_provenance))
    changes["sector_official_subject_activity_applied"] = official_applied

    org_sector_decisions = organisation_sector.resolve_all_organisation_sectors(
        ordered,
        reference=reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        previous_provenance=previous_provenance,
    )
    org_sector_applied, org_sector_provenance = organisation_sector.apply_organisation_sector_decisions(
        ordered, org_sector_decisions
    )
    decisions.extend(decisions_from_provenance(org_sector_provenance))
    changes["organisation_sector_applied"] = org_sector_applied
    changes.update(organisation_sector.summary(org_sector_decisions))

    registry_rows = sector_registry.build_registry(
        ordered,
        reference,
        source_fact_rows=source_facts,
        org_cache_rows=org_cache,
        previous_provenance=previous_provenance,
    )
    sector_registry_safety.enforce_candidate_conflicts(registry_rows)
    registry_applied, registry_provenance, registry_known_conflicts = sector_registry.apply_registry(ordered, registry_rows)
    decisions.extend(decisions_from_provenance(registry_provenance))
    changes["sector_registry_applied"], changes["sector_registry_known_conflicts"] = registry_applied, registry_known_conflicts
    changes["sector_registry_auto_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_AUTO for row in registry_rows)
    changes["sector_registry_review_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_REVIEW for row in registry_rows)
    changes["sector_registry_conflict_orgs"] = sum(row.get("Decision") == sector_registry.DECISION_CONFLICT for row in registry_rows)
    changes["sector_safe_name_backfill"] = _observe_layer(
        decisions,
        ordered,
        origin="SAFE_NAME_RULE",
        confidence="HIGH",
        mutate=lambda: backfill_safe_name_sectors(ordered),
    )
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
    llm_changes, llm_provenance = source_llm_fallback.apply_source_llm_fallback(ordered)
    changes.update(llm_changes)
    neutralize_sector_fallback(ordered, changes, llm_provenance)
    decisions.extend(decisions_from_provenance(llm_provenance))
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
    )
