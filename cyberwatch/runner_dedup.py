"""Application des décisions du filet de déduplication quotidien."""

from __future__ import annotations

from . import dedup, dedup_ai, dedup_review, duplicate_audit, incident_dedup, org_identity
from .model import Item


def _fact_indexes(source_fact_rows: list[dict]) -> tuple[dict[str, dict], dict[str, str]]:
    facts_by_item: dict[str, dict] = {}
    victim_websites: dict[str, str] = {}
    for row in source_fact_rows:
        item_id = (row.get("Item_ID") or "").strip()
        if not item_id:
            continue
        facts_by_item[item_id] = row
        website = (row.get("Victim_Website") or "").strip()
        if website:
            victim_websites[item_id] = website
    return facts_by_item, victim_websites


def _validated_proposals(
    candidates: list,
    decisions: dict,
    state: dedup_ai.DedupAiRunState,
) -> tuple[list[dict], list[dict]]:
    candidates_by_id = {dedup_ai.candidate_id(candidate): candidate for candidate in candidates}
    organisation_proposals: list[dict] = []
    incident_proposals: list[dict] = []
    for pair_key, decision in decisions.items():
        candidate = candidates_by_id.get(pair_key)
        if candidate is None:
            continue
        cached_row = state.rows_by_pair.get(pair_key, {})
        input_hash = cached_row.get("Input_Hash", "")
        proposal = dedup_ai.validate_ai_dedup_decision(
            candidate, decision, model=cached_row.get("Model") or state.model, input_hash=input_hash
        )
        if proposal is not None:
            organisation_proposals.append(proposal)
        incident_proposal = dedup_ai.validate_ai_incident_decision(
            candidate, decision, model=cached_row.get("Model") or state.model, input_hash=input_hash
        )
        if incident_proposal is not None:
            incident_proposals.append(incident_proposal)
    return organisation_proposals, incident_proposals


def apply_daily_decisions(
    state: dedup_ai.DedupAiRunState,
    items: list[Item],
    new_or_updated_items: list[Item],
    source_fact_rows: list[dict],
) -> list[str]:
    """Challenge, valide puis fusionne les propositions sans persister."""
    company_ids: dict[str, str] = {}
    facts_by_item, victim_websites = _fact_indexes(source_fact_rows)
    state.pending_rows = dedup_review.reconcile(
        state.pending_rows,
        items,
        incident_dedup.decision_map(state.incident_dedup_rows),
    )
    deferred: list[duplicate_audit.DedupAuditCandidate] = []
    candidates = duplicate_audit.find_daily_llm_candidates(
        new_or_updated_items,
        items,
        company_ids=company_ids,
        victim_websites=victim_websites,
        deferred=deferred,
    )
    candidate_map = {dedup_ai.candidate_id(c): c for c in candidates}
    for candidate in dedup_review.retry_candidates(state.pending_rows, items, limit=state.daily_max_candidates):
        candidate_map.setdefault(dedup_ai.candidate_id(candidate), candidate)
    candidates = list(candidate_map.values())
    pending = {row["pair_key"]: row for row in state.pending_rows
               if row.get("left") in {i.Item_ID for i in items} and row.get("right") in {i.Item_ID for i in items}}
    for candidate in deferred:
        key = dedup_ai.candidate_id(candidate)
        if key not in candidate_map:
            pending.setdefault(key, {"pair_key": key, "left": candidate.left.Item_ID,
                                    "right": candidate.right.Item_ID, "status": "TOP_K_DEFERRED",
                                    "attempts": 0, "first_seen": state.run_id})
    state.pending_rows = list(pending.values())
    decisions = dedup_ai.challenge_candidates_batch(
        candidates, facts_by_item, state, company_ids
    )
    organisation_proposals, incident_proposals = _validated_proposals(
        candidates, decisions, state
    )

    existing_rows = state.organisation_identity_rows
    merged_rows, organisation_problems = org_identity.merge_organisation_identity_rows(
        existing_rows, organisation_proposals
    )
    existing_incident_rows = state.incident_dedup_rows
    merged_incident_rows, incident_problems = incident_dedup.merge_rows(
        existing_incident_rows,
        incident_proposals,
        current_item_ids={item.Item_ID for item in items if item.Item_ID},
    )
    problems = [*organisation_problems, *incident_problems]
    if problems:
        return problems

    existing_aliases = {
        row.get("Alias_Key", "")
        for row in existing_rows
        if row.get("Decision") == org_identity.DECISION_SAME
    }
    merged_aliases = {
        row.get("Alias_Key", "")
        for row in merged_rows
        if row.get("Decision") == org_identity.DECISION_SAME
    }
    previous_incidents = {
        row.get("Pair_Key", ""): row for row in existing_incident_rows
    }
    state.organisation_identity_rows_applied = len(merged_aliases - existing_aliases)
    state.incident_decision_rows_applied = sum(
        previous_incidents.get(row["Pair_Key"]) != row for row in merged_incident_rows
    )
    state.organisation_identity_rows = merged_rows
    state.incident_dedup_rows = merged_incident_rows
    previous = org_identity.ORGANISATION_IDENTITY_REGISTRY
    try:
        org_identity.ORGANISATION_IDENTITY_REGISTRY = {
            row["Alias_Key"]: row["Canonical_Key"] for row in merged_rows
            if row.get("Decision") == org_identity.DECISION_SAME}
        applied_decisions = incident_dedup.decision_map(merged_incident_rows)
        grouped = {item.Item_ID: n for n, component in enumerate(dedup.group_components(
            items, applied_decisions)) for item in component}
        dedup_review.outcomes(
            state,
            candidates,
            decisions,
            incident_proposals,
            grouped,
            items=items,
            incident_decisions=applied_decisions,
        )
    finally:
        org_identity.ORGANISATION_IDENTITY_REGISTRY = previous
    return []
