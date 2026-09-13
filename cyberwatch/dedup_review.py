"""Persistent, bounded retries and per-pair outcomes for the daily dedup net."""
from __future__ import annotations

import json
from pathlib import Path

from . import dedup, dedup_ai, duplicate_audit

AUTO_RETRY = {"DISABLED", "BUDGET_BLOCKED", "ERROR", "NOT_REVIEWED_CAPACITY", "TOP_K_DEFERRED"}
TERMINAL_STATUSES = {"APPLIED", "DIFFERENT", "UNKNOWN_SEPARATE"}
MAX_ERROR_ATTEMPTS = 3


def load(path: Path) -> list[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("Invalid dedup review queue")
    return value


def retry_candidates(
    rows: list[dict], items: list, *, limit: int = 40,
    facts_by_item: dict[str, dict] | None = None,
    victim_websites: dict[str, str] | None = None,
) -> list:
    by_id = {item.Item_ID: item for item in items}
    result = []
    for row in sorted(rows, key=lambda r: (r.get("attempts", 0), r.get("first_seen", ""), r.get("pair_key", ""))):
        status = row.get("status")
        if status not in AUTO_RETRY:
            continue
        if status == "ERROR" and int(row.get("attempts", 0) or 0) >= MAX_ERROR_ATTEMPTS:
            continue
        a, b = by_id.get(row.get("left")), by_id.get(row.get("right"))
        if a is None or b is None:
            continue
        result.extend(duplicate_audit.find_daily_llm_candidates(
            [a], [a, b], max_candidates_per_item=1,
            facts_by_item=facts_by_item, victim_websites=victim_websites,
        ))
        if len(result) >= limit:
            break
    return result


def requires_review(candidate, decision) -> bool:
    """Signale une abstention à forte valeur sans la transformer en décision."""
    if decision.status not in {dedup_ai.STATUS_OK, dedup_ai.STATUS_CACHE_HIT}:
        return False
    if (
        decision.same_organisation != dedup_ai.UNKNOWN
        and decision.same_incident != dedup_ai.UNKNOWN
    ):
        return False
    signals = candidate.signals
    if signals is None or signals.publication_days_apart not in {0, 1, 2}:
        return False
    strong_identity = (
        signals.organisation_exact
        or signals.organisation_similarity >= 0.95
        or signals.shared_company_id
        or signals.shared_victim_domain
    )
    corroborated_event = any((
        signals.event_date_match == "MATCH",
        signals.threat_match == "MATCH",
        signals.threat_actor_match == "MATCH",
        signals.affected_count_match == "MATCH",
        signals.data_type_match == "MATCH",
    ))
    conflicts = any((
        signals.event_date_match == "CONFLICT",
        signals.threat_match == "CONFLICT",
        signals.threat_actor_match == "CONFLICT",
        signals.affected_count_match == "CONFLICT",
        signals.source_native_id_match == "CONFLICT",
    ))
    deterministic = dedup.decide_merge(candidate.left, candidate.right)
    veto = deterministic.reason_code in dedup.STRONG_KEEP_REASON_CODES
    return strong_identity and corroborated_event and not conflicts and not veto


def reconcile(
    rows: list[dict],
    items: list,
    incident_decisions: dict[str, str],
) -> list[dict]:
    """Retire les attentes résolues et qualifie les reprises épuisées."""
    by_id = {item.Item_ID: item for item in items if item.Item_ID}
    components = dedup.group_components(items, incident_decisions)
    grouped = {item.Item_ID: index for index, component in enumerate(components) for item in component}
    result: list[dict] = []
    for raw in rows:
        row = dict(raw)
        left, right = row.get("left", ""), row.get("right", "")
        if left not in by_id or right not in by_id or left == right:
            continue
        if row.get("status") in TERMINAL_STATUSES:
            continue
        if grouped.get(left) == grouped.get(right):
            continue
        attempts = int(row.get("attempts", 0) or 0)
        if row.get("status") == "ERROR" and attempts >= MAX_ERROR_ATTEMPTS:
            row["status"] = "RETRY_EXHAUSTED"
        if row.get("status") == "SAME_NOT_GROUPED":
            row["blocked_reason"] = dedup.separation_reason(
                items, left, right, incident_decisions
            )
        result.append(row)
    return sorted(result, key=lambda row: (
        row.get("first_seen", ""), row.get("pair_key", "")
    ))


def outcomes(
    state,
    candidates: list,
    decisions: dict,
    accepted: list[dict],
    grouped: dict,
    *,
    items: list | None = None,
    incident_decisions: dict[str, str] | None = None,
) -> None:
    pending = {row["pair_key"]: row for row in state.pending_rows}
    accepted_by_id = {row["Pair_Key"]: row for row in accepted}
    for candidate in candidates:
        key = dedup_ai.candidate_id(candidate)
        decision = decisions.get(key, dedup_ai.DedupAiDecision(status="NOT_REVIEWED_CAPACITY"))
        previous = pending.get(key, {})
        reviewed = decision.status in {dedup_ai.STATUS_OK, dedup_ai.STATUS_CACHE_HIT}
        state.reviewed_count += int(reviewed)
        status = decision.status
        if reviewed:
            if key not in accepted_by_id:
                status = "UNKNOWN" if decision.same_incident == dedup_ai.UNKNOWN else "VALIDATION_REJECTED"
                if (
                    decision.same_organisation == dedup_ai.DIFFERENT
                    and decision.confidence >= dedup_ai.DIFFERENT_CONFIDENCE_THRESHOLD
                ):
                    status = "DIFFERENT"
            elif decision.same_incident == dedup_ai.DIFFERENT:
                status = "DIFFERENT"
            else:
                same_group = (candidate.left.Item_ID in grouped and
                              grouped.get(candidate.left.Item_ID) == grouped.get(candidate.right.Item_ID))
                status = "APPLIED" if same_group else "SAME_NOT_GROUPED"
                state.incident_pairs_resolved += int(same_group)
        review_required = requires_review(candidate, decision)
        if review_required:
            status = "REVIEW_REQUIRED"
        elif reviewed and (
            decision.same_organisation == dedup_ai.UNKNOWN
            or decision.same_incident == dedup_ai.UNKNOWN
        ):
            status = "UNKNOWN_SEPARATE"
        previous_attempts = int(previous.get("attempts", 0) or 0)
        attempts = previous_attempts + 1 if decision.status == "ERROR" else (
            0 if reviewed else previous_attempts
        )
        if status == "ERROR" and attempts >= MAX_ERROR_ATTEMPTS:
            status = "RETRY_EXHAUSTED"
        blocked_reason = ""
        if status == "SAME_NOT_GROUPED" and items is not None:
            blocked_reason = dedup.separation_reason(
                items,
                candidate.left.Item_ID,
                candidate.right.Item_ID,
                incident_decisions,
            )
        deterministic = dedup.decide_merge(candidate.left, candidate.right)
        same_group = (candidate.left.Item_ID in grouped and
                      grouped.get(candidate.left.Item_ID) == grouped.get(candidate.right.Item_ID))
        row = {"pair_key": key, "left": candidate.left.Item_ID, "right": candidate.right.Item_ID,
               "status": status, "first_seen": previous.get("first_seen", state.run_id),
               "last_run": state.run_id,
               "attempts": attempts,
               "same_organisation": decision.same_organisation, "same_incident": decision.same_incident,
               "confidence": decision.confidence, "reason": decision.reason,
               "blocked_reason": blocked_reason,
               "input_hash": state.rows_by_pair.get(key, {}).get("Input_Hash", ""),
               "model": state.rows_by_pair.get(key, {}).get("Model", ""),
               "disabled_reason": dedup_ai.daily_summary(state)["dedup_disabled_reason"] if status == "DISABLED" else ""}
        row.update({
            "Pair_Key": key,
            "Candidate_Generated": 1,
            "Candidate_Selected": int(decision.status in {
                dedup_ai.STATUS_OK, dedup_ai.STATUS_CACHE_HIT,
                dedup_ai.STATUS_ERROR, dedup_ai.STATUS_BUDGET_BLOCKED,
            }),
            "Deterministic_Decision": deterministic.action,
            "Deterministic_Reason": deterministic.reason_code,
            "LLM_Called": int(
                decision.status in {dedup_ai.STATUS_OK, dedup_ai.STATUS_ERROR}
                and not decision.cache_hit
            ),
            "LLM_Model": row["model"],
            "LLM_Cache_Hit": int(decision.cache_hit),
            "LLM_Same_Organisation": decision.same_organisation,
            "LLM_Same_Incident": decision.same_incident,
            "LLM_Confidence": decision.confidence,
            "Review_Required": int(review_required),
            "Merge_Applied": int(same_group),
            "Final_Separation_Reason": "" if same_group else (blocked_reason or status),
            "Signals": duplicate_audit.fact_comparison(candidate.signals)
            if candidate.signals is not None else {},
        })
        if candidate.signals is not None:
            row.update({
                "Organisation_Exact": int(candidate.signals.organisation_exact),
                "Organisation_Similarity": candidate.signals.organisation_similarity,
                "Publication_Days_Apart": candidate.signals.publication_days_apart,
                "Event_Date_Match": candidate.signals.event_date_match,
                "Threat_Match": candidate.signals.threat_match,
                "Threat_Actor_Match": candidate.signals.threat_actor_match,
                "Affected_Count_Match": candidate.signals.affected_count_match,
                "Data_Type_Overlap": candidate.signals.data_type_overlap,
                "Source_Pair": candidate.signals.source_pair,
                "Source_Native_ID_Match": candidate.signals.source_native_id_match,
                "Matched_Facts": list(decision.matched_facts),
                "Conflicting_Facts": list(decision.conflicting_facts),
                "Missing_Facts": list(decision.missing_facts),
                "Incomparable_Facts": list(decision.incomparable_facts),
            })
        state.review_rows.append(row)
        if status in TERMINAL_STATUSES:
            pending.pop(key, None)
        else:
            pending[key] = row
    state.pending_rows = sorted(pending.values(), key=lambda row: (row["first_seen"], row["pair_key"]))


def save(state) -> None:
    directory = state.cache_path.parent
    directory.mkdir(parents=True, exist_ok=True)
    for name, payload in (("dedup_review_queue.json", state.pending_rows),
                          ("dedup_review_latest.json", {"run_id": state.run_id,
                                                       "summary": dedup_ai.daily_summary(state),
                                                       "pairs": state.review_rows})):
        path = directory / name
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(path)
    if state.run_id:
        history = directory / "llm_runs" / "".join(c for c in state.run_id if c.isalnum() or c in "-_")
        history.mkdir(parents=True, exist_ok=True)
        (history / "dedup_review.json").write_text(
            json.dumps({"summary": dedup_ai.daily_summary(state), "pairs": state.review_rows},
                       ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
