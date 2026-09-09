"""Persistent, bounded retries and per-pair outcomes for the daily dedup net."""
from __future__ import annotations

import json
from pathlib import Path

from . import dedup, dedup_ai, duplicate_audit

AUTO_RETRY = {"DISABLED", "BUDGET_BLOCKED", "ERROR", "NOT_REVIEWED_CAPACITY", "TOP_K_DEFERRED"}
TERMINAL_STATUSES = {"APPLIED", "DIFFERENT"}
MAX_ERROR_ATTEMPTS = 3


def load(path: Path) -> list[dict]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise ValueError("Invalid dedup review queue")
    return value


def retry_candidates(rows: list[dict], items: list, *, limit: int = 40) -> list:
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
        result.extend(duplicate_audit.find_daily_llm_candidates([a], [a, b], max_candidates_per_item=1))
        if len(result) >= limit:
            break
    return result


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
        state.review_rows.append(row)
        if status in {"APPLIED", "DIFFERENT"}:
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
