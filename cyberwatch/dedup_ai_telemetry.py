"""Per-run telemetry for the daily deduplication challenger."""
from __future__ import annotations

from .model import DEDUP_AI_DAILY_USAGE_COLUMNS

DAILY_STATUS_OK = "OK"
DAILY_STATUS_NO_CANDIDATES = "NO_CANDIDATES"
DAILY_STATUS_LLM_DISABLED = "LLM_DISABLED"
DAILY_STATUS_LLM_ERROR = "LLM_ERROR"
DAILY_STATUS_BUDGET_BLOCKED = "BUDGET_BLOCKED"
DAILY_STATUS_CAPACITY_LIMIT = "CAPACITY_LIMIT"
DAILY_USAGE_COLUMNS = DEDUP_AI_DAILY_USAGE_COLUMNS


def _too_large(state) -> int:
    """Paires différées parce que leur seule charge utile dépassait le budget."""
    return int(getattr(state, "candidates_not_reviewed_too_large", 0) or 0)


def daily_status(state) -> str:
    if not state.enabled or not state.daily_enabled:
        return DAILY_STATUS_LLM_DISABLED
    if state.candidates_not_reviewed_capacity > 0 or _too_large(state) > 0:
        return DAILY_STATUS_CAPACITY_LIMIT
    if state.calls_budget_blocked > 0 and state.batch_calls_succeeded == 0:
        return DAILY_STATUS_BUDGET_BLOCKED
    if state.batch_calls_failed > 0 and state.batch_calls_succeeded == 0:
        return DAILY_STATUS_LLM_ERROR
    if any(row.get("status") == "ERROR" for row in state.review_rows):
        return DAILY_STATUS_LLM_ERROR
    if state.pending_rows:
        return "REVIEW_REQUIRED"
    if state.candidates_generated == 0:
        return DAILY_STATUS_NO_CANDIDATES
    return DAILY_STATUS_OK


def daily_summary(state) -> dict[str, object]:
    return {
        "dedup_status": daily_status(state),
        "dedup_disabled_reason": ("API_KEY_MISSING" if not state.enabled else
                                  "FLAG_DISABLED" if not state.daily_enabled else ""),
        "dedup_requested_model": state.requested_model or state.model,
        "dedup_effective_model": state.effective_model,
        "dedup_pairs_reviewed": state.reviewed_count,
        "dedup_incident_pairs_resolved": state.incident_pairs_resolved,
        "dedup_candidates_generated": state.candidates_generated,
        "dedup_candidates_selected": state.candidates_selected,
        "dedup_candidates_not_reviewed_capacity": state.candidates_not_reviewed_capacity,
        "dedup_candidates_not_reviewed_too_large": _too_large(state),
        "dedup_llm_calls": state.batch_calls_attempted,
        "dedup_llm_calls_succeeded": state.batch_calls_succeeded,
        "dedup_llm_calls_failed": state.batch_calls_failed,
        "dedup_llm_cache_hits": state.cache_hits,
        "dedup_llm_same_org": state.same_organisation_count,
        "dedup_llm_same_incident": state.same_incident_count,
        "dedup_llm_different": state.different_count,
        "dedup_llm_unknown": state.unknown_count,
        "dedup_org_aliases_applied": state.organisation_identity_rows_applied,
        "dedup_incident_decisions_applied": state.incident_decision_rows_applied,
        "dedup_incident_merges_enabled": True,
        "dedup_review_required": (
            len(state.pending_rows) or state.candidates_not_reviewed_capacity or _too_large(state)
        ),
        "dedup_retry_exhausted": sum(
            row.get("status") == "RETRY_EXHAUSTED" for row in state.pending_rows
        ),
        "dedup_same_not_grouped": sum(
            row.get("status") == "SAME_NOT_GROUPED" for row in state.pending_rows
        ),
        "dedup_llm_input_tokens": state.batch_input_tokens,
        "dedup_llm_output_tokens": state.batch_output_tokens,
        "dedup_llm_cost_usd": round(state.estimated_cost_usd, 6),
        "dedup_llm_duration_seconds": round(state.batch_duration_seconds, 3),
    }


def daily_usage_row(state, *, run_id: str, as_of: str, mode: str,
                    prompt_version: str) -> dict[str, str]:
    summary = daily_summary(state)
    return {
        "Run_ID": run_id, "As_Of": as_of, "Mode": mode,
        "Status": daily_status(state),
        "Enabled": "1" if state.enabled and state.daily_enabled else "0",
        "Disabled_Reason": str(summary["dedup_disabled_reason"]),
        "Model": state.model,
        "Requested_Model": str(summary["dedup_requested_model"]),
        "Effective_Model": str(summary["dedup_effective_model"]),
        "Prompt_Version": prompt_version,
        "Candidates_Generated": str(summary["dedup_candidates_generated"]),
        "Candidates_Selected": str(summary["dedup_candidates_selected"]),
        "Candidates_Not_Reviewed_Capacity": str(summary["dedup_candidates_not_reviewed_capacity"]),
        "Pairs_Reviewed": str(summary["dedup_pairs_reviewed"]),
        "Incident_Pairs_Resolved": str(summary["dedup_incident_pairs_resolved"]),
        "LLM_Calls": str(summary["dedup_llm_calls"]),
        "LLM_Calls_Succeeded": str(summary["dedup_llm_calls_succeeded"]),
        "LLM_Calls_Failed": str(summary["dedup_llm_calls_failed"]),
        "LLM_Cache_Hits": str(summary["dedup_llm_cache_hits"]),
        "LLM_Same_Organisation": str(summary["dedup_llm_same_org"]),
        "LLM_Same_Incident": str(summary["dedup_llm_same_incident"]),
        "LLM_Different": str(summary["dedup_llm_different"]),
        "LLM_Unknown": str(summary["dedup_llm_unknown"]),
        "Org_Aliases_Applied": str(summary["dedup_org_aliases_applied"]),
        "Incident_Decisions_Applied": str(summary["dedup_incident_decisions_applied"]),
        "Review_Required": str(summary["dedup_review_required"]),
        "LLM_Input_Tokens": str(summary["dedup_llm_input_tokens"]),
        "LLM_Output_Tokens": str(summary["dedup_llm_output_tokens"]),
        "LLM_Cost_USD": f"{summary['dedup_llm_cost_usd']:.6f}",
        "LLM_Duration_Seconds": f"{summary['dedup_llm_duration_seconds']:.3f}",
    }
