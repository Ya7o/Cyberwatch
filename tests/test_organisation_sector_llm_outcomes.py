from __future__ import annotations

from cyberwatch import organisation_sector_llm as osllm


def test_legacy_positive_cache_is_still_produced():
    assert osllm._cached_decision_outcome({"Sector": "Santé"}) == "PRODUCED"


def test_persisted_abstention_replays_as_no_match_not_budget_blocked():
    row = {
        "Sector": "",
        "Decision_Status": "ABSTAINED",
        "Execution_Status": "EXECUTED",
    }
    assert osllm._cached_decision_outcome(row) == "NO_MATCH"


def test_empty_unexecuted_cache_has_no_decision():
    assert osllm._cached_decision_outcome({"Decision_Status": "", "Execution_Status": "BUDGET_BLOCKED"}) == ""
