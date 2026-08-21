from cyberwatch.collectors.base import SourceSpec
from cyberwatch.source_portfolio import build_portfolio


def _score(source_id, index, reliability=100, recent_runs=10, exclusive=1, warnings=None):
    return {
        "source_id": source_id,
        "value_index": index,
        "reliability_pct": reliability,
        "recent_runs": recent_runs,
        "exclusive_incidents": exclusive,
        "warnings": warnings or [],
    }


def _payload(rows, gaps=None):
    return {
        "as_of": "2026-08-21T12:00:00+04:00",
        "snapshot_run_id": "RUN-X",
        "sources": rows,
        "coverage": {"missing_tracked_locations": gaps or []},
    }


def test_strong_active_source_is_kept():
    specs = [SourceSpec("A", "CORE_DIRECT", "France métropolitaine", active=True)]
    result = build_portfolio(_payload([_score("A", 82)]), specs)
    assert result["active_decisions"][0]["action"] == "KEEP"


def test_weak_redundant_unreliable_source_becomes_deactivation_candidate():
    specs = [SourceSpec("A", "CORE_DIRECT", "France métropolitaine", active=True)]
    result = build_portfolio(_payload([_score("A", 22, reliability=30, recent_runs=8, exclusive=0)]), specs)
    assert result["active_decisions"][0]["action"] == "DEACTIVATION_CANDIDATE"


def test_low_score_without_enough_evidence_is_review_not_auto_deactivation():
    specs = [SourceSpec("A", "CORE_DIRECT", "France métropolitaine", active=True)]
    result = build_portfolio(_payload([_score("A", 30, reliability=0, recent_runs=2, exclusive=0)]), specs)
    assert result["active_decisions"][0]["action"] == "REVIEW"


def test_inactive_source_filling_gap_is_prioritized():
    specs = [
        SourceSpec("MAURICE", "CORE_DIRECT", "Maurice", start_url="https://example.mu", active=False, success_test="ok"),
        SourceSpec("FRANCE", "CORE_DIRECT", "France métropolitaine", start_url="https://example.fr", active=False, success_test="ok"),
    ]
    result = build_portfolio(_payload([], gaps=["Maurice"]), specs)
    assert result["inactive_candidates"][0]["source_id"] == "MAURICE"
    assert "fills_observed_location_gap" in result["inactive_candidates"][0]["reasons"]


def test_known_access_blocker_reduces_candidate_priority():
    specs = [
        SourceSpec("OPEN", "CORE_DIRECT", "Maurice", start_url="https://open.example", active=False, success_test="ok"),
        SourceSpec("BLOCKED", "CORE_DIRECT", "Maurice", start_url="https://blocked.example", active=False, success_test="ok", notes="Réactiver après correction 403"),
    ]
    result = build_portfolio(_payload([], gaps=["Maurice"]), specs)
    rows = {row["source_id"]: row for row in result["inactive_candidates"]}
    assert rows["OPEN"]["priority"] > rows["BLOCKED"]["priority"]


def test_decision_is_deterministic_across_spec_order():
    specs = [
        SourceSpec("B", "CORE_DIRECT", "Maurice", active=False),
        SourceSpec("A", "CORE_DIRECT", "France métropolitaine", active=True),
    ]
    payload = _payload([_score("A", 70)], gaps=["Maurice"])
    assert build_portfolio(payload, specs) == build_portfolio(payload, list(reversed(specs)))
