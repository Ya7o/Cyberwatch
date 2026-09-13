import json
from types import SimpleNamespace

from cyberwatch import dedup, dedup_ai, dedup_review, llm_runtime, org_identity, runner_dedup
from cyberwatch.duplicate_audit import compute_candidate_signals, fact_comparison, find_daily_llm_candidates


def _reparstores(make_item):
    left = make_item(
        source="CYBERATTAQUE_ORG", org="Répar’stores",
        published="2026-09-05", url="https://cyberattaque.test/reparstores",
    )
    right = make_item(
        source="FRENCHBREACHES", org="Répar'Store",
        published="2026-09-05", url="https://frenchbreaches.test/reparstore",
    )
    facts = [
        {"Item_ID": left.Item_ID, "Source_ID": left.Source_ID,
         "Summary": "Les données clients ont été exposées."},
        {"Item_ID": right.Item_ID, "Source_ID": right.Source_ID,
         "Affected_Count": "1800000", "Affected_Unit": "clients",
         "Affected_Count_Raw": "1,8 million de clients",
         "Summary": "Un incident a compromis les données clients."},
    ]
    return left, right, facts


def test_reparstores_typographic_and_plural_variant_is_candidate(make_item, monkeypatch):
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})
    left, right, facts = _reparstores(make_item)
    by_item = {row["Item_ID"]: row for row in facts}

    candidates = find_daily_llm_candidates(
        [left], [left, right], facts_by_item=by_item,
    )

    assert len(candidates) == 1
    signals = candidates[0].signals
    assert signals.organisation_similarity == 0.9524
    assert signals.affected_count_match == "MISSING"
    assert "affected_count" in fact_comparison(signals)["missing_facts"]
    assert fact_comparison(signals)["conflicting_facts"] == []


def test_different_units_are_not_direct_conflicts(make_item):
    left, right, _ = _reparstores(make_item)
    facts = {
        left.Item_ID: {"Affected_Count": "1800000", "Affected_Unit": "clients"},
        right.Item_ID: {"Affected_Count": "1800000", "Affected_Unit": "factures"},
    }
    signals = compute_candidate_signals(left, right, facts_by_item=facts)
    assert signals.affected_count_match == "INCOMPARABLE"
    assert "affected_count" in fact_comparison(signals)["incomparable_facts"]


def test_real_count_conflict_is_preserved(make_item):
    left, right, _ = _reparstores(make_item)
    facts = {
        left.Item_ID: {"Affected_Count": "5000", "Affected_Unit": "clients"},
        right.Item_ID: {"Affected_Count": "1800000", "Affected_Unit": "clients"},
    }
    signals = compute_candidate_signals(left, right, facts_by_item=facts)
    assert signals.affected_count_match == "CONFLICT"
    assert "affected_count" in fact_comparison(signals)["conflicting_facts"]


def test_strong_unknown_requires_review(make_item):
    left, right, facts = _reparstores(make_item)
    candidate = find_daily_llm_candidates(
        [left], [left, right], facts_by_item={row["Item_ID"]: row for row in facts},
    )[0]
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK,
        same_organisation=dedup_ai.UNKNOWN,
        same_incident=dedup_ai.UNKNOWN,
        confidence=0.4,
    )
    assert dedup_review.requires_review(candidate, decision) is True


def test_weak_unknown_does_not_force_merge(make_item):
    left = make_item(source="A", org="Fédération Française de Voile", url="https://a")
    right = make_item(source="B", org="Fédération Française de Volley", url="https://b")
    candidate = find_daily_llm_candidates([left], [left, right])[0]
    decision = dedup_ai.DedupAiDecision(
        status=dedup_ai.STATUS_OK,
        same_organisation=dedup_ai.UNKNOWN,
        same_incident=dedup_ai.UNKNOWN,
    )
    assert dedup_review.requires_review(candidate, decision) is False
    assert len(dedup.build_incidents([left, right])) == 2

    state = SimpleNamespace(
        pending_rows=[], review_rows=[], reviewed_count=0,
        incident_pairs_resolved=0, run_id="RUN-WEAK-UNKNOWN",
        rows_by_pair={}, enabled=True, daily_enabled=True,
        candidates_not_reviewed_capacity=0, candidates_not_reviewed_too_large=0,
        calls_budget_blocked=0, batch_calls_succeeded=1, batch_calls_failed=0,
        candidates_generated=1, candidates_selected=1, requested_model="test",
        model="test", effective_model="test", cache_hits=0,
        same_organisation_count=0, same_incident_count=0, different_count=0,
        unknown_count=1, organisation_identity_rows_applied=0,
        incident_decision_rows_applied=0, batch_calls_attempted=1,
        batch_input_tokens=0, batch_output_tokens=0, estimated_cost_usd=0,
        batch_duration_seconds=0,
    )
    key = dedup_ai.candidate_id(candidate)
    dedup_review.outcomes(
        state, [candidate], {key: decision}, [],
        {left.Item_ID: 0, right.Item_ID: 1}, items=[left, right], incident_decisions={},
    )
    assert state.review_rows[0]["status"] == "UNKNOWN_SEPARATE"
    assert state.review_rows[0]["Review_Required"] == 0
    assert state.pending_rows == []


def test_reparstores_same_incident_merges(make_item, tmp_path, monkeypatch):
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-no-network")
    left, right, facts = _reparstores(make_item)
    state = dedup_ai.start_run(tmp_path / "cache.csv")
    state.run_id = "RUN-REPARSTORES-TEST"

    def call_json(**kwargs):
        body = json.loads(kwargs["user_content"][kwargs["user_content"].index("{"):])
        candidate = body["candidates"][0]
        return SimpleNamespace(
            data={"decisions": [{
                "candidate_id": candidate["candidate_id"],
                "same_organisation": "SAME", "same_incident": "SAME",
                "confidence": 0.98,
                "evidence": "Répar’stores et Répar'Store désignent la même victime.",
                "reason": "Même événement publié le même jour.",
                "matched_facts": ["Répar’stores", "Répar'Store", "threat"],
                "conflicting_facts": [], "missing_facts": ["affected_count:left"],
                "incomparable_facts": [],
            }]},
            model="test-model", duration_seconds=0,
            usage=SimpleNamespace(estimated_cost_usd=0, input_tokens=10, output_tokens=10),
        )

    monkeypatch.setattr(llm_runtime, "runtime", lambda: SimpleNamespace(call_json=call_json))
    assert runner_dedup.apply_daily_decisions(state, [left, right], [left], facts) == []
    assert state.incident_pairs_resolved == 1
    assert not state.pending_rows

    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {
        row["Alias_Key"]: row["Canonical_Key"] for row in state.organisation_identity_rows
    })
    assert len(dedup.build_incidents([left, right], state.incident_dedup_rows)) == 1


def test_strong_unknown_is_audited_without_alias(make_item, tmp_path, monkeypatch):
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-no-network")
    left, right, facts = _reparstores(make_item)
    state = dedup_ai.start_run(tmp_path / "cache.csv")
    state.run_id = "RUN-UNKNOWN-TEST"

    def call_json(**kwargs):
        body = json.loads(kwargs["user_content"][kwargs["user_content"].index("{"):])
        candidate = body["candidates"][0]
        return SimpleNamespace(
            data={"decisions": [{
                "candidate_id": candidate["candidate_id"],
                "same_organisation": "SAME", "same_incident": "UNKNOWN",
                "confidence": 0.9,
                "evidence": "Répar’stores et Répar'Store semblent désigner la même victime.",
                "reason": "Contexte incident insuffisant.",
                "matched_facts": ["Répar’stores", "Répar'Store", "threat"],
                "conflicting_facts": [], "missing_facts": ["affected_count:left"],
                "incomparable_facts": [],
            }]}, model="test-model", duration_seconds=0,
            usage=SimpleNamespace(estimated_cost_usd=0, input_tokens=10, output_tokens=10),
        )

    monkeypatch.setattr(llm_runtime, "runtime", lambda: SimpleNamespace(call_json=call_json))
    assert runner_dedup.apply_daily_decisions(state, [left, right], [left], facts) == []
    assert state.organisation_identity_rows == []
    assert state.pending_rows[0]["status"] == "REVIEW_REQUIRED"
    assert state.pending_rows[0]["Review_Required"] == 1
    assert state.pending_rows[0]["Merge_Applied"] == 0
    assert len(dedup.build_incidents([left, right])) == 2
