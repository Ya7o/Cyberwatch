import csv
import json

from cyberwatch import dedup_ai
from cyberwatch.duplicate_audit import (
    DedupAuditCandidate,
    MERGE_REVIEW_WEAK_CANONICAL_NAME,
    RISK_FALSE_MERGE,
    RISK_MISSED_DUPLICATE,
)


def _candidate(make_item, risk_type=RISK_MISSED_DUPLICATE, *, days=1, same_source=False, recurrence=False):
    left = make_item(
        source="A",
        org="Globex",
        published="2026-08-01",
        url="https://a",
        title="Globex revendiqué par Qilin",
    )
    right = make_item(
        source="A" if same_source else "B",
        org="Globex France",
        published=f"2026-08-{1 + days:02d}",
        url="https://b",
        title="Globex France frappé une nouvelle fois" if recurrence else "Globex France : cyberattaque",
    )
    return DedupAuditCandidate(
        risk_type=risk_type,
        left=left,
        right=right,
        days_apart=days,
        reason_code=MERGE_REVIEW_WEAK_CANONICAL_NAME,
    )


def test_same_day_cross_source_false_merge_is_not_sent_to_llm(make_item):
    candidate = _candidate(
        make_item,
        risk_type=RISK_FALSE_MERGE,
        days=0,
    )
    assert dedup_ai.worth_challenging(candidate) is False


def test_same_source_false_merge_is_sent_to_llm(make_item):
    candidate = _candidate(
        make_item,
        risk_type=RISK_FALSE_MERGE,
        days=2,
        same_source=True,
    )
    assert dedup_ai.worth_challenging(candidate) is True


def test_same_day_recurrence_remains_auditable(make_item):
    candidate = _candidate(
        make_item,
        risk_type=RISK_FALSE_MERGE,
        days=0,
        recurrence=True,
    )
    assert dedup_ai.worth_challenging(candidate) is True


def test_classic_openai_call_uses_local_facts_and_cache(monkeypatch, tmp_path, make_item):
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("DEDUP_AI_MAX_COST_USD", "1")
    cache_path = tmp_path / "dedup_ai_cache.csv"
    candidate = _candidate(make_item)
    facts = {
        candidate.left.Item_ID: {
            "Item_ID": candidate.left.Item_ID,
            "Victim_Website": "globex.example",
            "Threat_Actor": "Qilin",
        },
        candidate.right.Item_ID: {
            "Item_ID": candidate.right.Item_ID,
            "Victim_Website": "globex.example",
            "Threat_Actor": "Qilin",
        },
    }
    calls = []

    def fake_post(body, state):
        calls.append(body)
        assert "tools" not in body
        user_text = body["input"][1]["content"]
        assert "globex.example" in user_text
        assert "Qilin" in user_text
        return {
            "output_text": json.dumps({
                "same_organisation": "SAME",
                "same_incident": "SAME",
                "confidence": 0.97,
                "evidence": "Même domaine victime et même acteur.",
                "reason": "Les deux sources décrivent le même événement.",
            }),
            "usage": {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 0},
                "output_tokens": 30,
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": 130,
            },
        }

    monkeypatch.setattr(dedup_ai.ai, "_post_openai", fake_post)

    state = dedup_ai.start_run(cache_path)
    first = dedup_ai.challenge_candidate(candidate, facts, state)
    assert first.status == dedup_ai.STATUS_OK
    assert first.same_incident == dedup_ai.SAME
    assert state.calls_attempted == 1
    dedup_ai.save_cache(state)

    rows = list(csv.DictReader(cache_path.open(encoding="utf-8")))
    assert len(rows) == 1
    assert rows[0]["Same_Incident"] == "SAME"

    def should_not_call(*args, **kwargs):
        raise AssertionError("cache miss")

    monkeypatch.setattr(dedup_ai.ai, "_post_openai", should_not_call)
    cached_state = dedup_ai.start_run(cache_path)
    second = dedup_ai.challenge_candidate(candidate, facts, cached_state)
    assert second.status == dedup_ai.STATUS_CACHE_HIT
    assert second.cache_hit is True
    assert cached_state.calls_attempted == 0


def test_absent_api_key_disables_calls(monkeypatch, tmp_path, make_item):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    state = dedup_ai.start_run(tmp_path / "cache.csv")
    decision = dedup_ai.challenge_candidate(_candidate(make_item), {}, state)
    assert decision.status == dedup_ai.STATUS_DISABLED
    assert state.calls_attempted == 0
