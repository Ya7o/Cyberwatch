import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from cyberwatch import dedup, dedup_ai, dedup_review, incident_dedup, llm_runtime, org_identity, runner_dedup
from cyberwatch.model import Item


FIXTURES = Path(__file__).parent / 'fixtures/editorial_20260906'


def state(tmp_path, monkeypatch):
    # The repository may already contain decisions produced by a previous
    # backfill; these tests exercise the path from an empty dynamic registry.
    monkeypatch.setattr(org_identity, 'ORGANISATION_IDENTITY_REGISTRY', {})
    monkeypatch.setenv('OPENAI_API_KEY', 'test-only-no-network')
    monkeypatch.setenv('DEDUP_AI_DAILY_ENABLED', '1')
    result = dedup_ai.start_run(tmp_path / 'cache.csv')
    result.run_id = 'RUN-REPAIR-TEST'
    return result


def mock_transport(monkeypatch, label='SAME'):
    calls = []

    def call_json(**kwargs):
        content = kwargs['user_content']
        body = json.loads(content[content.index('{'):])
        candidates = body['candidates']
        calls.append(candidates)
        return SimpleNamespace(
            data={'decisions': [{'candidate_id': c['candidate_id'], 'same_organisation': 'SAME',
                                  'same_incident': label, 'confidence': .95,
                                  'evidence': 'Même notification, même archive et même contexte.',
                                  'reason': 'Corroboration entre les deux sources.',
                                  'matched_facts': ['notification', 'volume'], 'conflicting_facts': []}
                                 for c in candidates]},
            model='test-model', duration_seconds=0,
            usage=SimpleNamespace(estimated_cost_usd=0, input_tokens=10, output_tokens=10),
        )
    monkeypatch.setattr(llm_runtime, 'runtime', lambda: SimpleNamespace(call_json=call_json))
    return calls


def examples():
    rows = json.loads((FIXTURES / 'dedup_pairs.json').read_text())
    return [Item.from_row(r['item']) for r in rows], [r['facts'] for r in rows]


def test_actual_pairs_are_merged_persisted_and_replayed(tmp_path, monkeypatch):
    items, facts = examples()
    run = state(tmp_path, monkeypatch)
    calls = mock_transport(monkeypatch)
    before, registry = dedup.build_incidents_with_registry(items, [])
    assert len(before) == 4
    assert runner_dedup.apply_daily_decisions(run, items, items, facts) == []
    assert run.incident_pairs_resolved == 2
    assert len(calls) == 1
    assert not run.pending_rows
    monkeypatch.setattr(org_identity, 'ORGANISATION_IDENTITY_REGISTRY', {
        row['Alias_Key']: row['Canonical_Key'] for row in run.organisation_identity_rows})
    merged, registry = dedup.build_incidents_with_registry(items, registry, run.incident_dedup_rows)
    assert len(merged) == 2
    assert all(i.Items_Count == 2 and len(i.Source_URLs.split(' | ')) == 2 for i in merged)
    assert sum(bool(row['Redirect_To']) for row in registry) == 2
    again, again_registry = dedup.build_incidents_with_registry(items, registry, run.incident_dedup_rows)
    assert [i.to_row() for i in again] == [i.to_row() for i in merged]
    assert again_registry == registry
    dedup_ai.save_cache(run)
    dedup_review.save(run)
    assert json.loads((tmp_path / 'dedup_review_queue.json').read_text()) == []


def test_disabled_pairs_remain_retryable_without_new_items(tmp_path, monkeypatch):
    items, facts = examples()
    run = state(tmp_path, monkeypatch)
    run.enabled = False
    assert runner_dedup.apply_daily_decisions(run, items, items, facts) == []
    assert len(run.pending_rows) == 2
    assert all(r['disabled_reason'] == 'API_KEY_MISSING' for r in run.pending_rows)
    dedup_review.save(run)
    next_run = state(tmp_path, monkeypatch)
    next_run.pending_rows = dedup_review.load(tmp_path / 'dedup_review_queue.json')
    mock_transport(monkeypatch)
    assert runner_dedup.apply_daily_decisions(next_run, items, [], facts) == []
    assert next_run.incident_pairs_resolved == 2


@pytest.mark.parametrize('error', [llm_runtime.LlmError, llm_runtime.LlmBudgetExceeded])
def test_failed_or_budget_blocked_pairs_are_not_lost(error, tmp_path, monkeypatch):
    items, facts = examples()
    run = state(tmp_path, monkeypatch)
    def fail(**_):
        raise error('test')
    monkeypatch.setattr(llm_runtime, 'runtime', lambda: SimpleNamespace(call_json=fail))
    assert runner_dedup.apply_daily_decisions(run, items, items, facts) == []
    assert run.incident_pairs_resolved == 0 and len(run.pending_rows) == 2
    assert not run.incident_dedup_rows
    expected_attempts = 1 if error is llm_runtime.LlmError else 0
    assert {row['attempts'] for row in run.pending_rows} == {expected_attempts}


def test_three_errors_exhaust_retry_and_keep_review_visible(tmp_path, monkeypatch):
    items, facts = examples()
    run = state(tmp_path, monkeypatch)

    def fail(**_):
        raise llm_runtime.LlmError('test')

    monkeypatch.setattr(llm_runtime, 'runtime', lambda: SimpleNamespace(call_json=fail))
    for _ in range(3):
        assert runner_dedup.apply_daily_decisions(run, items, items, facts) == []

    assert {row['status'] for row in run.pending_rows} == {'RETRY_EXHAUSTED'}
    assert {row['attempts'] for row in run.pending_rows} == {3}
    assert dedup_review.retry_candidates(run.pending_rows, items) == []
    following_run = state(tmp_path, monkeypatch)
    following_run.pending_rows = copy.deepcopy(run.pending_rows)
    assert dedup_ai.daily_summary(following_run)['dedup_status'] == 'REVIEW_REQUIRED'


def test_reconcile_removes_a_same_pair_now_grouped(make_item):
    left = make_item(source='A', org='Globex', published='2026-08-01', url='https://a')
    right = make_item(source='B', org='Globex', published='2026-08-08', url='https://b')
    pair = incident_dedup.pair_key(left.Item_ID, right.Item_ID)
    rows = [{'pair_key': pair, 'left': left.Item_ID, 'right': right.Item_ID,
             'status': 'SAME_NOT_GROUPED', 'attempts': 0, 'first_seen': 'RUN-1'}]

    assert dedup_review.reconcile(rows, [left, right], {pair: incident_dedup.SAME}) == []


def test_old_non_error_attempt_count_does_not_exhaust_retry(make_item):
    left = make_item(source='A', org='Example Company', published='2026-08-01', url='https://a')
    right = make_item(source='B', org='ExampleCompany', published='2026-08-01', url='https://b')
    rows = [{
        'pair_key': incident_dedup.pair_key(left.Item_ID, right.Item_ID),
        'left': left.Item_ID,
        'right': right.Item_ID,
        'status': 'DISABLED',
        'attempts': 3,
        'first_seen': 'RUN-OLD',
    }]

    assert len(dedup_review.retry_candidates(rows, [left, right])) == 1


def test_alias_does_not_bypass_incident_time_bound(make_item):
    from cyberwatch.duplicate_audit import find_daily_llm_candidates
    a = make_item(org='Example Company', source='A', published='2026-01-01')
    b = make_item(org='ExampleCompany', source='B', published='2026-02-01')
    candidate = find_daily_llm_candidates([a], [a, b])[0]
    decision = dedup_ai.DedupAiDecision(status='OK', same_organisation='SAME', same_incident='SAME', confidence=.95)
    assert dedup_ai.validate_ai_incident_decision(candidate, decision) is None
    assert dedup_ai.validate_ai_dedup_decision(candidate, decision) is not None


def test_current_zero_call_telemetry_replaces_previous_run(tmp_path, monkeypatch):
    from cyberwatch.source_facts_ai_runtime import _Runtime
    monkeypatch.delenv('OPENAI_API_KEY', raising=False)
    monkeypatch.setenv('SOURCE_FACTS_AI_STATS_PATH', str(tmp_path / 'source.json'))
    monkeypatch.setenv('SOURCE_FACTS_AI_CACHE_PATH', str(tmp_path / 'cache.json'))
    (tmp_path / 'source.json').write_text('{"calls_success": 10}')
    runtime = _Runtime()
    runtime.run_id = 'RUN-ZERO'
    runtime.save_stats()
    result = json.loads((tmp_path / 'source.json').read_text())
    assert result['run_id'] == 'RUN-ZERO' and result['calls_success'] == 0
    assert result['disabled_reason'] == 'API_KEY_MISSING'
    monkeypatch.setattr(llm_runtime, '_RUNTIME', llm_runtime.LlmRuntime())
    monkeypatch.setenv('LLM_USAGE_PATH', str(tmp_path / 'usage.json'))
    llm_runtime.begin_run('RUN-ZERO')
    llm_runtime._write_stats()
    assert json.loads((tmp_path / 'usage.json').read_text())['calls_attempted'] == 0
