"""Read-only, offline probes for the 2026-09-06 deduplication audit.

Run from the repository root: .venv/bin/python audit/dedup_2026-09-06/probe.py
Only stdout is written; canonical files and network are never used for writes.
"""
import collections
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
os.environ['LLM_USAGE_PATH'] = str(Path(tempfile.gettempdir()) / 'cyberwatch-dedup-audit-usage.json')
from cyberwatch import config, dedup, dedup_ai, dedup_review, duplicate_audit, incident_dedup, org_identity, store
from cyberwatch.model import Item
from cyberwatch.normalize import organisation_key


def pack(item):
    return {k: getattr(item, k) for k in ('Item_ID', 'Source_ID', 'Source_Item_ID', 'Organisation_Raw', 'Published_Date', 'Event_Date', 'Threat', 'Title', 'URL')}


def make(n, day, source, native='', event='', org='Audit Example', threat=''):
    return Item(Item_ID=n, Source_ID=source, Source_Item_ID=native,
                Published_Date='2026-08-' + f'{day:02d}', Event_Date=event,
                Organisation_Raw=org, Organisation_Key=organisation_key(org),
                Threat=threat, Title='Notification du même incident', URL='https://example.test/' + n)


items = store.load_items()
incidents = store.load_incidents()
decisions = incident_dedup.decision_map(store.load_incident_dedup_registry())
start = time.perf_counter()
components = dedup.group_components(items, decisions)
group_seconds = time.perf_counter() - start
groups = {i.Item_ID: n for n, group in enumerate(components) for i in group}
facts = store.load_source_facts()
websites = {r['Item_ID']: r.get('Victim_Website', '') for r in facts}
deferred = []
start = time.perf_counter()
candidates = duplicate_audit.find_daily_llm_candidates(items, items, victim_websites=websites, deferred=deferred)
candidate_seconds = time.perf_counter() - start
audit_candidates = duplicate_audit.find_audit_candidates(items)
missed_edges = []
within_reasons = collections.Counter()
for a, b in itertools.combinations(items, 2):
    decision = dedup.decide_merge(a, b, decisions)
    if groups.get(a.Item_ID) == groups.get(b.Item_ID):
        within_reasons[decision.reason_code] += 1
    elif decision.action == dedup.MERGE:
        missed_edges.append({'left': pack(a), 'right': pack(b), 'reason': decision.reason_code})
native_groups = collections.defaultdict(list)
for item in items:
    if item.Source_Item_ID:
        native_groups[(item.Source_ID, item.Source_Item_ID)].append(item.Item_ID)
replayed, _ = dedup.build_incidents_with_registry(items, store.load_incident_id_registry(), store.load_incident_dedup_registry(), facts)
stored_by_id = {i.Incident_ID: i.to_row() for i in incidents}
result = {
    'items': len(items), 'stored_incidents': len(incidents), 'recomputed_incidents': len(replayed),
    'replay_equals_stored': [i.to_row() for i in replayed] == [i.to_row() for i in incidents],
    'replay_differences': {i.Incident_ID: {k: {'stored': stored_by_id.get(i.Incident_ID, {}).get(k), 'recomputed': v} for k, v in i.to_row().items() if stored_by_id.get(i.Incident_ID, {}).get(k) != v} for i in replayed if stored_by_id.get(i.Incident_ID) != i.to_row()},
    'component_sizes': dict(collections.Counter(map(len, components))),
    'group_seconds': group_seconds, 'full_candidate_seconds': candidate_seconds,
    'source_native_ids': {source: {'total': sum(i.Source_ID == source for i in items), 'native': sum(i.Source_ID == source and bool(i.Source_Item_ID) for i in items)} for source in sorted({i.Source_ID for i in items})},
    'duplicate_item_ids': [k for k, v in collections.Counter(i.Item_ID for i in items).items() if v > 1],
    'duplicate_native_ids': {str(k): v for k, v in native_groups.items() if len(v) > 1},
    'missing_component_items': [i.Item_ID for i in items if i.Item_ID not in groups],
    'within_component_pair_reasons': dict(within_reasons),
    'merge_edges_between_components': missed_edges,
    'registry_decisions': dict(collections.Counter(decisions.values())),
    'organisation_registry_rows': len(store.load_organisation_identity_registry_rows()),
    'full_candidates': len(candidates), 'full_deferred': len(deferred),
    'candidate_strong_signal_pairs': sum(c.signals.strong_signal_count > 0 for c in candidates),
    'candidate_unique_organisation_pairs': len({tuple(sorted((c.left.Organisation_Raw, c.right.Organisation_Raw))) for c in candidates}),
    'production_audit_candidates_by_risk': dict(collections.Counter(c.risk_type for c in audit_candidates)),
    'production_audit_candidates_by_reason': dict(collections.Counter(c.reason_code for c in audit_candidates)),
    'production_audit_pairs_already_grouped': sum(groups[c.left.Item_ID] == groups[c.right.Item_ID] for c in audit_candidates),
    'incidents_without_incident_decision_registry': len(dedup.group_components(items)),
    'event_dates_present': sum(bool(i.Event_Date) for i in items),
    'candidates_already_grouped': sum(groups[c.left.Item_ID] == groups[c.right.Item_ID] for c in candidates),
    'candidate_examples': [{'left': pack(c.left), 'right': pack(c.right), 'days': c.days_apart, 'signals': vars(c.signals)} for c in candidates[:20]],
    'recent_usage': store.load_dedup_ai_daily_usage()[-12:],
    'review_queue_exists': (ROOT / 'data/dedup_review_queue.json').exists(),
    'benchmark': duplicate_audit.dedup_identity_benchmark(json.loads((ROOT / 'tests/fixtures/dedup_identity_cases.json').read_text())['cases']),
}

# A third observation can split a pair that the pairwise rule accepts.
a, b, c = make('A', 1, 'FRENCHBREACHES', 'post-a'), make('B', 2, 'FRENCHBREACHES', 'post-b'), make('C', 3, 'CYBERATTAQUE_ORG', 'post-c')
result['interleaving_probe'] = {'pair_ac': vars(dedup.decide_merge(a, c)), 'components': [[i.Item_ID for i in g] for g in dedup.group_components([a, b, c])], 'candidate_ac': len(duplicate_audit.find_daily_llm_candidates([c], [a, c]))}

# An accepted, persisted SAME can be bypassed after a native-ID split.
c = make('C', 8, 'CYBERATTAQUE_ORG', 'post-c')
same = {incident_dedup.pair_key('A', 'C'): incident_dedup.SAME}
cand_same = duplicate_audit.find_daily_llm_candidates([c], [a, c])[0]
verdict_same = dedup_ai.DedupAiDecision(status='OK', same_organisation='SAME', same_incident='SAME', confidence=.95)
result['accepted_same_not_grouped_probe'] = {'accepted': dedup_ai.validate_ai_incident_decision(cand_same, verdict_same) is not None, 'pair_ac': vars(dedup.decide_merge(a, c, same)), 'components': [[i.Item_ID for i in g] for g in dedup.group_components([a, b, c], same)]}

# Every edge satisfies the ransomware window, but the component does not.
a, b, c = [make(n, day, source, threat=config.THREAT_RANSOMWARE) for n, day, source in [('A', 1, 'CYBERATTAQUE_ORG'), ('B', 14, 'RANSOMWARE_LIVE'), ('C', 27, 'FRENCHBREACHES')]]
result['ransomware_chain_probe'] = {'components': [[i.Item_ID for i in g] for g in dedup.group_components([a, b, c])], 'outer_pair': vars(dedup.decide_merge(a, c))}

# Mixed event/publication ordering can hide a valid bridge from the post-pass.
a = make('A', 1, 'CYBERATTAQUE_ORG', event='2026-07-01', threat=config.THREAT_RANSOMWARE)
b = make('B', 10, 'RANSOMWARE_LIVE', threat=config.THREAT_RANSOMWARE)
result['mixed_dates_probe'] = {'pair': vars(dedup.decide_merge(a, b)), 'components': [[i.Item_ID for i in g] for g in dedup.group_components([a, b])]}

# SAME organisation and UNKNOWN incident can still trigger name-based merging.
a = make('A', 1, 'A', org='Audit Example')
b = make('B', 2, 'B', org='AuditExample')
cand = duplicate_audit.find_daily_llm_candidates([a], [a, b])[0]
verdict = dedup_ai.DedupAiDecision(status='OK', same_organisation='SAME', same_incident='UNKNOWN', confidence=.95)
alias = dedup_ai.validate_ai_dedup_decision(cand, verdict)
previous = org_identity.ORGANISATION_IDENTITY_REGISTRY
try:
    org_identity.ORGANISATION_IDENTITY_REGISTRY = {alias['Alias_Key']: alias['Canonical_Key']}
    result['unknown_incident_probe'] = {'incident_proposal': dedup_ai.validate_ai_incident_decision(cand, verdict), 'components_after_alias': [[i.Item_ID for i in g] for g in dedup.group_components([a, b])]}
finally:
    org_identity.ORGANISATION_IDENTITY_REGISTRY = previous

state = dedup_ai.DedupAiRunState(enabled=True, api_key='', model='offline', cache_path=Path('/tmp/unused.csv'), daily_enabled=True)
state.pending_rows = [{'pair_key': dedup_ai.candidate_id(cand), 'left': a.Item_ID, 'right': b.Item_ID, 'status': 'ERROR', 'attempts': 3, 'first_seen': 'old-run'}]
result['exhausted_retry_probe'] = {'retry_candidates': len(dedup_review.retry_candidates(state.pending_rows, [a, b])), 'summary': dedup_ai.daily_summary(state)}

# Conservative policy also makes repeated editorial reports unreviewable.
a = make('A', 1, 'CYBERATTAQUE_ORG', 'article-1')
b = make('B', 2, 'CYBERATTAQUE_ORG', 'article-2')
result['same_source_followup_probe'] = {'decision': vars(dedup.decide_merge(a, b)), 'candidates': len(duplicate_audit.find_daily_llm_candidates([b], [a, b]))}

# Per-run cost on unique organisations, with no possible ransomware merge.
result['scaling_group_seconds'] = {}
for count in (100, 300):
    sample = [make(str(n), 1, 'FRENCHBREACHES', str(n), org=f'Audit Organisation {n}') for n in range(count)]
    start = time.perf_counter()
    assert len(dedup.group_components(sample)) == count
    result['scaling_group_seconds'][str(count)] = time.perf_counter() - start
print(json.dumps(result, ensure_ascii=False, indent=2))
