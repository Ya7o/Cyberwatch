import json

from cyberwatch import config, enrichment, source_facts_ai, sources, status, watchlists
from cyberwatch.http import Budget, HttpClient
from cyberwatch.runner import MODE_MAJ, make_run_context, run_source

context = make_run_context(MODE_MAJ, target_start="2026-01-01", layers=config.LAYER_GROUPS["core"])
client = HttpClient(run_budget=Budget(config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "stable-cache-second"))
for source_id in ("FRENCHBREACHES", "CYBERATTAQUE_ORG"):
    rows = []
    outcome, collected, _ = run_source(
        client,
        sources.by_id(source_id),
        context,
        watchlists.known_organisations(),
        watchlists.entity_index(),
        watchlists.entity_territories(),
        enrichment.load_reference(),
        None,
        None,
        rows,
    )
    print(f"{source_id}_SECOND: status={outcome.status} coverage={outcome.coverage}% items={len(collected)} facts={len(rows)}")
    if outcome.status != status.OK or outcome.coverage < 100:
        raise SystemExit(f"{source_id} incomplete")
stats = source_facts_ai.runtime_stats()
print("SECOND_PASS_STATS=" + json.dumps(stats, ensure_ascii=False, sort_keys=True))
if stats.get("calls_attempted") != 0 or stats.get("items_would_call") != 0:
    raise SystemExit(f"second-pass cache misses={stats.get('items_would_call')} calls={stats.get('calls_attempted')}")
if stats.get("items_fully_cached") != 497:
    raise SystemExit(f"expected 497 full cache hits, got {stats.get('items_fully_cached')}")
