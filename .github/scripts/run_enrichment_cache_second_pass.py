import json

from cyberwatch import config, enrichment, source_facts_ai, sources, status, watchlists
from cyberwatch.http import Budget, HttpClient
from cyberwatch.runner import MODE_MAJ, make_run_context, run_source

context = make_run_context(MODE_MAJ, target_start="2026-01-01", layers=config.LAYER_GROUPS["core"])
client = HttpClient(run_budget=Budget(config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "stable-cache-second"))
source_counts = {}
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
    source_counts[source_id] = len(collected)
    print(f"{source_id}_SECOND: status={outcome.status} coverage={outcome.coverage}% items={len(collected)} facts={len(rows)}")
    if outcome.status != status.OK or outcome.coverage < 100:
        raise SystemExit(f"{source_id} incomplete")
stats = source_facts_ai.runtime_stats()
print("SECOND_PASS_STATS=" + json.dumps(stats, ensure_ascii=False, sort_keys=True))
if stats.get("calls_attempted") != 0:
    raise SystemExit(f"unexpected AI calls with AI disabled: {stats.get('calls_attempted')}")
# 497 items were the closeout corpus already cached before this verification.
# Additional misses are allowed only as delta beyond that corpus (new/changed
# source content arriving while the two-pass validation runs).
full = int(stats.get("items_fully_cached") or 0)
eligible = int(stats.get("items_eligible") or 0)
misses = int(stats.get("items_would_call") or 0)
if full < 497:
    raise SystemExit(f"historical cache regression: only {full}/497 full cache hits")
if full + misses != eligible:
    raise SystemExit(f"inconsistent cache accounting: full={full} misses={misses} eligible={eligible}")
if misses > max(0, eligible - 497):
    raise SystemExit(f"unexpected historical cache misses: full={full} misses={misses} eligible={eligible}")
print("SECOND_PASS_VERDICT=PASS historical=497 fully_cached new_or_changed=" + str(misses))
