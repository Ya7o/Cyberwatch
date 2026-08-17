import json

from cyberwatch import config, enrichment, site, source_facts, source_facts_ai, sources, status, store, watchlists
from cyberwatch.http import Budget, HttpClient
from cyberwatch.runner import MODE_MAJ, make_run_context, run_source

context = make_run_context(MODE_MAJ, target_start="2026-01-01", layers=config.LAYER_GROUPS["core"])
client = HttpClient(run_budget=Budget(config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "fb-stable-cache"))
spec = sources.by_id("FRENCHBREACHES")
rows = []
outcome, collected, _ = run_source(
    client,
    spec,
    context,
    watchlists.known_organisations(),
    watchlists.entity_index(),
    watchlists.entity_territories(),
    enrichment.load_reference(),
    None,
    None,
    rows,
)
print(f"FRENCHBREACHES_FIRST: status={outcome.status} coverage={outcome.coverage}% items={len(collected)} facts={len(rows)}")
if outcome.status != status.OK or outcome.coverage < 100:
    raise SystemExit("FrenchBreaches incomplete")
existing_ids = {item.Item_ID for item in store.load_items()}
incoming = [row for row in rows if row.get("Item_ID") in existing_ids]
produced = {row.get("Item_ID") for row in incoming if row.get("Item_ID")}
for item in collected:
    if item.Item_ID in existing_ids and item.Item_ID not in produced:
        incoming.append({
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Summary": "",
            "Initial_Access": "",
            "Attack_Flow_JSON": "",
            "Impact": "",
            "Evidence_JSON": "",
        })
store.save_source_facts(source_facts.merge_source_facts(store.load_source_facts(), incoming))
source_facts_ai._flush_runtime()
print("FIRST_PASS_STATS=" + json.dumps(source_facts_ai.runtime_stats(), ensure_ascii=False, sort_keys=True))
site.build()
