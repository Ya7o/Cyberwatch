import csv
import io
import json
import subprocess

from cyberwatch import config, enrichment, site, source_facts, source_facts_ai, sources, status, store, watchlists
from cyberwatch.http import Budget, HttpClient
from cyberwatch.runner import MODE_MAJ, make_run_context, run_source

TARGET_SOURCES = ("FRENCHBREACHES", "CYBERATTAQUE_ORG")
BASELINE_SHA = "580e0a42353a7bbff5ec8406a1d601696d96c29e"

existing_items = store.load_items()
existing_ids = {item.Item_ID for item in existing_items}
context = make_run_context(MODE_MAJ, target_start="2026-01-01", layers=config.LAYER_GROUPS["core"])
client = HttpClient(run_budget=Budget(config.MAX_REQUESTS_PER_RUN, config.MAX_SECONDS_PER_RUN, "source-facts-closeout"))
known_orgs = watchlists.known_organisations()
entity_index = watchlists.entity_index()
territories = watchlists.entity_territories()
reference = enrichment.load_reference()

incoming = []
for source_id in TARGET_SOURCES:
    spec = sources.by_id(source_id)
    if spec is None:
        raise SystemExit(f"source missing: {source_id}")
    rows = []
    outcome, collected_items, _ = run_source(
        client, spec, context, known_orgs, entity_index, territories, reference,
        None, None, rows,
    )
    print(f"{source_id}: {outcome.status} coverage={outcome.coverage}% items={len(collected_items)} facts={len(rows)}")
    if outcome.status != status.OK or outcome.coverage < 100:
        raise SystemExit(f"source incomplete: {source_id} {outcome.status} {outcome.coverage}")

    filtered_rows = [row for row in rows if row.get("Item_ID") in existing_ids]
    incoming.extend(filtered_rows)
    produced_ids = {row.get("Item_ID") for row in filtered_rows if row.get("Item_ID")}
    reviewed = [item for item in collected_items if item.Item_ID in existing_ids]
    cleared = []
    for item in reviewed:
        if item.Item_ID in produced_ids:
            continue
        # The source item was successfully reviewed but no longer produces a
        # SourceFact. Send a minimal authoritative row so refreshable semantic
        # fields are cleared while merge_source_facts preserves legacy facts.
        incoming.append({
            "Item_ID": item.Item_ID,
            "Source_ID": item.Source_ID,
            "Summary": "",
            "Initial_Access": "",
            "Attack_Flow_JSON": "",
            "Impact": "",
            "Evidence_JSON": "",
        })
        cleared.append(item.Item_ID)
    if cleared:
        print(f"{source_id}: stale semantic enrichments cleared for {cleared}")

merged = source_facts.merge_source_facts(store.load_source_facts(), incoming)

# Restore any non-refreshable facts that the previous backfill accidentally erased.
baseline_text = subprocess.check_output(["git", "show", f"{BASELINE_SHA}:data/source_facts.csv"], text=True)
baseline = {row["Item_ID"]: row for row in csv.DictReader(io.StringIO(baseline_text)) if row.get("Item_ID")}
by_id = {row.get("Item_ID"): row for row in merged if row.get("Item_ID")}
refreshable = {"Summary", "Initial_Access", "Attack_Flow_JSON", "Impact"}
base_cols = {"Item_ID", "Source_ID", "Extraction_Method", "Extraction_Version", "Source_Metadata_JSON", "Evidence_JSON"}
recovered = []
for item_id, current in by_id.items():
    old = baseline.get(item_id)
    if not old:
        continue
    current_e = json.loads(current.get("Evidence_JSON") or "{}") if current.get("Evidence_JSON") else {}
    old_e = json.loads(old.get("Evidence_JSON") or "{}") if old.get("Evidence_JSON") else {}
    changed = False
    for col, old_value in old.items():
        if col in refreshable or col in base_cols or not old_value or current.get(col):
            continue
        current[col] = old_value
        if isinstance(old_e, dict) and col in old_e:
            current_e[col] = old_e[col]
        changed = True
    if changed:
        current["Evidence_JSON"] = json.dumps(current_e, ensure_ascii=False, sort_keys=True, separators=(",", ":")) if current_e else ""
        recovered.append(item_id)
print("legacy facts recovered:", recovered)

store.save_source_facts([by_id[key] for key in sorted(by_id)])
source_facts_ai._flush_runtime()
print("AI stats:", json.dumps(source_facts_ai.runtime_stats(), ensure_ascii=False, sort_keys=True))
site.build()
