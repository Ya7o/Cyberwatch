from cyberwatch import site, source_facts, store

TARGET_SOURCES = {"FRENCHBREACHES", "CYBERATTAQUE_ORG"}

rows = store.load_source_facts()
before = sum(1 for row in rows if row.get("Source_ID") in TARGET_SOURCES and str(row.get("Summary") or "").strip())
changed = 0
for row in rows:
    if row.get("Source_ID") not in TARGET_SOURCES or str(row.get("Summary") or "").strip():
        continue
    evidence = source_facts._loads_json(str(row.get("Evidence_JSON") or "")) or {}
    source_facts._derive_summary(row, evidence)
    if str(row.get("Summary") or "").strip():
        row["Evidence_JSON"] = source_facts._dumps_json(evidence)
        changed += 1

store.save_source_facts(rows)
site.build()
after = sum(1 for row in rows if row.get("Source_ID") in TARGET_SOURCES and str(row.get("Summary") or "").strip())
print(f"STRUCTURED_SUMMARY_MIGRATION before={before} added={changed} after={after}")
if after < before or changed <= 0:
    raise SystemExit("structured summary migration produced no useful additions")
