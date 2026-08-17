import json
import re
from pathlib import Path

from cyberwatch import store

TARGET = {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}
HEDGE = re.compile(r"\b(aurait|auraient|pourrait|pourraient|susceptible|susceptibles|potentiellement|probable|probablement|possible|possiblement|présumé|présumée|hypothèse|semblerait)\b", re.I)
RESPONSE = re.compile(r"\b(isol|remédi|restaur|notification|réinitial|investigation|enquête|confinement|débranch|déconnect|correctif|rotation des)\w*", re.I)

facts = [r for r in store.load_source_facts() if r.get("Source_ID") in TARGET]
incidents = json.loads(Path("assets/data/incidents.json").read_text(encoding="utf-8"))
bad_flow = []
bad_impact = []
summary_missing = []
initial_count = 0
enriched_ids = set()
for row in facts:
    if row.get("Initial_Access"):
        initial_count += 1
        enriched_ids.add(row["Item_ID"])
    flow = json.loads(row.get("Attack_Flow_JSON") or "[]")
    if flow:
        enriched_ids.add(row["Item_ID"])
    for step in flow:
        text = f"{step.get('action','')} {step.get('evidence','')}"
        if HEDGE.search(text) or RESPONSE.search(text):
            bad_flow.append((row["Item_ID"], text))
    impact = row.get("Impact") or ""
    if impact:
        enriched_ids.add(row["Item_ID"])
        if HEDGE.search(impact) or RESPONSE.search(impact):
            bad_impact.append((row["Item_ID"], impact))
    if (row.get("Initial_Access") or row.get("Attack_Flow_JSON") or row.get("Impact")) and not row.get("Summary"):
        summary_missing.append(row["Item_ID"])

published = {fact.get("item_id") for inc in incidents for fact in (inc.get("facts") or []) if fact.get("item_id")}
projection_gaps = sorted(enriched_ids - published)
stats = json.loads(Path("data/source_facts_ai_usage.json").read_text(encoding="utf-8"))
report = {
    "target_rows": len(facts),
    "summary_count": sum(bool(r.get("Summary")) for r in facts),
    "initial_access_count": initial_count,
    "attack_flow_count": sum(bool(r.get("Attack_Flow_JSON")) for r in facts),
    "impact_count": sum(bool(r.get("Impact")) for r in facts),
    "bad_flow": bad_flow,
    "bad_impact": bad_impact,
    "summary_missing_on_enriched": summary_missing,
    "projection_gaps": projection_gaps,
    "ai_usage": stats,
}
Path("audit").mkdir(exist_ok=True)
Path("audit/enrichment_closeout_final.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(report, ensure_ascii=False, indent=2))
if bad_flow or bad_impact or summary_missing or projection_gaps or initial_count < 1:
    raise SystemExit("closeout quality gate failed")
