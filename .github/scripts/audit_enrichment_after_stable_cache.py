import json
import re
from pathlib import Path

from cyberwatch import store

TARGET = {"CYBERATTAQUE_ORG", "FRENCHBREACHES"}
HEDGE = re.compile(r"\b(aurait|auraient|pourrait|pourraient|susceptible|susceptibles|potentiellement|probable|probablement|possible|possiblement|présumé|présumée|hypothèse|semblerait)\b", re.I)
RESPONSE = re.compile(r"\b(isol|remédi|restaur|notification|réinitial|investigation|enquête|confinement|débranch|déconnect|correctif|rotation des)\w*", re.I)
facts = [row for row in store.load_source_facts() if row.get("Source_ID") in TARGET]
incidents = json.loads(Path("assets/data/incidents.json").read_text(encoding="utf-8"))
bad_flow = []
bad_impact = []
missing_summary = []
enriched = set()
for row in facts:
    flow = json.loads(row.get("Attack_Flow_JSON") or "[]")
    if row.get("Initial_Access") or flow or row.get("Impact"):
        enriched.add(row["Item_ID"])
    for step in flow:
        text = f"{step.get('action','')} {step.get('evidence','')}"
        if HEDGE.search(text) or RESPONSE.search(text):
            bad_flow.append(row["Item_ID"])
    impact = row.get("Impact") or ""
    if impact and (HEDGE.search(impact) or RESPONSE.search(impact)):
        bad_impact.append(row["Item_ID"])
    if (row.get("Initial_Access") or flow or impact) and not row.get("Summary"):
        missing_summary.append(row["Item_ID"])
published = {fact.get("item_id") for inc in incidents for fact in (inc.get("facts") or []) if fact.get("item_id")}
report = {
    "target_rows": len(facts),
    "summary_count": sum(bool(row.get("Summary")) for row in facts),
    "initial_access_count": sum(bool(row.get("Initial_Access")) for row in facts),
    "attack_flow_count": sum(bool(row.get("Attack_Flow_JSON")) for row in facts),
    "impact_count": sum(bool(row.get("Impact")) for row in facts),
    "bad_flow": bad_flow,
    "bad_impact": bad_impact,
    "summary_missing_on_enriched": missing_summary,
    "projection_gaps": sorted(enriched - published),
}
Path("audit/enrichment_closeout_final.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
print(json.dumps(report, ensure_ascii=False, indent=2))
if bad_flow or bad_impact or missing_summary or report["projection_gaps"] or report["initial_access_count"] < 1:
    raise SystemExit("closeout regression")
