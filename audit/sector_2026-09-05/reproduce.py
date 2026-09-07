"""Audit hors ligne du snapshot de production figé au 5 septembre 2026.

Ne modifie ni le corpus canonique ni le cache et n'appelle aucun LLM.
Exécuter avec le Python du projet ; la sortie JSON est écrite sur stdout.
"""
import csv
import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent
PROD = ROOT / "production"
os.environ["SOURCE_FACTS_AI_ENABLED"] = "0"
sys.path.insert(0, str(PROD))
from cyberwatch import config, sector, source_facts, source_facts_ai, llm_runtime, enrichment
from cyberwatch.model import Item


def read_csv(name):
    with (PROD / "data" / name).open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


items = read_csv("items.csv")
facts = {row["Item_ID"]: row for row in read_csv("source_facts.csv")}
incidents = json.loads((PROD / "assets/data/incidents.json").read_text())
cache = json.loads((PROD / "data/source_facts_ai_cache.json").read_text())["entries"]
unknown = [row for row in items if row["Sector"] == "Inconnu"]
traces = []
for item in unknown:
    fact = facts.get(item["Item_ID"], {})
    metadata = json.loads(fact.get("Source_Metadata_JSON") or "{}")
    content_hash = metadata.get("_source_facts_content_hash")
    entries = [
        {"cache_key": key, "model_label": value.get("model"),
         "content_hash": value.get("content_hash"),
         "fields": {k: v for k, v in value.get("fields", {}).items() if k.startswith("activity_")}}
        for key, value in cache.items()
        if value.get("item_id") == item["Item_ID"] and value.get("content_hash") == content_hash
    ]
    traces.append({
        "item_id": item["Item_ID"], "organisation": item["Organisation_Raw"],
        "published_date": item["Published_Date"], "source": item["Source_ID"], "url": item["URL"],
        "sector": item["Sector"], "activity": fact.get("Activity_Description", ""),
        "activity_sector": fact.get("Activity_Sector_Match", ""),
        "evidence": {k: v for k, v in json.loads(fact.get("Evidence_JSON") or "{}").items() if k.startswith("Activity_")},
        "semantic_status": {k: v for k, v in metadata.get("_source_facts_semantic_status", {}).items() if k.startswith("activity_")},
        "cache": entries,
    })

# Reproductions déterministes : ces réponses sont des fixtures explicites,
# jamais présentées comme le retour brut historique (non conservé).
sentence = "ZeroGaspi commercialise en ligne des produits destinés notamment à réduire le gaspillage et les déchets."
partial = "commercialise en ligne des produits destinés notamment à réduire le gaspillage et les déchets."
fixture = {
    "activity_description": {"value": "vente en ligne de produits anti-gaspillage", "evidence": partial, "confidence": 0.9},
    "activity_sector_match": {"value": config.SECTOR_RETAIL, "evidence": sentence, "confidence": 0.9},
}
fields = set(fixture)
normalized_partial = source_facts_ai._normalize(fixture, sentence, fields, "ZeroGaspi")
fixture["activity_description"]["evidence"] = sentence
normalized_full = source_facts_ai._normalize(fixture, sentence, fields, "ZeroGaspi")

runtime = SimpleNamespace(cache={}, model="audit-fixture", semantic_retries=0,
    semantic_recovered_on_retry=0, semantic_first_misses=0, semantic_new_abstentions=0)
# Précréer l'entrée évite toute dépendance au hash d'une RawEntry pour ce test unitaire.
runtime.cache["fixture"] = {"fields": {}}
source_facts_ai._store_field_cache(runtime, "fixture", None, None, fields, normalized_partial)
assert "activity_description" not in normalized_partial
assert "activity_description" in normalized_full
assert runtime.cache["fixture"]["fields"]["activity_description"]["misses"] == 2

recent_incidents = [i for i in incidents if i["date"] >= "2026-09-03"]
replayed = enrichment.finalize_snapshot([Item.from_row(i) for i in items])
replayed_items = {i.Item_ID: i for i in replayed.items}
ignored_ids = [t["item_id"] for t in traces if t["activity"] and t["activity_sector"]]
assert all(replayed_items[i].Sector == "Inconnu" for i in ignored_ids)
report = {
    "production_sha": json.loads((ROOT / "head.json").read_text())["sha"],
    "published_equals_repository": (ROOT / "sources/published_incidents.json").read_bytes() == (PROD / "assets/data/incidents.json").read_bytes(),
    "counts": {
        "items": len(items), "unknown_items": len(unknown),
        "incidents": len(incidents), "unknown_incidents": sum(i["sector"] == "Inconnu" for i in incidents),
        "recent_incidents": len(recent_incidents), "recent_unknown_incidents": sum(i["sector"] == "Inconnu" for i in recent_incidents),
        "unknown_items_with_materialized_activity_and_sector": sum(bool(t["activity"] and t["activity_sector"]) for t in traces),
        "replayed_materialized_activity_still_unknown": sum(replayed_items[i].Sector == "Inconnu" for i in ignored_ids),
    },
    "recent_incidents": recent_incidents,
    "unknown_incidents": [i for i in incidents if i["sector"] == "Inconnu"],
    "unknown_item_traces": traces,
    "reproductions": {
        "fixture_partial_evidence_normalized": normalized_partial,
        "fixture_full_evidence_normalized": normalized_full,
        "fixture_after_one_store": runtime.cache["fixture"],
        "deterministic_activity_zerogaspi": source_facts._extract_victim_activity("ZeroGaspi", sentence),
        "deterministic_sector_full_sentence_zerogaspi": sector.classify_sector_activity(sentence),
        "deterministic_cma_name": sector.classify_sector_name("Chambre de Métiers et de l’Artisanat d’Occitanie"),
        "deterministic_cma_activity": sector.classify_sector_activity("Chambre de Métiers et de l’Artisanat."),
        "effective_source_facts_model_default_routing": llm_runtime.model_for_task("source_facts", "gpt-5-nano"),
    },
}
print(json.dumps(report, ensure_ascii=False, indent=2))
