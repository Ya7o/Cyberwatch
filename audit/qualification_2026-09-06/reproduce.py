"""Audit hors réseau, sans écriture du corpus ni appel LLM.

Exécuter depuis la racine : .venv/bin/python audit/qualification_2026-09-06/reproduce.py
Les cas adversariaux sont des contre-exemples, pas un échantillon statistique.
"""
from __future__ import annotations

import copy
import csv
import ast
import hashlib
import json
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from cyberwatch import config, dedup, enrichment, production, runner, sector_resolution, source_facts, sources, store
from cyberwatch.collectors.base import RawEntry
from cyberwatch.model import Item
from cyberwatch.normalize import classify_threat, classify_location
from cyberwatch.source_facts_ai_activity import normalize_activity


def item(**kwargs):
    values = dict(Item_ID="audit", Source_ID="CYBERATTAQUE_ORG", Organisation_Raw="Acme",
                  Organisation_Key="acme", Published_Date="2026-09-06",
                  Collected_As_Of="2026-09-06", Title="Acme victime d'une intrusion",
                  URL="https://example.test/acme", Sector=config.SECTOR_UNKNOWN,
                  Threat=config.THREAT_INTRUSION, Location=config.LOC_INCONNU)
    return Item(**{**values, **kwargs})


def finalize(items, facts=None):
    with patch.object(enrichment, "load_reference", return_value={}), \
         patch.object(store, "load_incident_id_registry", return_value=[]), \
         patch.object(store, "load_incident_dedup_registry", return_value=[]):
        return enrichment.finalize_snapshot(items, facts or [], previous_sector_rows=[])


def probes():
    result = []

    def record(case, expected, observed, detail=None):
        result.append(dict(case=case, expected=expected, observed=observed,
                           meets_expectation=expected == observed, detail=detail))

    text = "Acme : intrusion dans la messagerie, aucune fuite de données identifiée"
    seed = classify_threat(text)
    report = finalize([item(Title=text, Threat=seed)])
    record("T1_NEGATED_LEAK_REINTRODUCED", config.THREAT_INTRUSION,
           report.incidents[0].Menace, {"title": text, "initial": seed, "stabilized": report.items[0].Threat})

    text = "Acme : intrusion confirmée, aucun ransomware détecté"
    report = finalize([item(Title=text)])
    record("T2_NEGATED_RANSOMWARE", config.THREAT_INTRUSION, report.incidents[0].Menace, text)

    entry = RawEntry(title="Acme", organisation="Acme", published="2026-09-06",
                     summary="Acme est victime d'un ransomware avec exfiltration de données.",
                     threat=config.THREAT_LEAK, url="https://example.test/acme")
    converted = runner.entry_to_item(entry, sources.by_id("FRENCHBREACHES"), "2026-09-06", {}, {}, {}, {})
    initial = converted.Threat
    facts = [{"Item_ID": converted.Item_ID, "Summary": entry.summary, "Claim_Status": "reported"}]
    report = finalize([converted], facts)
    record("T3_RANSOMWARE_IN_SUMMARY_LOST", config.THREAT_RANSOMWARE, report.incidents[0].Menace,
           {"entry": asdict(entry), "initial": initial, "stabilized": report.items[0].Threat})

    text = "Acme : fuite de données, risque de phishing pour les clients"
    report = finalize([item(Title=text, Threat=config.THREAT_LEAK)])
    record("T4_LEAK_BEATS_DOWNSTREAM_PHISHING", config.THREAT_LEAK, report.incidents[0].Menace)

    text = "Acme : intrusion confirmée en France métropolitaine ; son prestataire est à La Réunion."
    converted = runner.entry_to_item(RawEntry(title="Acme victime d'une intrusion", organisation="Acme",
        summary=text, published="2026-09-06", url="https://example.test/acme"),
        sources.by_id("CYBERATTAQUE_ORG"), "2026-09-06", {}, {}, {}, {})
    record("L1_SUPPLIER_TERRITORY", config.LOC_FRANCE, finalize([converted]).incidents[0].Localisation, text)

    text = "Acme : fuite de 97400 comptes clients"
    record("L2_COUNT_AS_POSTAL_CODE", config.LOC_INCONNU, classify_location(text), text)

    fact = {"Item_ID": "audit", "Fine_Location": "Saint-Denis de La Réunion",
            "Evidence_JSON": json.dumps({"Fine_Location": "L'incident Acme touche exclusivement le site de Saint-Denis de La Réunion."})}
    report = finalize([item(Source_ID="FRENCHBREACHES", Location=config.LOC_FRANCE)], [fact])
    record("L3_FINE_LOCATION_NOT_PROPAGATED", config.LOC_REUNION, report.incidents[0].Localisation, fact)

    loc_items = [item(Item_ID="a", Source_ID="FRENCHBREACHES", Location=config.LOC_FRANCE),
                 item(Item_ID="b", Source_ID="BONJOURLAFUITE", Location=config.LOC_MAYOTTE,
                      URL="https://example.test/acme-2")]
    incidents = dedup.build_incidents(loc_items)
    record("L4_CONFLICT_LOCATION_LEXICAL_TIE", config.LOC_INCONNU, incidents[0].Localisation,
           {"incidents": len(incidents), "items_in_incident": incidents[0].Items_Count,
            "values": [i.Location for i in loc_items]})

    context = "Acme commercialise en ligne des chaussures."
    raw = {"activity_description": {"value": "éditeur de logiciels", "confidence": .95, "evidence": context},
           "activity_sector_match": {"value": config.SECTOR_TECH, "confidence": .95, "evidence": context}}
    normalized, rejections = normalize_activity(raw, context, "Acme")
    fact = {"Item_ID": "audit", "Activity_Description": normalized.get("activity_description", {}).get("value", ""),
            "Activity_Sector_Match": normalized.get("activity_sector_match", {}).get("value", ""),
            "Evidence_JSON": json.dumps({"Activity_Description": context})}
    report = finalize([item()], [fact])
    record("S1_QUOTE_DOES_NOT_SUPPORT_ACTIVITY", config.SECTOR_RETAIL, report.incidents[0].Secteur,
           {"raw": raw, "normalized": normalized, "rejections": rejections})

    fact = {"Item_ID": "audit", "Source_Sector_Raw": "Manufacturing",
            "Activity_Description": "éditeur de logiciels", "Activity_Sector_Match": config.SECTOR_TECH,
            "Evidence_JSON": json.dumps({"Activity_Description": "Le fournisseur AcmeSoft édite des logiciels."})}
    report = finalize([item(Sector=config.SECTOR_INDUSTRY)], [fact])
    record("S2_BAD_ACTIVITY_SUPPRESSES_NATIVE_SECTOR", config.SECTOR_INDUSTRY, report.incidents[0].Secteur,
           report.sector_resolution_rows)

    fact = {"Item_ID": "audit", "Activity_Description": "vente en ligne de chaussures",
            "Activity_Sector_Match": config.SECTOR_RETAIL,
            "Evidence_JSON": json.dumps({"Activity_Description": "Acme commercialise en ligne des chaussures."})}
    report = finalize([item()], [fact])
    record("S3_VALID_ACTIVITY_TRANSPORT", config.SECTOR_RETAIL, report.incidents[0].Secteur)

    original = item(Title="Acme victime d'une intrusion", Location=config.LOC_FRANCE)
    previous = finalize([copy.deepcopy(original)])
    changed_facts = [{"Item_ID": "audit", "Summary": "Acme est victime d'une fuite de données.", "Claim_Status": "reported"}]
    updated = finalize([copy.deepcopy(original)], changed_facts)
    record("R1_EXISTING_ITEMS_ARE_REQUALIFIED", True,
           previous.incidents[0].Menace != updated.incidents[0].Menace,
           {"before": previous.incidents[0].Menace, "after": updated.incidents[0].Menace})

    old = {"Item_ID": "audit", "Activity_Description": "vente en ligne de chaussures",
           "Activity_Sector_Match": config.SECTOR_RETAIL,
           "Evidence_JSON": json.dumps({"Activity_Description": "Acme commercialise en ligne des chaussures."}),
           "Source_Metadata_JSON": json.dumps({"_source_facts_content_hash": "A"})}
    def empty_revision(status):
        return {"Item_ID": "audit", "Activity_Description": "", "Activity_Sector_Match": "",
                "Source_Metadata_JSON": json.dumps({"_source_facts_content_hash": "B",
                    "_source_facts_semantic_status": {"activity_description": status, "activity_sector_match": status}})}
    first = source_facts.merge_source_facts([old], [empty_revision("miss")])
    second = source_facts.merge_source_facts(first, [empty_revision("abstained")])
    sanitized, _ = source_facts.sanitize_source_facts(second)
    report = finalize([item()], sanitized)
    record("R2_STALE_ACTIVITY_AFTER_SECOND_MISS", "", second[0].get("Activity_Description"),
           {"first": first, "second": second, "final_sector": report.incidents[0].Secteur})
    return result


def snapshot():
    items, incidents = store.load_items(), store.load_incidents()
    facts, decisions = store.load_source_facts(), store.load_sector_resolution()
    reference = enrichment.load_reference()
    fresh = copy.deepcopy(items)
    for observation in fresh:
        observation.Sector = config.SECTOR_UNKNOWN
    no_ref = sector_resolution.resolve_items(fresh, facts, {}, previous_rows=[])
    no_ref_incidents, _ = dedup.build_incidents_with_registry(
        fresh, store.load_incident_id_registry(), store.load_incident_dedup_registry(), facts)
    return {
        "items": len(items), "incidents": len(incidents), "source_facts": len(facts),
        "dates": {"first": min(i.Published_Date for i in items), "last": max(i.Published_Date for i in items)},
        "items_by_source": dict(Counter(i.Source_ID for i in items)),
        "sector_incidents": dict(Counter(i.Secteur for i in incidents)),
        "threat_incidents": dict(Counter(i.Menace for i in incidents)),
        "location_incidents": dict(Counter(i.Localisation for i in incidents)),
        "sector_decision_reasons": dict(Counter(r.get("Reason") for r in decisions)),
        "sector_decision_statuses": dict(Counter(r.get("Status") for r in decisions)),
        "sector_without_reference_or_legacy_item_values": {
            "note": "Ablation des références exactes et des anciens secteurs ; watchlists et règles nominatives conservées. Ce n'est pas une prévision.",
            "reasons": dict(Counter(r["Reason"] for r in no_ref)),
            "unknown_items": sum(i.Sector == config.SECTOR_UNKNOWN for i in fresh),
            "incidents": len(no_ref_incidents),
            "unknown_incidents": sum(i.Secteur == config.SECTOR_UNKNOWN for i in no_ref_incidents),
        },
        "fine_locations": [{"item_id": f["Item_ID"], "location": f.get("Fine_Location")} for f in facts if f.get("Fine_Location")],
        "sector_transport_gaps": sector_resolution.fact_transport_gaps(items, facts, reference),
        "business_corpus": production.evaluate_business_corpus(),
        "active_sources": [{"id": s.source_id, "threat_default": s.default_threat,
                            "location_default": s.location_rule} for s in sources.active_sources(config.LAYER_GROUPS["all"])],
    }


def cache_stats():
    payload = json.loads((ROOT / "data/source_facts_ai_cache.json").read_text())
    entries = list(payload.get("entries", {}).values())
    result = {"entries": len(entries), "fields": {}}
    for name in ("activity_description", "activity_sector_match", "fine_location", "summary", "threat_candidate"):
        result["fields"][name] = dict(Counter(e.get("fields", {}).get(name, {}).get("status", "missing") for e in entries))
    for filename in ("source_facts_ai_usage.json", "llm_usage.json"):
        path = ROOT / "data" / filename
        if path.exists():
            result[filename] = json.loads(path.read_text())
    return result


def public_stats():
    directory = Path(__file__).with_name("public")
    if not directory.exists():
        return {}
    records = list(csv.DictReader((directory / "main/data/incidents.csv").open(encoding="utf-8-sig")))
    page = json.loads((directory / "pages/incidents.json").read_text())
    rows = page if isinstance(page, list) else page.get("incidents", [])
    status = json.loads((directory / "pages/status.json").read_text())
    identical = {}
    for module, names in {"enrichment.py": ["stabilize_threats"],
                          "normalize.py": ["classify_location", "_location_from_text"]}.items():
        def definitions(path):
            return {node.name: ast.dump(node) for node in ast.parse(path.read_text()).body if isinstance(node, ast.FunctionDef)}
        local = definitions(ROOT / "cyberwatch" / module)
        remote = definitions(directory / "main/cyberwatch" / module)
        identical.update({module + ":" + name: local.get(name) == remote.get(name) for name in names})
    return {"main_incidents": len(records),
            "main_sectors": dict(Counter(r["Secteur"] for r in records)),
            "main_threats": dict(Counter(r["Menace"] for r in records)),
            "main_locations": dict(Counter(r["Localisation"] for r in records)),
            "pages_type": type(page).__name__, "pages_keys": list(page)[:15] if isinstance(page, dict) else [],
            "pages_count": len(rows), "pages_sectors": dict(Counter(r.get("sector", "missing") for r in rows)),
            "identical_function_asts_local_and_remote": identical,
            "status": {"as_of": status.get("analytics", {}).get("as_of"),
                       "coverage": status.get("analytics", {}).get("coverage")}}


def main():
    tracked = [*sorted((ROOT / "cyberwatch").rglob("*.py")),
               ROOT / ".github/workflows/collect.yml", ROOT / "validation/business_corpus.json",
               *(ROOT / "data" / name for name in ("items.csv", "incidents.csv", "source_facts.csv", "sector_resolution.csv", "enrichment_reference.csv"))]
    report = {"scope": "working_tree_local_offline", "snapshot": snapshot(), "probes": probes(), "public": public_stats(),
              "cache": cache_stats(), "sha256": {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}}
    destination = Path(__file__).with_name("evidence.json")
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"snapshot": report["snapshot"], "probes": report["probes"], "public": report["public"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
