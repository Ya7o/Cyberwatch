#!/usr/bin/env python3
import csv
import json
from pathlib import Path

OUT = Path("sources/veillellm")
TYPE_VALUES = {"Ransomware","DDoS","Malware","Compromission de compte / messagerie","Intrusion","Fuite de données","Phishing / fraude","Incident tiers","Autre cyber","Inconnu"}
SECTOR_VALUES = {"Administration / Collectivité","Santé","Éducation / Formation","Finance / Assurance","Transport / Logistique","Sport","Commerce / Distribution","Numérique / Technologie","Énergie / Utilities","Industrie / Manufacture","Construction / BTP","Services aux entreprises","Inconnu"}
COLS = ["date","organisation","territoire","localisation","secteur","type_menace","acteur","statut","score_cyberattaque","impact_connu","source_urls","synthese","evolution"]


def fix_incident(i):
    org = (i.get("organisation") or "").strip()
    low = org.lower()
    # Avoid the lexical false-positive 'moto' -> sport for motoculture businesses.
    if "motoculture" in low and i.get("secteur") == "Sport":
        i["secteur"] = "Inconnu"
    # Remove attack-description suffixes accidentally retained in organisation names.
    for suffix in (" menacé par un ransomware", " menace par un ransomware", " piraté", " pirate"):
        if low.endswith(suffix):
            org = org[: -len(suffix)].strip()
            i["organisation"] = org
            low = org.lower()
            break
    if i.get("secteur") not in SECTOR_VALUES:
        i["secteur"] = "Inconnu"
    if i.get("type_menace") not in TYPE_VALUES:
        i["type_menace"] = "Inconnu"
    if not i.get("territoire"):
        i["territoire"] = "Inconnu"
    return i


def run(stem):
    jp = OUT / f"{stem}.json"
    cp = OUT / f"{stem}.csv"
    data = json.loads(jp.read_text(encoding="utf-8"))
    incidents = [fix_incident(x) for x in data.get("incidents", [])]
    data["incidents"] = incidents
    data["metadata"]["record_count"] = len(incidents)
    data["metadata"]["canonical_validation"] = True
    jp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    with cp.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        for i in incidents:
            row = {k: i.get(k, "") for k in COLS if k != "source_urls"}
            row["source_urls"] = " | ".join(i.get("sources", []))
            w.writerow(row)


for stem in ("cyberattaque_org_2026", "frenchbreaches_2026"):
    run(stem)
