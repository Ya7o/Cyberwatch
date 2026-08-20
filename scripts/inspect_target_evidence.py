#!/usr/bin/env python3
"""Diagnostic CI des cas terrain historiques à surveiller."""
from __future__ import annotations

import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("sde 03", "bija industrie", "samboat", "eva", "kpark", "k par k", "chupin", "clenet")


def main() -> int:
    items_path = ROOT / "data" / "items.csv"
    facts_path = ROOT / "data" / "source_facts.csv"
    cache_path = ROOT / "data" / "org_enrichment_cache.csv"

    items = list(csv.DictReader(items_path.open(encoding="utf-8"))) if items_path.exists() else []
    facts = list(csv.DictReader(facts_path.open(encoding="utf-8"))) if facts_path.exists() else []
    cache = list(csv.DictReader(cache_path.open(encoding="utf-8"))) if cache_path.exists() else []

    facts_by = {}
    for row in facts:
        facts_by.setdefault(row.get("Item_ID", ""), []).append(row)

    print("TARGET_EVIDENCE_START")
    for item in items:
        name = (item.get("Organisation_Raw") or "").lower().replace("–", "-")
        if not any(target in name for target in TARGETS):
            continue
        print("ITEM", {key: item.get(key, "") for key in ("Item_ID", "Source_ID", "Organisation_Raw", "Organisation_Key", "Sector", "Title", "URL")})
        for fact in facts_by.get(item.get("Item_ID", ""), []):
            print("FACT", {key: fact.get(key, "") for key in ("Source_Sector_Raw", "Activity_Description", "Victim_Website", "Summary", "Evidence_JSON", "Source_Metadata_JSON")})
        key = item.get("Organisation_Key", "")
        for row in cache:
            if (row.get("Organisation_Key") or "") == key:
                print("CACHE", {field: row.get(field, "") for field in ("Match_Status", "Validated_Sector", "Validated_Via", "Activity_Label", "Evidence_URL", "Evidence_Source")})
    print("TARGET_EVIDENCE_END")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
