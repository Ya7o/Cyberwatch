#!/usr/bin/env python3
"""Audit offline déterministe des champs de qualité ITEMS."""
from __future__ import annotations
import argparse, csv, hashlib, json, random, re
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import config
from cyberwatch.enrichment import _UNKNOWN_LEAK_MARKERS
from cyberwatch.normalize import classify_threat, searchable

FIELDS = ("Organisation_Raw", "Organisation_Key", "Threat", "Sector", "Location")
UNKNOWN = "Inconnu"

def load(path):
    return list(csv.DictReader(Path(path).open(encoding="utf-8", newline="")))

def key(row):
    return (row["Source_ID"], row["Source_Item_ID"]) if row.get("Source_Item_ID") else (row["Source_ID"], row["URL"], row["Published_Date"])

def summary(rows):
    sources=defaultdict(list)
    for row in rows: sources[row["Source_ID"]].append(row)
    def stats(values):
        return {"items":len(values), "threat_unknown":sum(r["Threat"]==UNKNOWN for r in values), "sector_unknown":sum(r["Sector"]==UNKNOWN for r in values), "location_unknown":sum(r["Location"]==UNKNOWN for r in values), "organisation_empty":sum(not r["Organisation_Raw"] for r in values)}
    aggregate = re.compile(r"\b\d+\s+(?:sdis|agences?|écoles?|ecoles?|hôpitaux?|hopitaux?)\b", re.I)
    return {"global":stats(rows), "sources":{s:stats(v) for s,v in sorted(sources.items())}, "threat":dict(sorted(Counter(r["Threat"] for r in rows).items())), "sector":dict(sorted(Counter(r["Sector"] for r in rows).items())), "location":dict(sorted(Counter(r["Location"] for r in rows).items())), "aggregates":sorted({r["Organisation_Raw"] for r in rows if any(x in r["Organisation_Raw"].lower() for x in ("&", "/", " et ")) or aggregate.search(r["Organisation_Raw"] or "")})}

def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

def diff(before, after):
    old={key(r):r for r in before}; new={key(r):r for r in after}; changes=[]
    added=[]
    removed=[]
    for value in sorted(set(new) - set(old)):
        row = new[value]
        added.append({"key": value, "status": "ADDED", "source": row["Source_ID"], "source_item_id": row["Source_Item_ID"], "published": row["Published_Date"], "organisation": row["Organisation_Raw"], "title": row["Title"]})
    for value in sorted(set(old) - set(new)):
        row = old[value]
        removed.append({"key": value, "status": "REMOVED", "source": row["Source_ID"], "source_item_id": row["Source_Item_ID"], "published": row["Published_Date"], "organisation": row["Organisation_Raw"], "title": row["Title"]})
    for k in sorted(set(old)&set(new)):
        for field in FIELDS:
            if old[k][field]!=new[k][field]: changes.append({"key":k,"source":old[k]["Source_ID"],"source_item_id":old[k]["Source_Item_ID"],"published":old[k]["Published_Date"],"organisation":old[k]["Organisation_Raw"],"title":old[k]["Title"],"field":field,"before":old[k][field],"after":new[k][field]})
    return changes, added, removed


def run_audit(rows, before_rows=None):
    """Return the complete, order-independent audit payload."""
    result = summary(rows)
    if before_rows is not None:
        changes, added, removed = diff(before_rows, rows)
        result["changes"] = changes
        result["added"] = added
        result["removed"] = removed
        result["added_rows"] = len(added)
        result["removed_rows"] = len(removed)
        result["changed_rows"] = len({tuple(change["key"]) for change in changes})
        for field in FIELDS:
            result[f"changed_{field.lower()}"] = sum(change["field"] == field for change in changes)
    return result


def threat_backfill_candidates(rows):
    """Observe the existing unknown-threat backfill without writing data."""
    candidates = []
    for row in rows:
        if row.get("Threat") != UNKNOWN:
            continue
        direct = classify_threat(row.get("Title", ""), row.get("Threat_Raw", ""))
        candidate = direct
        reason = "classify_threat"
        if candidate == config.THREAT_UNKNOWN:
            markers = [marker for marker in _UNKNOWN_LEAK_MARKERS if marker in searchable(row.get("Title", ""))]
            if markers:
                candidate = config.THREAT_LEAK
                reason = "title_markers=" + ",".join(markers)
        if candidate != config.THREAT_UNKNOWN:
            candidates.append({
                "source_id": row.get("Source_ID", ""),
                "source_item_id": row.get("Source_Item_ID", ""),
                "organisation": row.get("Organisation_Raw", ""),
                "title": row.get("Title", ""),
                "threat_before": row.get("Threat", ""),
                "threat_candidate": candidate,
                "reason": reason,
            })
    return sorted(candidates, key=lambda value: (value["source_id"], value["source_item_id"], value["title"]))

def main():
    p=argparse.ArgumentParser();p.add_argument('--items');p.add_argument('--before');p.add_argument('--after');p.add_argument('--check',action='store_true');p.add_argument('--metrics', action='store_true');a=p.parse_args()
    if bool(a.before) != bool(a.after):
        p.error("--before et --after doivent être fournis ensemble")
    rows=load(a.items or a.after)
    before_rows = load(a.before) if a.before else None
    result=run_audit(rows, before_rows)
    result["threat_backfill_candidates"] = threat_backfill_candidates(rows)
    result["threat_backfill_candidates_total"] = len(result["threat_backfill_candidates"])
    blob=canonical(result); digest=hashlib.sha256(blob.encode()).hexdigest(); print(blob); print('audit_hash='+digest)
    if a.metrics:
        for name, value in result["global"].items():
            print(f"{name}={value}")
        for name in ("added_rows", "removed_rows", "changed_rows") + tuple(f"changed_{field.lower()}" for field in FIELDS):
            if name in result:
                print(f"{name}={result[name]}")
    if a.check:
        shuffled=list(rows); random.Random(42).shuffle(shuffled)
        shuffled_result = run_audit(shuffled, before_rows)
        shuffled_result["threat_backfill_candidates"] = threat_backfill_candidates(shuffled)
        shuffled_result["threat_backfill_candidates_total"] = len(shuffled_result["threat_backfill_candidates"])
        if canonical(shuffled_result)!=canonical(result): raise SystemExit('audit non déterministe')
        print('check=PASS')
if __name__=='__main__': main()
