#!/usr/bin/env python3
"""Benchmark read-only de profondeur du registre entreprise (5/10/20).

Une seule requête réseau est faite par organisation avec la profondeur maximale.
Les profondeurs inférieures sont simulées en tronquant la même liste ordonnée,
ce qui évite de tripler la charge sur l'API. Le matching utilisé est exactement
celui de production : égalité de nom normalisé et SIREN unique, aucun fuzzy.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import requests

from cyberwatch import config, org_enrichment, store

DEFAULT_DEPTHS = (5, 10, 20)


def evaluate_payload(
    query_name: str, payload: dict, depths=DEFAULT_DEPTHS
) -> dict[int, dict]:
    results = payload.get("results") if isinstance(payload, dict) else []
    results = results if isinstance(results, list) else []
    out: dict[int, dict] = {}
    for depth in depths:
        sliced = dict(payload) if isinstance(payload, dict) else {}
        sliced["results"] = results[:depth]
        status, candidate = org_enrichment._match(query_name, sliced)
        out[int(depth)] = {
            "status": status,
            "siren": str(candidate.get("siren") or "") if candidate else "",
        }
    return out


def query_names(source_id: str, max_queries: int) -> list[str]:
    matched_cache = {
        row.get("Organisation_Key", "")
        for row in store.load_org_enrichment_cache()
        if row.get("Match_Status") == org_enrichment.MATCHED
    }
    by_key: dict[str, str] = {}
    for item in store.load_items():
        if source_id and item.Source_ID != source_id:
            continue
        if not item.Organisation_Key or item.Organisation_Key in matched_cache:
            continue
        if item.Sector != config.SECTOR_UNKNOWN and item.Location != config.LOC_INCONNU:
            continue
        by_key.setdefault(item.Organisation_Key, item.Organisation_Raw)
    return [by_key[key] for key in sorted(by_key)][:max_queries]


def benchmark(
    names: list[str], timeout: float = 10.0, depths=DEFAULT_DEPTHS
) -> dict:
    max_depth = max(depths)
    rows: list[dict] = []
    errors: list[dict] = []
    started = time.monotonic()

    for index, name in enumerate(names, start=1):
        call_started = time.monotonic()
        try:
            response = requests.get(
                org_enrichment.ORG_ENRICHMENT_URL,
                params={"q": name, "per_page": max_depth},
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("JSON non objet")
            depth_results = evaluate_payload(name, payload, depths)
            rows.append({
                "query": name,
                "duration_s": round(time.monotonic() - call_started, 3),
                "depths": depth_results,
            })
        except (requests.RequestException, ValueError) as exc:
            errors.append({
                "query": name,
                "error": f"{type(exc).__name__}: {exc}",
            })
        print(f"ORG_DEPTH {index}/{len(names)} {name}", flush=True)

    counts: dict[str, dict] = {}
    for depth in depths:
        counts[str(depth)] = dict(Counter(
            row["depths"][int(depth)]["status"] for row in rows
        ))

    def transitions(target_depth: int) -> dict:
        counter: Counter = Counter()
        for row in rows:
            base = row["depths"][5]
            target = row["depths"][target_depth]
            if base == target:
                continue
            counter[f"{base['status']}->{target['status']}"] += 1
            if (
                base["status"] == target["status"] == org_enrichment.MATCHED
                and base["siren"] != target["siren"]
            ):
                counter["MATCHED_SIREN_CHANGED"] += 1
        return dict(counter)

    return {
        "queries_selected": len(names),
        "queries_completed": len(rows),
        "errors": errors,
        "depth_counts": counts,
        "transitions_vs_5": {
            str(depth): transitions(depth) for depth in depths if depth != 5
        },
        "duration_s": round(time.monotonic() - started, 3),
        "matching_policy": "exact_name_unique_siren_no_fuzzy",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", default="BONJOURLAFUITE")
    parser.add_argument("--max-queries", type=int, default=200)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", default="")
    args = parser.parse_args()

    names = query_names(args.source, max(0, args.max_queries))
    result = benchmark(names, timeout=args.timeout)
    text = json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2)
    print(text)
    if args.json:
        Path(args.json).write_text(text + "\n", encoding="utf-8")
    return 0 if not result["errors"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
