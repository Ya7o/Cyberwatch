#!/usr/bin/env python3
"""Mesure la précision Golden de chaque canal du registre Sector."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import enrichment, sector_registry, store
from cyberwatch.golden import read_csv
from cyberwatch.golden_review import apply_audit, validate_audit


def effective_golden() -> list[dict]:
    golden_path = ROOT / "data" / "golden" / "qualification_golden.csv"
    audit_path = ROOT / "data" / "golden" / "qualification_golden_audit.csv"
    rows = read_csv(golden_path)
    if audit_path.exists():
        audit = read_csv(audit_path)
        problems = validate_audit(audit, rows)
        if problems:
            raise SystemExit("audit golden invalide: " + "; ".join(problems))
        rows = apply_audit(rows, audit)
    return [row for row in rows if (row.get("Review_Status") or "") != "REVIEW"]


def evaluate() -> dict:
    items = store.load_items()
    provenance = store.load_qualification_provenance()
    registry = sector_registry.build_registry(
        items,
        enrichment.load_reference(),
        source_fact_rows=store.read_csv(store.SOURCE_FACTS_CSV),
        org_cache_rows=store.load_org_enrichment_cache(),
        previous_provenance=provenance,
    )
    golden = {
        row.get("Organisation_Key", ""): row
        for row in effective_golden()
        if row.get("Organisation_Key") and row.get("Secteur_REF")
    }

    stats: dict[str, dict[str, int]] = defaultdict(
        lambda: {"cases": 0, "correct": 0, "wrong": 0}
    )
    details: list[dict] = []
    for row in registry:
        sector = row.get("Sector", "")
        if not sector or sector == "Inconnu" or row.get("Decision") == sector_registry.DECISION_CONFLICT:
            continue
        reference = golden.get(row.get("Organisation_Key", ""))
        if reference is None:
            continue
        channel = row.get("Evidence_Type", "") or "unknown"
        expected = reference.get("Secteur_REF", "")
        correct = sector == expected
        stats[channel]["cases"] += 1
        stats[channel]["correct" if correct else "wrong"] += 1
        details.append({
            "Organisation_Key": row.get("Organisation_Key", ""),
            "Organisation": row.get("Organisation", ""),
            "Channel": channel,
            "Candidate": sector,
            "Expected": expected,
            "Correct": correct,
            "Registry_Decision": row.get("Decision", ""),
        })

    channels = {}
    policy = sector_registry.load_policy()
    for channel in sorted(set(stats) | set((policy.get("channels") or {}).keys())):
        values = stats[channel]
        cases = values["cases"]
        precision = (values["correct"] / cases * 100.0) if cases else 0.0
        cfg = (policy.get("channels") or {}).get(channel) or {}
        channels[channel] = {
            **values,
            "precision_pct": round(precision, 2),
            "enabled": bool(cfg.get("enabled", False)),
            "requires_golden": bool(cfg.get("requires_golden", True)),
        }

    return {
        "schema_version": 1,
        "minimum_precision_pct": float(policy.get("minimum_precision_pct", 95.0)),
        "minimum_cases": int(policy.get("minimum_cases", 10)),
        "channels": channels,
        "details": details,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", default="")
    args = parser.parse_args()
    result = evaluate()
    print("SECTOR REGISTRY GOLDEN")
    for channel, metrics in result["channels"].items():
        print(
            f"{channel}: enabled={metrics['enabled']} cases={metrics['cases']} "
            f"correct={metrics['correct']} wrong={metrics['wrong']} "
            f"precision={metrics['precision_pct']:.2f}%"
        )
    if args.json:
        target = Path(args.json)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"json={target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
