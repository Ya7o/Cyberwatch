#!/usr/bin/env python3
"""Produit une baseline qualification et peut exécuter la requalification offline."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import site, store
from cyberwatch.golden import read_csv
from cyberwatch.golden_review import apply_audit, validate_audit
from cyberwatch.qualification import qualify
from cyberwatch.qualification_baseline import build_report, golden_reference_by_anchor
from cyberwatch.qualification_decision import decisions_from_provenance
from cyberwatch.runner import save_snapshot_provenance


def reviewed_golden() -> list[dict[str, str]]:
    golden_path = ROOT / "data" / "golden" / "qualification_golden.csv"
    audit_path = ROOT / "data" / "golden" / "qualification_golden_audit.csv"
    rows = read_csv(golden_path)
    if audit_path.exists():
        audit_rows = read_csv(audit_path)
        problems = validate_audit(audit_rows, rows)
        if problems:
            raise SystemExit("audit golden invalide:\n- " + "\n- ".join(problems))
        rows = apply_audit(rows, audit_rows)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", dest="json_path", required=True)
    parser.add_argument("--requalify", action="store_true")
    parser.add_argument("--persist", action="store_true")
    args = parser.parse_args()

    items = store.load_items()
    if args.requalify:
        qualified = qualify(items)
        items = qualified.items
        decisions = qualified.decisions
        if args.persist:
            store.save_items(qualified.items)
            store.save_incidents(qualified.incidents)
            store.save_qualification_provenance(qualified.provenance)
            store.save_incident_id_registry(qualified.incident_id_registry)
            save_snapshot_provenance(
                store.load_items(), store.load_incidents(), operation="BACKFILL_UNKNOWNS",
            )
            site.build()
    else:
        decisions = decisions_from_provenance(store.load_qualification_provenance())

    references = golden_reference_by_anchor(reviewed_golden(), store.load_incident_id_registry())
    report = build_report(items, decisions, reference_by_item=references)
    report["mode"] = "requalified" if args.requalify else "published"

    target = Path(args.json_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print(f"QUALIFICATION BASELINE ({report['mode']})")
    print(f"items={report['items']}")
    for row in report["coverage"]:
        if row["Source_ID"] == "ALL":
            print(f"{row['Field']}: coverage={row['Coverage_pct']:.1f}% unknown={row['Unknown']}/{row['Total']}")
    for row in report["decision_summary"]:
        print(f"{row['Origin']}/{row['Field']}: decisions={row['Decisions']} applied={row['Applied']} rejected={row['Rejected']}")
    for row in report["quality_by_origin"]:
        print(f"quality {row['Origin']}/{row['Field']}: precision={row['Precision_pct']:.1f}% regressions={row['Regressions']} applied={row['Applied']}")
    print(f"json={target}")


if __name__ == "__main__":
    main()
