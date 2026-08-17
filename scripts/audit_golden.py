#!/usr/bin/env python3
"""Audite la fiabilité du golden set et matérialise sa vue revue."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch.golden import GOLDEN_COLUMNS, read_csv, validate_file, write_csv
from cyberwatch.golden_review import FINDING_COLUMNS, quality_report, validate_audit


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", default=str(ROOT / "data" / "golden" / "qualification_golden.csv"))
    parser.add_argument("--audit", default=str(ROOT / "data" / "golden" / "qualification_golden_audit.csv"))
    parser.add_argument("--findings", default=str(ROOT / "bench" / "results" / "golden_quality_findings.csv"))
    parser.add_argument("--json", dest="json_path", default=str(ROOT / "bench" / "results" / "golden_quality_summary.json"))
    parser.add_argument("--materialized", default="")
    parser.add_argument("--allow-stale-taxonomy", action="store_true")
    parser.add_argument("--fail-on-warnings", action="store_true")
    args = parser.parse_args()

    problems = validate_file(args.golden, require_current_taxonomy=not args.allow_stale_taxonomy)
    if problems:
        raise SystemExit("golden set invalide:\n- " + "\n- ".join(problems))

    golden_rows = read_csv(args.golden)
    audit_path = Path(args.audit)
    audit_rows = read_csv(audit_path) if audit_path.exists() else []
    audit_problems = validate_audit(audit_rows, golden_rows)
    if audit_problems:
        raise SystemExit("audit golden invalide:\n- " + "\n- ".join(audit_problems))

    result = quality_report(golden_rows, audit_rows)
    findings = result.pop("findings")
    effective_rows = result.pop("effective_rows")
    write_csv(args.findings, findings, FINDING_COLUMNS)

    target = Path(args.json_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    if args.materialized:
        write_csv(args.materialized, effective_rows, GOLDEN_COLUMNS)

    print("GOLDEN QUALITY AUDIT")
    print(
        f"base={result['base_cases']} effective={result['effective_cases']} "
        f"reviewed={result['reviewed_cases']} ({result['review_coverage_pct']:.1f}%)"
    )
    print(
        f"corrections={result['corrected_fields']} duplicates_removed={result['duplicates_removed']} "
        f"unresolved={result['unresolved_review_cases']}"
    )
    print(
        f"source_url_coverage={result['source_url_coverage']['pct']:.1f}% "
        f"findings={result['findings_count']}"
    )
    for field, distribution in result["confidence"].items():
        print(f"{field}_confidence={distribution}")
    print(f"findings_csv={args.findings}")
    print(f"summary_json={target}")

    if args.fail_on_warnings and findings:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
