#!/usr/bin/env python3
"""Compare le golden set versionné aux qualifications Cyberwatch courantes."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch.golden import DETAIL_COLUMNS, evaluate, read_csv, validate_file, write_csv


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", default=str(ROOT / "data" / "golden" / "qualification_golden.csv"))
    parser.add_argument("--incidents", default=str(ROOT / "data" / "incidents.csv"))
    parser.add_argument("--details", default=str(ROOT / "bench" / "results" / "golden_evaluation.csv"))
    parser.add_argument("--json", dest="json_path", default="")
    parser.add_argument(
        "--allow-stale-taxonomy",
        action="store_true",
        help="Autorise exceptionnellement un golden set créé avec une autre METHOD_ID.",
    )
    args = parser.parse_args()

    problems = validate_file(args.golden, require_current_taxonomy=not args.allow_stale_taxonomy)
    if problems:
        raise SystemExit("golden set invalide:\n- " + "\n- ".join(problems))

    golden_rows = read_csv(args.golden)
    if not golden_rows:
        raise SystemExit("golden set vide: ajoutez des cas de référence avant l'évaluation")
    incidents = read_csv(args.incidents)
    result = evaluate(golden_rows, incidents)
    details = result.pop("details")
    write_csv(args.details, details, DETAIL_COLUMNS)

    print("GOLDEN QUALIFICATION BENCHMARK")
    print(f"cases={result['cases']} matched={result['matched']} ambiguous={result['ambiguous']} missing={result['missing']}")
    for field, metrics in result["fields"].items():
        print(
            f"{field}: accuracy={metrics['accuracy_pct']:.1f}% "
            f"coverage={metrics['coverage_pct']:.1f}% "
            f"precision_when_qualified={metrics['precision_when_qualified_pct']:.1f}% "
            f"resolvable_unknown={metrics['resolvable_unknown']} "
            f"wrong_classification={metrics['wrong_classification']}"
        )
    print(f"details={args.details}")

    if args.json_path:
        target = Path(args.json_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"json={target}")


if __name__ == "__main__":
    main()
