#!/usr/bin/env python3
"""Compare le golden set à la DB Cyberwatch et aux exports LLM expérimentaux."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch.golden import read_csv, validate_file, write_csv
from cyberwatch.golden_challengers import (
    COMPARISON_DETAIL_COLUMNS,
    compare_challengers,
    load_optional_csv,
)


def _print_source(name: str, result: dict[str, object]) -> None:
    print(
        f"{name}: matched={result['matched']} ambiguous={result['ambiguous']} "
        f"missing={result['missing']}"
    )
    for field, metrics in result["fields"].items():
        print(
            f"  {field}: accuracy={metrics['accuracy_pct']:.1f}% "
            f"coverage={metrics['coverage_pct']:.1f}% "
            f"precision_when_qualified={metrics['precision_when_qualified_pct']:.1f}% "
            f"resolvable_unknown={metrics['resolvable_unknown']} "
            f"wrong_classification={metrics['wrong_classification']}"
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--golden", default=str(ROOT / "data" / "golden" / "qualification_golden.csv"))
    parser.add_argument("--incidents", default=str(ROOT / "data" / "incidents.csv"))
    parser.add_argument(
        "--frenchbreaches",
        default=str(ROOT / "sources" / "veillellm" / "frenchbreaches_2026.csv"),
    )
    parser.add_argument(
        "--cyberattaque",
        default=str(ROOT / "sources" / "veillellm" / "cyberattaque_org_2026.csv"),
    )
    parser.add_argument(
        "--manual-matches",
        default=str(ROOT / "data" / "golden" / "challenger_matches.csv"),
    )
    parser.add_argument(
        "--details",
        default=str(ROOT / "bench" / "results" / "golden_challenger_comparison.csv"),
    )
    parser.add_argument(
        "--json",
        dest="json_path",
        default=str(ROOT / "bench" / "results" / "golden_challenger_summary.json"),
    )
    parser.add_argument("--allow-stale-taxonomy", action="store_true")
    args = parser.parse_args()

    problems = validate_file(args.golden, require_current_taxonomy=not args.allow_stale_taxonomy)
    if problems:
        raise SystemExit("golden set invalide:\n- " + "\n- ".join(problems))

    golden_rows = read_csv(args.golden)
    if not golden_rows:
        raise SystemExit("golden set vide: ajoutez des cas de référence avant la comparaison")

    incidents = read_csv(args.incidents)
    challengers = {
        "FRENCHBREACHES_LLM": read_csv(args.frenchbreaches),
        "CYBERATTAQUE_ORG_LLM": read_csv(args.cyberattaque),
    }
    manual_matches = load_optional_csv(args.manual_matches)

    result = compare_challengers(golden_rows, incidents, challengers, manual_matches)
    details = result.pop("details")
    write_csv(args.details, details, COMPARISON_DETAIL_COLUMNS)

    print("GOLDEN QUALIFICATION — DB VS LLM CHALLENGERS")
    print(f"cases={result['cases']}")
    _print_source("CYBERWATCH_DB", result["db"])
    for name, source_result in result["challengers"].items():
        _print_source(name, source_result)
        print("  delta_vs_db_on_common_cases:")
        for field, metrics in result["pairwise_vs_db"][name].items():
            print(
                f"    {field}: delta={metrics['delta_accuracy_pp']:+.1f}pp "
                f"gains={metrics['gains']} regressions={metrics['regressions']} "
                f"common={metrics['common_matched_cases']}"
            )

    print(f"details={args.details}")
    target = Path(args.json_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"json={target}")


if __name__ == "__main__":
    main()
