#!/usr/bin/env python3
"""Refuse un canal Sector AUTO non certifié par la politique versionnée."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "data" / "sector_auto_policy.json"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    args = parser.parse_args()

    # La politique versionnée est un composant de sécurité, pas une option.
    # Sans elle, un fallback de code ne doit jamais être considéré publiable.
    if not POLICY_PATH.exists():
        print("SECTOR REGISTRY POLICY: FAIL")
        print(f"- politique versionnée absente: {POLICY_PATH}")
        return 1

    report = json.loads(Path(args.json).read_text(encoding="utf-8"))
    minimum_cases = int(report.get("minimum_cases", 10))
    minimum_precision = float(report.get("minimum_precision_pct", 95.0))
    failures = []

    for channel, metrics in (report.get("channels") or {}).items():
        if not metrics.get("enabled") or not metrics.get("requires_golden"):
            continue
        cases = int(metrics.get("cases", 0))
        precision = float(metrics.get("precision_pct", 0.0))
        if cases < minimum_cases:
            failures.append(
                f"{channel}: {cases} cas Golden < minimum {minimum_cases}"
            )
        elif precision < minimum_precision:
            failures.append(
                f"{channel}: précision {precision:.2f}% < {minimum_precision:.2f}%"
            )

    if failures:
        print("SECTOR REGISTRY POLICY: FAIL")
        for failure in failures:
            print("- " + failure)
        return 1
    print("SECTOR REGISTRY POLICY: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
