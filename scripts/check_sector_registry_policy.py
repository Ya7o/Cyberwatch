#!/usr/bin/env python3
"""Refuse un canal Sector AUTO non certifié par la politique versionnée."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", required=True)
    args = parser.parse_args()
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
