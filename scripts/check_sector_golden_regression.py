#!/usr/bin/env python3
"""Bloque une régression Sector entre deux rapports Golden JSON.

Ce garde est destiné aux backfills structurés : gagner de la couverture n'est
acceptable que si le nombre de mauvaises classifications n'augmente pas et si
la précision sur les valeurs qualifiées ne baisse pas.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _sector(path: str) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        return payload["fields"]["Secteur"]
    except (KeyError, TypeError) as exc:
        raise SystemExit(f"rapport Golden sans métriques Secteur: {path}") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before")
    parser.add_argument("after")
    args = parser.parse_args()

    before = _sector(args.before)
    after = _sector(args.after)
    problems: list[str] = []

    before_wrong = int(before.get("wrong_classification", 0))
    after_wrong = int(after.get("wrong_classification", 0))
    if after_wrong > before_wrong:
        problems.append(f"wrong_classification {before_wrong} -> {after_wrong}")

    before_precision = float(before.get("precision_when_qualified_pct", 0.0))
    after_precision = float(after.get("precision_when_qualified_pct", 0.0))
    if after_precision + 1e-9 < before_precision:
        problems.append(
            f"precision_when_qualified_pct {before_precision:.3f} -> {after_precision:.3f}"
        )

    before_coverage = float(before.get("coverage_pct", 0.0))
    after_coverage = float(after.get("coverage_pct", 0.0))
    if after_coverage + 1e-9 < before_coverage:
        problems.append(f"coverage_pct {before_coverage:.3f} -> {after_coverage:.3f}")

    before_accuracy = float(before.get("accuracy_pct", 0.0))
    after_accuracy = float(after.get("accuracy_pct", 0.0))
    if after_accuracy + 1e-9 < before_accuracy:
        problems.append(f"accuracy_pct {before_accuracy:.3f} -> {after_accuracy:.3f}")

    if problems:
        print("SECTOR_GOLDEN_REGRESSION=FAIL")
        for problem in problems:
            print(f"- {problem}")
        return 1

    print(
        "SECTOR_GOLDEN_REGRESSION=PASS "
        f"wrong={before_wrong}->{after_wrong} "
        f"precision={before_precision:.1f}->{after_precision:.1f} "
        f"coverage={before_coverage:.1f}->{after_coverage:.1f} "
        f"accuracy={before_accuracy:.1f}->{after_accuracy:.1f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
