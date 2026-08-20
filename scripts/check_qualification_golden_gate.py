#!/usr/bin/env python3
"""Bloque une requalification qui dégrade le Golden qualification.

Le contrôle compare l'état publié au résultat après requalification offline. Il
est volontairement relatif : aucune amélioration de couverture ne peut être
achetée au prix d'une baisse de précision/accuracy ou d'une hausse des erreurs.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def _load(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _num(mapping: dict, key: str) -> float:
    try:
        return float(mapping.get(key, 0) or 0)
    except (TypeError, ValueError):
        return 0.0


def qualification_gate_failures(before: dict, after: dict, *, tolerance_pp: float = 0.0) -> list[str]:
    failures: list[str] = []

    for key in ("matched",):
        if _num(after, key) < _num(before, key):
            failures.append(f"{key}: {_num(after, key):g} < {_num(before, key):g}")
    for key in ("missing", "ambiguous"):
        if _num(after, key) > _num(before, key):
            failures.append(f"{key}: {_num(after, key):g} > {_num(before, key):g}")

    before_fields = before.get("fields") or {}
    after_fields = after.get("fields") or {}
    for field in sorted(set(before_fields) | set(after_fields)):
        old = before_fields.get(field) or {}
        new = after_fields.get(field) or {}
        if not old or not new:
            failures.append(f"{field}: métriques absentes avant/après")
            continue

        for metric in ("accuracy_pct", "coverage_pct", "precision_when_qualified_pct"):
            old_value = _num(old, metric)
            new_value = _num(new, metric)
            if new_value + tolerance_pp < old_value:
                failures.append(
                    f"{field}/{metric}: {new_value:.1f}% < {old_value:.1f}% "
                    f"(tolérance {tolerance_pp:.1f} pp)"
                )

        for metric in ("wrong_classification", "resolvable_unknown"):
            if _num(new, metric) > _num(old, metric):
                failures.append(
                    f"{field}/{metric}: {_num(new, metric):g} > {_num(old, metric):g}"
                )

    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--tolerance-pp", type=float, default=0.0)
    args = parser.parse_args()

    before = _load(args.before)
    after = _load(args.after)
    failures = qualification_gate_failures(before, after, tolerance_pp=max(0.0, args.tolerance_pp))
    if failures:
        print("QUALIFICATION_GOLDEN_GATE=FAIL")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("QUALIFICATION_GOLDEN_GATE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
