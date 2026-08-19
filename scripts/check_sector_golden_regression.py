#!/usr/bin/env python3
"""Bloque une régression Sector entre deux rapports Golden JSON.

Ce garde est destiné aux backfills structurés : gagner de la couverture n'est
acceptable que si le nombre de mauvaises classifications n'augmente pas et si
la précision sur les valeurs qualifiées ne baisse pas.
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def _sector(path: str) -> dict:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    try:
        return payload["fields"]["Secteur"]
    except (KeyError, TypeError) as exc:
        raise SystemExit(f"rapport Golden sans métriques Secteur: {path}") from exc


def _details(path: str) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    target = Path(path)
    if not target.exists():
        return {}
    with target.open(encoding="utf-8", newline="") as handle:
        return {
            row.get("Golden_ID", ""): row
            for row in csv.DictReader(handle)
            if row.get("Golden_ID", "")
        }


def _is_false(value: str) -> bool:
    return str(value or "").strip().lower() in {"0", "false", "no", "non"}


def _print_newly_wrong(before_path: str, after_path: str) -> None:
    before = _details(before_path)
    after = _details(after_path)
    if not before or not after:
        return
    emitted = False
    for golden_id in sorted(after):
        new = after[golden_id]
        old = before.get(golden_id, {})
        if not _is_false(new.get("Secteur_Match", "")):
            continue
        if not new.get("Secteur_CW") or new.get("Secteur_CW") == "Inconnu":
            continue
        if _is_false(old.get("Secteur_Match", "")) and old.get("Secteur_CW") not in ("", "Inconnu"):
            continue
        if not emitted:
            print("NEWLY_WRONG_SECTOR_CASES")
            emitted = True
        print(
            f"- {golden_id} organisation={new.get('Organisation','')} "
            f"expected={new.get('Secteur_REF','')} got={new.get('Secteur_CW','')} "
            f"before={old.get('Secteur_CW','')}"
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--before-details", default="")
    parser.add_argument("--after-details", default="")
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
        _print_newly_wrong(args.before_details, args.after_details)
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
