#!/usr/bin/env python3
"""Bloque une régression Sector entre deux rapports Golden JSON.

Le garde publie aussi un diagnostic exploitable humainement : toutes les
classifications Sector erronées après traitement, et celles nouvellement
introduites par le run. Le rapport CSV peut être conservé comme artefact CI.

Le mode ``--require-zero-wrong`` est réservé aux runs de clôture ``golden-only`` :
il interdit de publier tant qu'une classification Sector qualifiée reste fausse.
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


def _wrong_rows(before_path: str, after_path: str) -> list[dict[str, str]]:
    before = _details(before_path)
    after = _details(after_path)
    rows: list[dict[str, str]] = []
    for golden_id in sorted(after):
        new = after[golden_id]
        old = before.get(golden_id, {})
        current = (new.get("Secteur_CW") or "").strip()
        if not _is_false(new.get("Secteur_Match", "")) or current in ("", "Inconnu"):
            continue
        old_current = (old.get("Secteur_CW") or "").strip()
        already_wrong = (
            _is_false(old.get("Secteur_Match", ""))
            and old_current not in ("", "Inconnu")
        )
        rows.append({
            "Golden_ID": golden_id,
            "Organisation": new.get("Organisation", ""),
            "Secteur_REF": new.get("Secteur_REF", ""),
            "Secteur_CW": current,
            "Secteur_Before": old_current,
            "Newly_Wrong": "false" if already_wrong else "true",
            "Incident_ID_Current": new.get("Incident_ID_Current", ""),
            "Match_Strategy": new.get("Match_Strategy", ""),
        })
    return rows


def _emit_diagnostics(before_path: str, after_path: str, report_csv: str) -> None:
    rows = _wrong_rows(before_path, after_path)
    newly_wrong = [row for row in rows if row["Newly_Wrong"] == "true"]

    print(f"ALL_WRONG_SECTOR_CASES count={len(rows)}")
    for row in rows:
        print(
            f"- {row['Golden_ID']} organisation={row['Organisation']} "
            f"expected={row['Secteur_REF']} got={row['Secteur_CW']} "
            f"before={row['Secteur_Before']} newly_wrong={row['Newly_Wrong']}"
        )

    print(f"NEWLY_WRONG_SECTOR_CASES count={len(newly_wrong)}")
    for row in newly_wrong:
        print(
            f"- {row['Golden_ID']} organisation={row['Organisation']} "
            f"expected={row['Secteur_REF']} got={row['Secteur_CW']} "
            f"before={row['Secteur_Before']}"
        )

    if report_csv:
        target = Path(report_csv)
        target.parent.mkdir(parents=True, exist_ok=True)
        columns = [
            "Golden_ID", "Organisation", "Secteur_REF", "Secteur_CW",
            "Secteur_Before", "Newly_Wrong", "Incident_ID_Current", "Match_Strategy",
        ]
        with target.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(rows)
        print(f"sector_golden_mismatch_report={target}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("before")
    parser.add_argument("after")
    parser.add_argument("--before-details", default="")
    parser.add_argument("--after-details", default="")
    parser.add_argument("--report-csv", default="")
    parser.add_argument(
        "--require-zero-wrong",
        action="store_true",
        help="échoue si une classification Sector qualifiée reste fausse après traitement",
    )
    args = parser.parse_args()

    before = _sector(args.before)
    after = _sector(args.after)
    problems: list[str] = []

    before_wrong = int(before.get("wrong_classification", 0))
    after_wrong = int(after.get("wrong_classification", 0))
    if after_wrong > before_wrong:
        problems.append(f"wrong_classification {before_wrong} -> {after_wrong}")
    if args.require_zero_wrong and after_wrong != 0:
        problems.append(f"closeout_wrong_classification expected=0 got={after_wrong}")

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

    _emit_diagnostics(args.before_details, args.after_details, args.report_csv)

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
