#!/usr/bin/env python3
"""Évalue et certifie la déduplication contre un golden pairwise revu.

Le benchmark privilégie explicitement la précision : une fausse fusion détruit
l'identité de deux événements et doit donc bloquer la CI. Le rappel reste
conservateur ; les cas ambigus hors fenêtre de fusion automatique peuvent rester
séparés tant que le plancher certifié n'est pas dégradé.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import store
from cyberwatch.dedup import group_components
from cyberwatch.org_identity import effective_organisation_key

VALID = {"SAME", "DIFFERENT"}
CERTIFIED_GOLDEN_VERSION = "DEDUP-GOLDEN-1"


def _load_rows(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _ratio(num: int, den: int) -> float:
    return round(100.0 * num / den, 2) if den else 0.0


def evaluate(golden_path: Path) -> dict:
    items = store.load_items()
    by_id = {item.Item_ID: item for item in items}
    component_of = {
        item.Item_ID: index
        for index, component in enumerate(group_components(items))
        for item in component
    }

    rows = _load_rows(golden_path)
    entity_correct = 0
    incident_correct = 0
    evaluated = 0
    missing: list[str] = []
    invalid: list[str] = []
    incomplete_evidence: list[str] = []
    wrong_version: list[str] = []
    duplicate_pairs: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()
    tp = fp = fn = tn = 0

    for row in rows:
        case_id = row.get("Case_ID", "")
        left_id = row.get("Left_Item_ID", "")
        right_id = row.get("Right_Item_ID", "")
        entity_ref = row.get("Same_Organisation_REF", "").upper()
        incident_ref = row.get("Same_Incident_REF", "").upper()

        pair = tuple(sorted((left_id, right_id)))
        if pair in seen_pairs:
            duplicate_pairs.append(case_id)
        seen_pairs.add(pair)

        if entity_ref not in VALID or incident_ref not in VALID or not case_id:
            invalid.append(case_id or "<sans Case_ID>")
            continue
        if not row.get("Evidence", "").strip() or not row.get("Reviewed_At", "").strip():
            incomplete_evidence.append(case_id)
        if row.get("Golden_Version", "") != CERTIFIED_GOLDEN_VERSION:
            wrong_version.append(case_id)

        left = by_id.get(left_id)
        right = by_id.get(right_id)
        if not left or not right:
            missing.append(case_id)
            continue

        evaluated += 1
        entity_same = (
            effective_organisation_key(left.Organisation_Raw, left.Organisation_Key)
            == effective_organisation_key(right.Organisation_Raw, right.Organisation_Key)
        )
        incident_same = component_of[left.Item_ID] == component_of[right.Item_ID]

        entity_correct += int(entity_same == (entity_ref == "SAME"))
        incident_correct += int(incident_same == (incident_ref == "SAME"))

        if incident_same and incident_ref == "SAME":
            tp += 1
        elif incident_same and incident_ref == "DIFFERENT":
            fp += 1
        elif not incident_same and incident_ref == "SAME":
            fn += 1
        else:
            tn += 1

    return {
        "golden_version": CERTIFIED_GOLDEN_VERSION,
        "golden_cases": len(rows),
        "evaluated_cases": evaluated,
        "positive_reference_cases": tp + fn,
        "negative_reference_cases": tn + fp,
        "missing_cases": missing,
        "invalid_cases": invalid,
        "incomplete_evidence_cases": incomplete_evidence,
        "wrong_version_cases": wrong_version,
        "duplicate_pair_cases": duplicate_pairs,
        "entity_accuracy_pct": _ratio(entity_correct, evaluated),
        "incident_accuracy_pct": _ratio(incident_correct, evaluated),
        "incident_precision_pct": _ratio(tp, tp + fp),
        "incident_recall_pct": _ratio(tp, tp + fn),
        "incident_true_positive": tp,
        "incident_false_positive": fp,
        "incident_false_negative": fn,
        "incident_true_negative": tn,
    }


def _failure_messages(result: dict, args: argparse.Namespace) -> list[str]:
    failures: list[str] = []
    structural_fields = (
        "invalid_cases",
        "missing_cases",
        "incomplete_evidence_cases",
        "wrong_version_cases",
        "duplicate_pair_cases",
    )
    for field in structural_fields:
        if result[field]:
            failures.append(f"{field}={result[field]}")

    checks = [
        ("evaluated_cases", result["evaluated_cases"], args.min_cases),
        ("positive_reference_cases", result["positive_reference_cases"], args.min_positive_cases),
        ("negative_reference_cases", result["negative_reference_cases"], args.min_negative_cases),
        ("entity_accuracy_pct", result["entity_accuracy_pct"], args.min_entity_accuracy),
        ("incident_accuracy_pct", result["incident_accuracy_pct"], args.min_incident_accuracy),
        ("incident_precision_pct", result["incident_precision_pct"], args.min_incident_precision),
        ("incident_recall_pct", result["incident_recall_pct"], args.min_incident_recall),
    ]
    for name, actual, minimum in checks:
        if actual < minimum:
            failures.append(f"{name}={actual} < {minimum}")
    if result["incident_false_positive"] > args.max_false_positive:
        failures.append(
            f"incident_false_positive={result['incident_false_positive']} > {args.max_false_positive}"
        )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--golden",
        default=str(ROOT / "data" / "golden" / "dedup_golden.csv"),
    )
    # Plancher de certification DEDUP-GOLDEN-1. Toute évolution du golden ou de
    # la méthode qui passe sous ces valeurs doit être revue explicitement.
    parser.add_argument("--min-cases", type=int, default=70)
    parser.add_argument("--min-positive-cases", type=int, default=50)
    parser.add_argument("--min-negative-cases", type=int, default=20)
    parser.add_argument("--min-entity-accuracy", type=float, default=100.0)
    parser.add_argument("--min-incident-accuracy", type=float, default=94.0)
    parser.add_argument("--min-incident-precision", type=float, default=100.0)
    parser.add_argument("--min-incident-recall", type=float, default=92.0)
    parser.add_argument("--max-false-positive", type=int, default=0)
    args = parser.parse_args()

    result = evaluate(Path(args.golden))
    print("DEDUP_GOLDEN=" + json.dumps(result, ensure_ascii=False, sort_keys=True))

    failures = _failure_messages(result, args)
    if failures:
        print("DEDUP_GOLDEN_FAIL=" + json.dumps(failures, ensure_ascii=False))
        return 1
    print("DEDUP_GOLDEN_CERTIFIED=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
