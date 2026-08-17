#!/usr/bin/env python3
"""Évalue la résolution d'identité et la déduplication contre un golden pairwise."""

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
    missing = []
    invalid = []
    tp = fp = fn = tn = 0

    for row in rows:
        case_id = row.get("Case_ID", "")
        entity_ref = row.get("Same_Organisation_REF", "").upper()
        incident_ref = row.get("Same_Incident_REF", "").upper()
        if entity_ref not in VALID or incident_ref not in VALID:
            invalid.append(case_id)
            continue

        left = by_id.get(row.get("Left_Item_ID", ""))
        right = by_id.get(row.get("Right_Item_ID", ""))
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
        "golden_cases": len(rows),
        "evaluated_cases": evaluated,
        "missing_cases": missing,
        "invalid_cases": invalid,
        "entity_accuracy_pct": _ratio(entity_correct, evaluated),
        "incident_accuracy_pct": _ratio(incident_correct, evaluated),
        "incident_precision_pct": _ratio(tp, tp + fp),
        "incident_recall_pct": _ratio(tp, tp + fn),
        "incident_true_positive": tp,
        "incident_false_positive": fp,
        "incident_false_negative": fn,
        "incident_true_negative": tn,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--golden",
        default=str(ROOT / "data" / "golden" / "dedup_golden.csv"),
    )
    parser.add_argument(
        "--min-cases",
        type=int,
        default=0,
        help="Nombre minimum de cas revus requis pour considérer le benchmark actif.",
    )
    args = parser.parse_args()

    result = evaluate(Path(args.golden))
    print("DEDUP_GOLDEN=" + json.dumps(result, ensure_ascii=False, sort_keys=True))

    if result["invalid_cases"] or result["missing_cases"]:
        return 1
    if result["evaluated_cases"] < args.min_cases:
        print(
            f"DEDUP_GOLDEN_INSUFFICIENT evaluated={result['evaluated_cases']} "
            f"required={args.min_cases}"
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
