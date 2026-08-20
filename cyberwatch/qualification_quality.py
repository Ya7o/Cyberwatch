"""Mesures de qualité des décisions de qualification contre un référentiel."""
from __future__ import annotations
from collections import defaultdict
from .qualification_decision import QualificationDecision

FIELD_TO_REF = {"Sector": "Secteur_REF", "Threat": "Menace_REF", "Location": "Localisation_REF"}

def evaluate_decisions_by_origin(decisions: list[QualificationDecision], reference_by_item: dict[str, dict[str, str]]) -> list[dict[str, object]]:
    """Mesure précision/gains/régressions par Origin x Field.

    `reference_by_item` est volontairement générique : le golden peut raccorder ses
    cas aux Item_ID puis réutiliser cette fonction sans coupler le moteur au format CSV.
    """
    grouped = defaultdict(list)
    for decision in decisions:
        ref_row = reference_by_item.get(decision.item_id)
        ref_field = FIELD_TO_REF.get(decision.field)
        if ref_row is None or ref_field is None or not ref_row.get(ref_field):
            continue
        grouped[(decision.origin, decision.field)].append((decision, ref_row[ref_field]))
    output = []
    for (origin, field), rows in sorted(grouped.items()):
        applied = [(d, ref) for d, ref in rows if d.decision == "APPLIED"]
        correct = sum(d.final_value == ref for d, ref in applied)
        incorrect = len(applied) - correct
        gains = sum(d.previous_value != ref and d.final_value == ref for d, ref in applied)
        regressions = sum(d.previous_value == ref and d.final_value != ref for d, ref in applied)
        output.append({
            "Origin": origin, "Field": field, "Evaluated": len(rows), "Applied": len(applied),
            "Correct": correct, "Incorrect": incorrect,
            "Precision_pct": round(100.0 * correct / len(applied), 1) if applied else 0.0,
            "Gains": gains, "Regressions": regressions,
            "Abstentions": len(rows) - len(applied),
        })
    return output
