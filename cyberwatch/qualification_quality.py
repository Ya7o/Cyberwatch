"""Mesures de qualité des décisions de qualification contre un référentiel."""
from __future__ import annotations
from collections import defaultdict
from .qualification_decision import QualificationDecision

FIELD_TO_REF = {"Sector": "Secteur_REF", "Threat": "Menace_REF", "Location": "Localisation_REF"}


def evaluate_decisions_by_origin(decisions: list[QualificationDecision], reference_by_item: dict[str, dict[str, str]]) -> list[dict[str, object]]:
    """Mesure précision/gains/régressions par Origin x Field."""
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


def quality_gate_failures(
    rows: list[dict[str, object]],
    *,
    minimum_cases: int = 10,
    minimum_precision_pct: float = 95.0,
    maximum_regressions: int = 0,
) -> list[str]:
    """Retourne les violations de qualité pour les canaux suffisamment évalués.

    Le gate reste volontairement générique : les seuils peuvent être durcis après
    établissement d'une baseline réelle, sans coupler cette fonction au golden.
    """
    failures: list[str] = []
    for row in rows:
        applied = int(row.get("Applied", 0) or 0)
        if applied < minimum_cases:
            continue
        precision = float(row.get("Precision_pct", 0.0) or 0.0)
        regressions = int(row.get("Regressions", 0) or 0)
        label = f"{row.get('Origin', '')}/{row.get('Field', '')}"
        if precision < minimum_precision_pct:
            failures.append(
                f"{label}: precision {precision:.1f}% < {minimum_precision_pct:.1f}% ({applied} cas)"
            )
        if regressions > maximum_regressions:
            failures.append(
                f"{label}: {regressions} regression(s) > {maximum_regressions}"
            )
    return failures
