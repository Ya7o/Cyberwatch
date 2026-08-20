"""Baseline reproductible de la qualité de qualification."""
from __future__ import annotations

from collections import defaultdict

from . import config
from .model import Item
from .qualification_decision import QualificationDecision, summarize_decisions
from .qualification_quality import evaluate_decisions_by_origin

FIELD_SPECS = {
    "Sector": config.SECTOR_UNKNOWN,
    "Threat": config.THREAT_UNKNOWN,
    "Location": config.LOC_INCONNU,
}


def coverage_rows(items: list[Item]) -> list[dict[str, object]]:
    """Couverture globale et par source pour les trois champs canoniques."""
    groups: dict[str, list[Item]] = {"ALL": list(items)}
    for item in items:
        groups.setdefault(item.Source_ID, []).append(item)
    rows: list[dict[str, object]] = []
    for source_id, values in sorted(groups.items()):
        for field, unknown in FIELD_SPECS.items():
            total = len(values)
            unknown_count = sum((getattr(item, field, "") or unknown) == unknown for item in values)
            known = total - unknown_count
            rows.append({
                "Source_ID": source_id,
                "Field": field,
                "Total": total,
                "Known": known,
                "Unknown": unknown_count,
                "Coverage_pct": round(100.0 * known / total, 1) if total else 0.0,
            })
    return rows


def golden_reference_by_anchor(
    golden_rows: list[dict[str, str]], registry_rows: list[dict[str, str]]
) -> dict[str, dict[str, str]]:
    """Rattache les labels golden à l'item ancre stable de l'incident snapshot."""
    anchor_by_incident = {
        row.get("Incident_ID", ""): row.get("Anchor_Item_ID", "")
        for row in registry_rows
        if row.get("Incident_ID") and row.get("Anchor_Item_ID") and not row.get("Redirect_To")
    }
    references: dict[str, dict[str, str]] = {}
    for row in golden_rows:
        anchor = anchor_by_incident.get((row.get("Incident_ID_Snapshot") or "").strip())
        if not anchor:
            continue
        references[anchor] = {
            "Secteur_REF": row.get("Secteur_REF", ""),
            "Menace_REF": row.get("Menace_REF", ""),
            "Localisation_REF": row.get("Localisation_REF", ""),
        }
    return references


def build_report(
    items: list[Item],
    decisions: list[QualificationDecision],
    *,
    reference_by_item: dict[str, dict[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "items": len(items),
        "coverage": coverage_rows(items),
        "decision_summary": summarize_decisions(decisions),
        "quality_by_origin": evaluate_decisions_by_origin(decisions, reference_by_item or {}),
    }


def compare_reports(before: dict[str, object], after: dict[str, object]) -> list[str]:
    """Gates relatifs : le nouveau snapshot ne doit pas être moins bon que le publié."""
    failures: list[str] = []
    before_cov = {(r["Source_ID"], r["Field"]): r for r in before.get("coverage", [])}
    after_cov = {(r["Source_ID"], r["Field"]): r for r in after.get("coverage", [])}
    for key, old in before_cov.items():
        new = after_cov.get(key)
        if not new:
            failures.append(f"{key[0]}/{key[1]}: métrique de couverture absente après qualification")
            continue
        if int(new["Unknown"]) > int(old["Unknown"]):
            failures.append(f"{key[0]}/{key[1]}: inconnus {old['Unknown']} -> {new['Unknown']}")
        if float(new["Coverage_pct"]) < float(old["Coverage_pct"]):
            failures.append(f"{key[0]}/{key[1]}: couverture {old['Coverage_pct']}% -> {new['Coverage_pct']}%")

    before_quality = {(r["Origin"], r["Field"]): r for r in before.get("quality_by_origin", [])}
    after_quality = {(r["Origin"], r["Field"]): r for r in after.get("quality_by_origin", [])}
    for key, old in before_quality.items():
        new = after_quality.get(key)
        if not new or int(new["Applied"]) < int(old["Applied"]):
            continue
        if float(new["Precision_pct"]) < float(old["Precision_pct"]):
            failures.append(f"{key[0]}/{key[1]}: précision {old['Precision_pct']}% -> {new['Precision_pct']}%")
        if int(new["Regressions"]) > int(old["Regressions"]):
            failures.append(f"{key[0]}/{key[1]}: régressions {old['Regressions']} -> {new['Regressions']}")
    return failures
