"""Revue traçable du golden set de qualification Cyberwatch.

Le fichier de référence initial reste immuable. Les décisions de revue sont
append-only dans ``qualification_golden_audit.csv`` puis appliquées pour produire
une vue effective (Golden v2, v3, ...). Cette séparation évite qu'une correction
du juge soit confondue avec une amélioration de Cyberwatch.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from copy import deepcopy

from . import config
from .normalize import classify_threat, organisation_key, searchable

AUDIT_COLUMNS = [
    "Golden_ID",
    "Field",
    "Old_Value",
    "Proposed_Value",
    "Decision",
    "Confidence",
    "Evidence_URLs",
    "Evidence_Text",
    "Reason",
    "Reviewed_At",
]

FINDING_COLUMNS = [
    "Severity",
    "Code",
    "Golden_ID",
    "Related_Golden_ID",
    "Field",
    "Current_Value",
    "Suggested_Value",
    "Message",
]

DECISIONS = frozenset({"CONFIRMED", "CORRECTED", "REVIEW", "DUPLICATE"})
AUDIT_FIELDS = frozenset(
    {"ALL", "Secteur", "Menace", "Localisation", "Incident", "Reference_Date", "Organisation"}
)
FIELD_TO_REF = {
    "Secteur": "Secteur_REF",
    "Menace": "Menace_REF",
    "Localisation": "Localisation_REF",
}
FIELD_TO_CONFIDENCE = {
    "Secteur": "Secteur_Confidence",
    "Menace": "Menace_Confidence",
    "Localisation": "Localisation_Confidence",
}
FIELD_TO_EVIDENCE = {
    "Secteur": "Secteur_Evidence",
    "Menace": "Menace_Evidence",
    "Localisation": "Localisation_Evidence",
}
ALLOWED_VALUES = {
    "Secteur": set(config.SECTORS),
    "Menace": set(config.THREATS),
    "Localisation": set(config.LOCATIONS),
}

_GENERIC_EVIDENCE_PREFIXES = (
    "l alerte frenchbreaches reference une violation de donnees",
    "la victime est une entite francaise implantee ou institutionnellement rattachee",
)


def _split_multi(value: str) -> list[str]:
    return [part.strip() for part in str(value or "").split("|") if part.strip()]


def _iso_date(value: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(value or "").strip())
    except ValueError:
        return None


def validate_audit(
    audit_rows: list[dict[str, str]], golden_rows: list[dict[str, str]] | None = None
) -> list[str]:
    """Valide le journal de revue, y compris l'ancien label lorsqu'il est connu."""
    problems: list[str] = []
    golden_by_id = {row.get("Golden_ID", ""): row for row in (golden_rows or [])}
    seen: set[tuple[str, str, str, str]] = set()

    for index, row in enumerate(audit_rows, start=2):
        prefix = f"ligne audit {index}"
        golden_id = (row.get("Golden_ID") or "").strip()
        field = (row.get("Field") or "").strip()
        decision = (row.get("Decision") or "").strip()
        old = (row.get("Old_Value") or "").strip()
        proposed = (row.get("Proposed_Value") or "").strip()
        confidence = (row.get("Confidence") or "").strip()
        reviewed_at = (row.get("Reviewed_At") or "").strip()

        if golden_rows is not None and golden_id not in golden_by_id:
            problems.append(f"{prefix}: Golden_ID inconnu ({golden_id!r})")
        if field not in AUDIT_FIELDS:
            problems.append(f"{prefix}: Field invalide ({field!r})")
        if decision not in DECISIONS:
            problems.append(f"{prefix}: Decision invalide ({decision!r})")
        if _iso_date(reviewed_at) is None:
            problems.append(f"{prefix}: Reviewed_At invalide ({reviewed_at!r})")
        if confidence and confidence not in {"HIGH", "MEDIUM", "LOW"}:
            problems.append(f"{prefix}: Confidence invalide ({confidence!r})")

        signature = (golden_id, field, decision, proposed)
        if signature in seen:
            problems.append(f"{prefix}: décision d'audit dupliquée")
        seen.add(signature)

        if decision == "CORRECTED":
            if field not in FIELD_TO_REF and field not in {"Reference_Date", "Organisation"}:
                problems.append(f"{prefix}: CORRECTED non supporté pour {field!r}")
            if not proposed:
                problems.append(f"{prefix}: Proposed_Value requis pour CORRECTED")
            if not (row.get("Reason") or "").strip():
                problems.append(f"{prefix}: Reason requis pour CORRECTED")
            if not _split_multi(row.get("Evidence_URLs", "")):
                problems.append(f"{prefix}: Evidence_URLs requis pour CORRECTED")
            if field in ALLOWED_VALUES and proposed not in ALLOWED_VALUES[field]:
                problems.append(f"{prefix}: Proposed_Value hors nomenclature ({proposed!r})")

            source = golden_by_id.get(golden_id)
            if source is not None:
                source_column = FIELD_TO_REF.get(field, field)
                current = (source.get(source_column) or "").strip()
                if old and current != old:
                    problems.append(
                        f"{prefix}: Old_Value={old!r} ne correspond pas au golden ({current!r})"
                    )

        if decision == "DUPLICATE":
            if field != "Incident":
                problems.append(f"{prefix}: DUPLICATE exige Field=Incident")
            if not proposed:
                problems.append(f"{prefix}: DUPLICATE exige le Golden_ID canonique dans Proposed_Value")
            elif golden_rows is not None and proposed not in golden_by_id:
                problems.append(f"{prefix}: cible DUPLICATE inconnue ({proposed!r})")
            if proposed == golden_id:
                problems.append(f"{prefix}: un cas ne peut pas être son propre doublon")

    return problems


def apply_audit(
    golden_rows: list[dict[str, str]], audit_rows: list[dict[str, str]], *, target_version: int = 2
) -> list[dict[str, str]]:
    """Matérialise la vue revue sans modifier la référence source en mémoire.

    Un cas ``DUPLICATE`` est retiré définitivement de la vue effective. Un cas
    ``REVIEW`` est lui aussi exclu tant que son arbitrage n'est pas clos : un juge
    explicitement litigieux ne doit pas participer au calcul d'accuracy.
    """
    problems = validate_audit(audit_rows, golden_rows)
    if problems:
        raise ValueError("audit golden invalide: " + "; ".join(problems))

    rows_by_id = {row["Golden_ID"]: deepcopy(row) for row in golden_rows}
    drop_ids: set[str] = set()

    for audit in audit_rows:
        golden_id = audit["Golden_ID"].strip()
        decision = audit["Decision"].strip()
        field = audit["Field"].strip()
        if decision in {"DUPLICATE", "REVIEW"}:
            drop_ids.add(golden_id)
            continue
        if decision != "CORRECTED":
            continue

        row = rows_by_id[golden_id]
        proposed = audit["Proposed_Value"].strip()
        if field in FIELD_TO_REF:
            row[FIELD_TO_REF[field]] = proposed
            confidence = audit.get("Confidence", "").strip()
            if confidence:
                row[FIELD_TO_CONFIDENCE[field]] = confidence
            evidence_text = audit.get("Evidence_Text", "").strip()
            if evidence_text:
                row[FIELD_TO_EVIDENCE[field]] = evidence_text
        elif field == "Reference_Date":
            row["Reference_Date"] = proposed
        elif field == "Organisation":
            row["Organisation"] = proposed
            row["Organisation_Key"] = organisation_key(proposed)

        row["Reviewed_At"] = audit["Reviewed_At"].strip()
        try:
            current_version = int(row.get("Golden_Version", "1"))
        except ValueError:
            current_version = 1
        row["Golden_Version"] = str(max(current_version, target_version))

    return [
        rows_by_id[row["Golden_ID"]]
        for row in golden_rows
        if row["Golden_ID"] not in drop_ids
    ]


def _finding(
    severity: str,
    code: str,
    row: dict[str, str],
    *,
    field: str = "",
    current: str = "",
    suggested: str = "",
    related: str = "",
    message: str,
) -> dict[str, str]:
    return {
        "Severity": severity,
        "Code": code,
        "Golden_ID": row.get("Golden_ID", ""),
        "Related_Golden_ID": related,
        "Field": field,
        "Current_Value": current,
        "Suggested_Value": suggested,
        "Message": message,
    }


def quality_report(
    golden_rows: list[dict[str, str]], audit_rows: list[dict[str, str]] | None = None
) -> dict[str, object]:
    """Mesure la qualité du juge lui-même et émet des signaux de revue déterministes."""
    audit_rows = audit_rows or []
    effective_rows = apply_audit(golden_rows, audit_rows) if audit_rows else deepcopy(golden_rows)
    findings: list[dict[str, str]] = []

    reviewed_ids = {row.get("Golden_ID", "") for row in audit_rows if row.get("Decision") != "REVIEW"}
    unresolved_review = {row.get("Golden_ID", "") for row in audit_rows if row.get("Decision") == "REVIEW"}
    corrected = sum(row.get("Decision") == "CORRECTED" for row in audit_rows)
    duplicate_decisions = sum(row.get("Decision") == "DUPLICATE" for row in audit_rows)

    confidence: dict[str, Counter[str]] = {
        field: Counter(row.get(f"{field}_Confidence", "") for row in effective_rows)
        for field in ("Secteur", "Menace", "Localisation")
    }

    urls_present = 0
    generic_evidence = 0
    for row in effective_rows:
        urls = _split_multi(row.get("Source_URLs", ""))
        if urls:
            urls_present += 1
        elif any(row.get(f"{field}_Confidence") == "HIGH" for field in ("Secteur", "Menace", "Localisation")):
            findings.append(
                _finding(
                    "WARN",
                    "HIGH_WITHOUT_SOURCE_URL",
                    row,
                    message="au moins un champ HIGH sans URL de source rejouable",
                )
            )

        for field in ("Secteur", "Menace", "Localisation"):
            evidence = searchable(row.get(f"{field}_Evidence", ""))
            if evidence and any(evidence.startswith(prefix) for prefix in _GENERIC_EVIDENCE_PREFIXES):
                generic_evidence += 1
                findings.append(
                    _finding(
                        "WARN",
                        "GENERIC_EVIDENCE",
                        row,
                        field=field,
                        current=row.get(f"{field}_REF", ""),
                        message="preuve générique : la décision n'est pas suffisamment ré-exécutable",
                    )
                )

        threat_evidence = row.get("Menace_Evidence", "")
        inferred = classify_threat(threat_evidence)
        current = row.get("Menace_REF", "")
        specific = {
            config.THREAT_RANSOMWARE,
            config.THREAT_DDOS,
            config.THREAT_MALWARE,
            config.THREAT_ACCOUNT,
            config.THREAT_LEAK,
            config.THREAT_PHISHING,
            config.THREAT_THIRD_PARTY,
        }
        if inferred in specific and current != inferred:
            findings.append(
                _finding(
                    "WARN",
                    "THREAT_POLICY_MISMATCH",
                    row,
                    field="Menace",
                    current=current,
                    suggested=inferred,
                    message="la preuve textuelle suggère une classe spécifique prioritaire différente",
                )
            )

    by_org: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in effective_rows:
        key = (row.get("Organisation_Key") or organisation_key(row.get("Organisation", ""))).strip()
        if key:
            by_org[key].append(row)
    duplicate_pairs = 0
    for org_rows in by_org.values():
        ordered = sorted(org_rows, key=lambda row: row.get("Reference_Date", ""))
        for i, left in enumerate(ordered):
            left_date = _iso_date(left.get("Reference_Date", ""))
            if not left_date:
                continue
            for right in ordered[i + 1 :]:
                right_date = _iso_date(right.get("Reference_Date", ""))
                if not right_date:
                    continue
                days = abs((right_date - left_date).days)
                if days > 3:
                    break
                duplicate_pairs += 1
                findings.append(
                    _finding(
                        "WARN",
                        "POSSIBLE_DUPLICATE",
                        left,
                        field="Incident",
                        related=right.get("Golden_ID", ""),
                        message=f"même organisation à {days} jour(s) d'écart ; vérifier qu'il s'agit de deux incidents distincts",
                    )
                )

    base_by_id = {row.get("Golden_ID", ""): row for row in golden_rows}
    for golden_id in sorted(unresolved_review):
        row = base_by_id.get(golden_id, {"Golden_ID": golden_id})
        findings.append(
            _finding("WARN", "UNRESOLVED_REVIEW", row, message="cas exclu du benchmark tant que la revue n'est pas tranchée")
        )

    return {
        "base_cases": len(golden_rows),
        "effective_cases": len(effective_rows),
        "reviewed_cases": len(reviewed_ids),
        "review_coverage_pct": round(100.0 * len(reviewed_ids) / len(golden_rows), 1) if golden_rows else 0.0,
        "audit_decisions": len(audit_rows),
        "corrected_fields": corrected,
        "duplicates_removed": duplicate_decisions,
        "unresolved_review_cases": len(unresolved_review),
        "source_url_coverage": {
            "count": urls_present,
            "pct": round(100.0 * urls_present / len(effective_rows), 1) if effective_rows else 0.0,
        },
        "confidence": {field: dict(counter) for field, counter in confidence.items()},
        "generic_evidence_findings": generic_evidence,
        "possible_duplicate_pairs": duplicate_pairs,
        "findings_count": len(findings),
        "findings": findings,
        "effective_rows": effective_rows,
    }
