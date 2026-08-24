"""Contrats bloquants entre les faits résolus et le dashboard publié."""
from __future__ import annotations

from collections import Counter


# Une source peut légitimement ne pas fournir d'URL directe. Dans ce cas le
# contrat exige une explication ``no_direct_url`` par source, pas une URL
# inventée au niveau de l'incident.
REQUIRED_INCIDENT_FIELDS = ("id", "org", "date", "threat", "sources")
SUMMARY_ABSENCE_STATUSES = {
    "missing_content", "abstained", "rejected_quality", "technical_failure",
}


def audit_payload(
    incidents: list[dict],
    facts: dict[str, dict],
    report: dict | None = None,
) -> dict:
    """Audit déterministe, sans réinterpréter ni modifier les données."""
    errors: list[dict] = []
    warnings: list[dict] = []
    ids = [str(row.get("id") or "") for row in incidents]
    duplicates = sorted(key for key, count in Counter(ids).items() if key and count > 1)
    if duplicates:
        errors.append({"issue": "duplicate_incident_id", "ids": duplicates})
    report_rows = (report or {}).get("incidents", []) if isinstance(report, dict) else []
    by_report_id = {
        str(row.get("incident_id") or ""): row
        for row in report_rows if isinstance(row, dict) and row.get("incident_id")
    }
    if report is not None and len(by_report_id) != len(incidents):
        errors.append({
            "issue": "incident_report_coverage",
            "expected": len(incidents),
            "actual": len(by_report_id),
        })

    for row in incidents:
        incident_id = str(row.get("id") or "")
        missing = [field for field in REQUIRED_INCIDENT_FIELDS if not row.get(field)]
        if missing:
            errors.append({"issue": "missing_required_incident_field", "id": incident_id, "fields": missing})
        if incident_id not in facts:
            errors.append({"issue": "missing_resolved_facts", "id": incident_id})
        sources = [str(value) for value in row.get("sources", []) if value]
        links = row.get("source_links", [])
        link_sources = {str(link.get("source") or "") for link in links if isinstance(link, dict) and link.get("url")}
        statuses = {
            str(status.get("source") or ""): str(status.get("status") or "")
            for status in row.get("source_link_status", []) if isinstance(status, dict)
        }
        for source in sources:
            if source not in link_sources and statuses.get(source) != "no_direct_url":
                errors.append({"issue": "unexplained_source_link", "id": incident_id, "source": source})
        if not row.get("summary"):
            report_row = by_report_id.get(incident_id, {})
            status = str(report_row.get("summary_status") or "")
            if status not in SUMMARY_ABSENCE_STATUSES:
                errors.append({"issue": "silent_summary_absence", "id": incident_id})
        report_row = by_report_id.get(incident_id, {})
        gaps = report_row.get("promotion_gaps", []) if isinstance(report_row, dict) else []
        if gaps:
            errors.append({"issue": "semantic_promotion_gap", "id": incident_id, "fields": gaps})
        if row.get("sector") == "Inconnu":
            sector_status = row.get("sector_status") if isinstance(row.get("sector_status"), dict) else {}
            if not sector_status.get("status"):
                errors.append({"issue": "silent_sector_unknown", "id": incident_id})
            else:
                warnings.append({"issue": "sector_unknown", "id": incident_id, "status": sector_status})

    return {
        "schema_version": 1,
        "incidents": len(incidents),
        "errors": errors,
        "warnings": warnings,
        "passed": not errors,
    }
