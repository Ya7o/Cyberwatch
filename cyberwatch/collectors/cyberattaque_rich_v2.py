"""Adaptateur de publication du schéma rich_facts v2 vers le dashboard actuel."""
from __future__ import annotations

from ..normalize import searchable
from .cyberattaque_rich import CyberattaqueRichCollector

_DISPLAY_STATUSES = {"confirmed", "reported", "claimed", "unknown"}
_STATUS_SCOPE = {"hypothesis": "Hypothèse", "denied": "Démenti", "negated": "Négation"}


def _statement(status: str, scope: str, date: str, evidence: str, value: str = "") -> dict:
    original = status if status else "unknown"
    display_status = original if original in _DISPLAY_STATUSES else "unknown"
    prefix = _STATUS_SCOPE.get(original, "")
    effective_scope = " · ".join(part for part in (prefix, scope) if part)
    row = {"kind": "statement", "status": display_status, "scope": effective_scope, "date": date or "", "evidence": evidence or ""}
    if value:
        row["value"] = value
    return row


def _augment(entry) -> None:
    metadata = dict(entry.source_metadata or {})
    rich = metadata.get("rich_facts")
    if not isinstance(rich, dict) or str(rich.get("version")) != "2":
        return
    claims = list(rich.get("claims") or [])
    existing = {searchable(str(c.get("evidence") or "")) for c in claims if isinstance(c, dict)}

    def add(row: dict) -> None:
        evidence = str(row.get("evidence") or "").strip()
        key = searchable(evidence)
        if not evidence or key in existing:
            return
        claims.append(_statement(str(row.get("status") or "unknown"), str(row.get("scope") or ""), str(row.get("date") or ""), evidence, str(row.get("value") or "")))
        existing.add(key)

    for row in rich.get("data_volumes") or []:
        if isinstance(row, dict):
            labelled = dict(row); labelled["scope"] = labelled.get("scope") or "Volume de données"; add(labelled)
    for row in rich.get("data_types") or []:
        if isinstance(row, dict):
            labelled = dict(row); labelled["scope"] = labelled.get("scope") or "Type de données"; add(labelled)
    for row in rich.get("timeline") or []:
        if isinstance(row, dict):
            labelled = {"status": row.get("status"), "scope": "Chronologie", "date": row.get("date"), "evidence": row.get("evidence"), "value": row.get("event")}; add(labelled)
    for row in rich.get("relations") or []:
        if isinstance(row, dict):
            relation = f"{row.get('subject','')} → {row.get('relation','')} → {row.get('object','')}".strip()
            labelled = {"status": row.get("status"), "scope": "Relation", "date": "", "evidence": row.get("evidence"), "value": relation}; add(labelled)
    for row in rich.get("vulnerabilities") or []:
        if isinstance(row, dict):
            labelled = {"status": row.get("status"), "scope": "Vulnérabilité", "date": "", "evidence": row.get("evidence"), "value": row.get("value")}; add(labelled)

    rich = dict(rich)
    rich["claims"] = claims[:40]
    metadata["rich_facts"] = rich
    entry.source_metadata = metadata


class CyberattaqueRichV2Collector(CyberattaqueRichCollector):
    """Extraction v2 + projection rétrocompatible pour la publication."""

    name = "cyberattaque_org"

    def collect(self, client, spec, window):
        result = super().collect(client, spec, window)
        for entry in result.entries:
            _augment(entry)
        return result
