"""Adaptateur de publication du schéma rich_facts v2 vers le dashboard actuel."""
from __future__ import annotations

from ..normalize import searchable
from . import cyberattaque_rich as _rich_module
from .cyberattaque_rich import CyberattaqueRichCollector

_DISPLAY_STATUSES = {"confirmed", "reported", "claimed", "unknown"}
_STATUS_SCOPE = {"hypothesis": "Hypothèse", "denied": "Démenti", "negated": "Négation"}


def _status_v2(sentence: str) -> str:
    """La modalité de la proposition prime sur une négation de confirmation voisine."""
    if _rich_module._DENIED.search(sentence):
        return "denied"
    if _rich_module._HYPOTHESIS.search(sentence):
        return "hypothesis"
    if _rich_module._NEGATION.search(sentence):
        return "negated"
    if _rich_module._CONFIRMED.search(sentence):
        return "confirmed"
    if _rich_module._CLAIMED.search(sentence):
        return "claimed"
    if _rich_module._REPORTED.search(sentence):
        return "reported"
    return "unknown"


# Les extracteurs du module v2 résolvent `_status` à l'exécution : cette
# substitution garde le moteur unique tout en corrigeant la priorité de modalité.
_rich_module._status = _status_v2


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
    # Les relations (sujet/prédicat/objet) ne sont volontairement pas projetées ici :
    # fact_resolution.py::_relation_claim_entries() lit déjà rich_facts.relations
    # directement et les traduit en champs métier lisibles (Acteur, Tiers impliqué).
    # Un join brut "sujet → relation → objet" n'est jamais une phrase publiable
    # (cf. doctrine "précision > taux de remplissage", METHODOLOGY.md §13) ; une
    # relation non couverte par un champ métier reste donc simplement absente
    # plutôt que montrée à l'utilisateur sous forme de jargon d'extraction.
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
