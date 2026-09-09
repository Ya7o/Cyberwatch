"""Résolution de la relation entre vulnérabilités citées et incident."""
from __future__ import annotations

import re
from typing import Iterable

from .fact_resolution_counts import _norm, _ordered_facts, _status, _text


VULNERABILITY_INCIDENT_LINK_RE = re.compile(
    r"\b(?:attaque|incident|intrusion|acc[èe]s initial|point d['’]entr[ée]e)\b.{0,120}"
    r"\b(?:exploit[ée]e?|utilis[ée]e?)\b.{0,80}\bCVE-\d{4}-\d+\b|"
    r"\bCVE-\d{4}-\d+\b.{0,120}\b(?:[àa] l['’]origine|vecteur|"
    r"point d['’]entr[ée]e|exploit[ée]e? (?:pour|lors de|dans))\b",
    re.I,
)
_UNCERTAIN_RE = re.compile(
    r"\b(?:rien|aucun [ée]l[ée]ment)\b.{0,100}\b(?:affirmer|[ée]tablir|relier)|"
    r"\b(?:moins cr[ée]dible|hypoth[èe]se|potentielle?|candidate?)\b",
    re.I,
)
_GENERIC_VALUES = {
    "corrected", "corrige", "corrigee", "correction",
    "vulnerability", "vulnerabilite", "faille",
}
_RELATIONSHIP_RANK = {"mentioned": 0, "candidate": 1, "exploited": 2}


def resolve_vulnerabilities(facts: Iterable[dict], claims: Iterable[dict]) -> list[dict]:
    """Conserve statut, preuve et relation jusqu'au contrat public."""
    selected: dict[str, dict] = {}

    def add(raw: dict, source: str, initial_access: str = "") -> None:
        value = _text(raw.get("value"))
        if not value or _norm(value) in _GENERIC_VALUES:
            return
        is_cve = bool(re.fullmatch(r"CVE-\d{4}-\d+", value, re.I))
        evidence = _text(raw.get("evidence"))
        status = _status(raw)
        if status in {"negated", "denied"} or (status == "hypothesis" and not is_cve):
            return
        relationship = _norm(raw.get("relationship"))
        if relationship not in _RELATIONSHIP_RANK:
            if _norm(initial_access) == "vulnerability exploitation":
                relationship = "exploited"
            elif status == "hypothesis" or _UNCERTAIN_RE.search(evidence):
                relationship = "candidate"
            elif VULNERABILITY_INCIDENT_LINK_RE.search(evidence):
                relationship = "exploited"
            else:
                relationship = "mentioned"
        key = _norm(value)
        entry = {
            "value": value.upper() if is_cve else value,
            "relationship": relationship,
            "status": status,
            "source": source,
            "sources": [source] if source else [],
        }
        if evidence:
            entry["evidence"] = evidence
        existing = selected.get(key)
        if existing is None:
            selected[key] = entry
            return
        if _RELATIONSHIP_RANK[relationship] > _RELATIONSHIP_RANK[existing["relationship"]]:
            entry["sources"] = list(dict.fromkeys(existing.get("sources", []) + entry["sources"]))
            selected[key] = entry
        elif source and source not in existing["sources"]:
            existing["sources"].append(source)

    for fact in _ordered_facts(facts):
        source = _text(fact.get("source"))
        rich = fact.get("rich_facts") if isinstance(fact.get("rich_facts"), dict) else {}
        for raw in rich.get("vulnerabilities", []) if isinstance(rich, dict) else []:
            if isinstance(raw, dict):
                add(raw, source, _text(fact.get("initial_access")))
        rich_values = {
            _norm(raw.get("value")) for raw in rich.get("vulnerabilities", [])
            if isinstance(raw, dict)
        }
        legacy = fact.get("vulnerabilities")
        for value in legacy if isinstance(legacy, list) else []:
            if _norm(value) not in rich_values:
                add({"value": value, "status": fact.get("claim_status")}, source,
                    _text(fact.get("initial_access")))
    for claim in claims:
        if isinstance(claim, dict) and claim.get("type") == "vulnerability":
            add(claim, _text(claim.get("source")))
    return list(selected.values())
