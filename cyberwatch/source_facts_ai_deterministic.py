"""Extraction déterministe des faits mécaniques.

Ces graines sont produites sans appel réseau, à partir de motifs explicites
observés dans le corps de l'article. Elles restent la couche la plus faible de
la fusion : le cache puis la réponse LLM validée les recouvrent.
"""

from __future__ import annotations

import re

from .collectors.base import RawEntry
from .source_facts_ai_contract import (
    DATA_TYPES_UNDISCLOSED_LABEL,
    MAX_EVIDENCE_CHARS,
    _DATA_RELATION,
    _DATA_TYPES_UNDISCLOSED_RE,
    _DATA_TYPE_PATTERNS,
    _GENERIC_EXPLAINER_RE,
    _HYPOTHETICAL_RE,
    _IMPACT_TRIGGER,
    _INITIAL_ACCESS_UNCERTAIN_RE,
    _INITIAL_ACCESS_UNKNOWN_RE,
    _NEGATED_DATA_RELATION,
    _NEGATED_DATA_VALUE_SENTENCE,
    _RESPONSE_ACTION_RE,
)
from .source_facts_ai_normalize import (
    _NON_EXPOSURE_DATA_CONTEXT_RE,
    _full_context,
    _negated_data_type,
)
from .normalize import searchable


_INITIAL_ACCESS_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("compromised_credentials", re.compile(
        r"(?:\b(?:intrusion|acc[èe]s|connexion|p[ée]n[ée]tr\w*)\b.{0,120}\b(?:compte|identifiants?|credentials?)\b.{0,70}\bcompromis\w*\b|"
        r"\b(?:compte|identifiants?|credentials?)\b.{0,70}\bcompromis\w*\b.{0,120}\b(?:intrusion|acc[èe]s|utilis[ée]\w*|p[ée]n[ée]tr\w*)\b)", re.I)),
    ("phishing", re.compile(
        r"\b(?:phishing|hame[cç]onnage)\b.{0,120}\b(?:a\s+permis|ayant\s+permis|permettant|acc[èe]s|intrusion|compte)\b", re.I)),
    ("vulnerability_exploitation", re.compile(
        r"(?:\bexploit\w*\b.{0,100}\b(?:vuln[ée]rabilit[ée]|faille|IDOR|injection\s+SQL|CVE-\d{4}-\d+)\b|"
        r"\b(?:vuln[ée]rabilit[ée]|faille|IDOR|injection\s+SQL|CVE-\d{4}-\d+)\b.{0,120}\b(?:a\s+permis|ayant\s+permis|permettant)\b.{0,80}\b(?:acc[èe]s|intrusion|compromission)\b)", re.I)),
    ("third_party", re.compile(
        r"\b(?:via|chez)\b.{0,80}\b(?:prestataire|fournisseur|sous[- ]traitant|tiers)\b.{0,80}\bcompromis\w*\b", re.I)),
    ("remote_access", re.compile(
        r"\b(?:RDP|VPN|bureau\s+[àa]\s+distance|acc[èe]s\s+distant)\b.{0,100}\b(?:compromis|exploit[ée]|intrusion|acc[èe]s\s+non\s+autoris[ée])\b", re.I)),
)


def _deterministic_initial_access(context: str) -> dict | None:
    if (
        not context
        or _INITIAL_ACCESS_UNKNOWN_RE.search(context)
        or _INITIAL_ACCESS_UNCERTAIN_RE.search(context)
    ):
        return None
    for segment in re.split(r"(?<=[.!?;])\s+|\n+", context):
        cleaned = " ".join(segment.split()).strip()
        if (
            not cleaned
            or _HYPOTHETICAL_RE.search(cleaned)
            or _GENERIC_EXPLAINER_RE.search(cleaned)
            or re.search(
                r"\b(?:le contexte actuel|indices? (?:qui )?orientent|"
                r"r[ée]cemment corrig[ée]e?|hypoth[èe]se)\b",
                cleaned,
                re.I,
            )
        ):
            continue
        for category, pattern in _INITIAL_ACCESS_PATTERNS:
            if pattern.search(cleaned):
                evidence = cleaned[:MAX_EVIDENCE_CHARS]
                return {"value": category, "confidence": 1.0, "evidence": evidence}
    return None


def _deterministic_data_types(context: str) -> list[dict]:
    if not context:
        return []
    result: list[dict] = []
    seen: set[str] = set()
    for canonical, pattern in _DATA_TYPE_PATTERNS:
        for match in pattern.finditer(context):
            sentence_start = max(
                context.rfind(".", 0, match.start()),
                context.rfind("!", 0, match.start()),
                context.rfind("?", 0, match.start()),
                context.rfind("\n", 0, match.start()),
            ) + 1
            sentence_ends = [
                point for point in (
                    context.find(".", match.end()),
                    context.find("!", match.end()),
                    context.find("?", match.end()),
                    context.find("\n", match.end()),
                )
                if point >= 0
            ]
            sentence_end = min(sentence_ends) + 1 if sentence_ends else len(context)
            sentence = context[sentence_start:sentence_end]
            start = max(0, match.start() - 180)
            end = min(len(context), match.end() + 180)
            window = context[start:end]
            if (
                _NEGATED_DATA_VALUE_SENTENCE.search(sentence)
                or _NEGATED_DATA_RELATION.search(window)
                or _NON_EXPOSURE_DATA_CONTEXT_RE.search(sentence)
                or _negated_data_type(canonical, match.group(0), context)
                or not _DATA_RELATION.search(window)
            ):
                continue
            key = searchable(canonical)
            if key in seen:
                break
            seen.add(key)
            result.append({"value": canonical, "confidence": 1.0, "evidence": match.group(0).strip()})
            break
    if not result:
        # Aucune catégorie précise n'a été trouvée : si l'article affirme
        # explicitement une exfiltration/exposition tout en indiquant que le
        # détail n'est pas communiqué, ce fait négatif est conservé plutôt que
        # de laisser une fiche vide indistincte d'une absence d'extraction.
        undisclosed = _DATA_TYPES_UNDISCLOSED_RE.search(context)
        if undisclosed and _DATA_RELATION.search(context) and not _NEGATED_DATA_RELATION.search(context):
            result.append({
                "value": DATA_TYPES_UNDISCLOSED_LABEL,
                "confidence": 1.0,
                "evidence": undisclosed.group(0).strip(),
            })
    return result


def _deterministic_impact(context: str) -> dict | None:
    for segment in re.split(r"(?<=[.!?;])\s+|\n+", context or ""):
        cleaned = " ".join(segment.split()).strip()
        if not cleaned or not _IMPACT_TRIGGER.search(cleaned):
            continue
        if _HYPOTHETICAL_RE.search(cleaned) or _RESPONSE_ACTION_RE.search(cleaned):
            continue
        evidence = cleaned[:MAX_EVIDENCE_CHARS]
        return {"value": evidence, "confidence": 1.0, "evidence": evidence}
    return None


def _deterministic_seed(entry: RawEntry) -> dict:
    context = _full_context(entry)
    seed: dict = {}
    data_types = _deterministic_data_types(context)
    if data_types:
        seed["data_types"] = data_types
    initial_access = _deterministic_initial_access(context)
    if initial_access:
        seed["initial_access"] = initial_access
    impact = _deterministic_impact(context)
    if impact:
        seed["impact"] = impact
    return seed
