"""Contrat unique des headlines éditoriales publiables."""
from __future__ import annotations

import re

MAX_HEADLINE_CHARS = 160

_TECHNICAL = re.compile(
    r"\b(?:header\s+html|javascript|css|cookie|lcp|chargement|vitesse\s+d[’']apparition|performance\s+web|navigation|footer|changelog)\b",
    re.I,
)
_STRUCTURED = re.compile(
    r"^(?:vecteur\s+d[’']entr[ée]e\s+document[ée]|impact\s+document[ée]|d[ée]roul[ée]\s+document[ée]|"
    r"[ée]l[ée]ments\s+document[ée]s|donn[ée]es\s+(?:concern[ée]es|expos[ée]es|revendiqu[ée]es))\s*:",
    re.I,
)
_GENERIC = re.compile(
    r"^(?:l[’']incident|la\s+cyberattaque|l[’']attaque|la\s+fuite)\s+(?:a\s+)?"
    r"(?:entra[iî]n[ée]|provoqu[ée]|caus[ée]|confirm[ée])\s+(?:une\s+)?(?:exfiltration|fuite)\s+de\s+donn[ée]es\.?$",
    re.I,
)


def rejection_reason(value: object) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        return "empty"
    if len(text) > MAX_HEADLINE_CHARS:
        return "too_long"
    if "\n" in str(value or "") or text.startswith(("-", "*", "#")) or "**" in text:
        return "markdown_or_list"
    if _STRUCTURED.search(text):
        return "structured_detail"
    if ": " in text:
        return "list_or_prefix"
    if _TECHNICAL.search(text):
        return "technical_fragment"
    if _GENERIC.fullmatch(text):
        return "generic"
    if re.fullmatch(r"[\d\s,.;:%]+", text):
        return "metric_only"
    if len(re.findall(r"[.!?](?:\s|$)", text)) > 1:
        return "multiple_sentences"
    return ""


def is_publishable_headline(value: object) -> bool:
    return not rejection_reason(value)
