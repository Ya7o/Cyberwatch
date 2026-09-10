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
_EDITORIAL_TITLE = re.compile(
    r"^(?=[^:\n]{2,80}:\s+)(?=.*\b(?:cyberattaque|ransomware|attaque|intrusion|fuite|pirat\w*|"
    r"donn[ée]es|menac[ée]s?|revendiqu[ée]s?|publie\w*\s+(?:\d[\d\s ,.]*\s+)?"
    r"(?:r[ée]servations|fichiers?|bases?))\b).+$",
    re.I,
)


_MARKDOWN_EMPHASIS_RE = re.compile(r"\*\*(.+?)\*\*|__(.+?)__")
#: Marqueur de gras resté ouvert : un paragraphe source coupé laisse un `**`
#: sans fermeture, que la substitution par paires ne peut pas atteindre.
_MARKDOWN_DANGLING_RE = re.compile(r"\*{2,}")


def strip_markdown_emphasis(text: str) -> str:
    """Retire le gras Markdown (`**...**`/`__...__`) qui a pu fuiter tel quel
    depuis un article source (constaté sur FRENCHBREACHES) — garde le texte,
    jamais la syntaxe d'édition.

    À n'appliquer qu'aux textes affichés : les citations brutes conservées pour
    l'audit gardent leur syntaxe d'origine.
    """
    cleaned = _MARKDOWN_EMPHASIS_RE.sub(lambda m: m.group(1) or m.group(2), str(text or ""))
    return " ".join(_MARKDOWN_DANGLING_RE.sub("", cleaned).split())


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
    # Un deux-points reste interdit pour les listes et les libellés de faits,
    # mais il est courant dans un vrai titre éditorial (« Organisation :
    # attaque… »). Le rejeter sans nuance privait notamment les articles
    # Cyberattaque.org d'une headline source pourtant directement prouvée.
    if ": " in text and not _EDITORIAL_TITLE.match(text):
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


def is_organisation_name_only(value: object, organisation: object) -> bool:
    """Un nom de victime n'est jamais une headline d'incident."""
    text = " ".join(str(value or "").split()).strip().casefold().rstrip(".")
    org = " ".join(str(organisation or "").split()).strip().casefold().rstrip(".")
    return bool(text and org and text == org)


def victim_claims_incident(value: object, organisation: object) -> bool:
    """Détecte l'inversion de rôle « la victime revendique l'attaque »."""
    text = " ".join(str(value or "").split()).strip().casefold()
    org = " ".join(str(organisation or "").split()).strip().casefold()
    if not text or not org:
        return False
    # Un titre passif (« Foo : attaque revendiquée par X ») reste valide.
    return bool(re.match(rf"^{re.escape(org)}\s+(?:affirme\s+)?revendiqu\w*\b", text))


def victim_self_reports_incident(value: object, organisation: object) -> bool:
    """Détecte une confirmation attribuée grammaticalement à la victime."""
    text = " ".join(str(value or "").split()).strip().casefold()
    org = " ".join(str(organisation or "").split()).strip().casefold()
    if not text or not org or not text.startswith(org):
        return False
    tail = text[len(org):]
    return bool(re.search(
        r"^.{0,60}\b(?:a\s+)?(?:déclaré|confirmé|annoncé|indiqué)\b.{0,50}"
        r"\b(?:subi|victime|fait l['’]objet)\b",
        tail,
    ))


def summary_role_is_supported(value: object, evidence: object, organisation: object) -> bool:
    """Une déclaration de victime doit apparaître avec le même rôle dans la preuve."""
    if not victim_self_reports_incident(value, organisation):
        return True
    return victim_self_reports_incident(evidence, organisation)


def is_publishable_for_organisation(value: object, organisation: object) -> bool:
    return bool(
        is_publishable_headline(value)
        and not is_organisation_name_only(value, organisation)
        and not victim_claims_incident(value, organisation)
    )


def is_publishable_headline(value: object) -> bool:
    return not rejection_reason(value)
