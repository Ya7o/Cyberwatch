"""Preuves textuelles transmises au filet LLM de déduplication.

L'audit du 10 septembre 2026 a montré que le filet recevait une entrée bien plus
pauvre que l'extraction : titres, identités, dates, menace déjà classée et
quelques SourceFacts, avec un ``Editorial_Evidence`` vide et sans secteur ni
localisation. Réactiver le modèle ne lui aurait donc pas donné les preuves
géographiques ni les réserves présentes dans l'article.

Ce module produit la part textuelle de cette entrée. Il travaille par
**paragraphes entiers** : quand le budget impose une réduction, on retire des
paragraphes, jamais des caractères au milieu d'une phrase. Un paragraphe est
retenu s'il porte l'identité de la victime, une date, l'événement lui-même ou
une réserve explicite — les quatre choses dont une décision de fusion dépend.
"""

from __future__ import annotations

import re

from . import article_body, threat_reservation
from .normalize import searchable

#: Version de la sélection, tracée avec la charge utile : un cache de paire
#: reste ainsi rattachable aux règles qui l'ont produit.
EVIDENCE_VERSION = "dedup-evidence-2026-09-10.1"

_PARAGRAPH_RE = re.compile(r"\n\s*\n+")

_DATE_RE = re.compile(
    r"\b\d{1,2}\s+(?:janvier|f[ée]vrier|mars|avril|mai|juin|juillet|ao[ûu]t|"
    r"septembre|octobre|novembre|d[ée]cembre)\b|\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b",
    re.I,
)

_EVENT_RE = re.compile(
    r"\b(?:cyberattaque|cyber-attaque|attaque informatique|piratage|intrusion|"
    r"ran[çc]ongiciel|ransomware|fuite de donn[ée]es|violation de donn[ée]es|"
    r"incident de s[ée]curit[ée]|compromission|exfiltration|prestataire)\b",
    re.I,
)


def paragraphs(text: str) -> list[str]:
    """Paragraphes du texte, espaces internes normalisés, ordre conservé."""
    blocks = [" ".join(block.split()) for block in _PARAGRAPH_RE.split(text or "")]
    return [block for block in blocks if block]


def _mentions_organisation(block: str, organisation: str) -> bool:
    needle = searchable(organisation)
    if not needle:
        return False
    if searchable(block).find(needle) >= 0:
        return True
    # « Ville du Tampon » et « mairie du Tampon » désignent la même victime :
    # le mot distinctif du nom suffit à rattacher le paragraphe.
    tokens = [token for token in needle.split() if len(token) > 3]
    return bool(tokens) and searchable(block).find(tokens[-1]) >= 0


def _reserved_blocks(text: str) -> set[str]:
    """Paragraphes portant une réserve explicite, à conserver en priorité."""
    reserved = threat_reservation.reserved(text)
    sentences = {" ".join(sentence.split()) for _, sentence in reserved.values()}
    return {block for block in paragraphs(text) if any(s and s in block for s in sentences)}


def relevant_paragraphs(text: str, organisation: str) -> list[str]:
    """Paragraphes liés à l'identité, aux dates, à l'événement ou aux réserves."""
    reserved = _reserved_blocks(text)
    keep: list[str] = []
    for block in paragraphs(text):
        if (
            block in reserved
            or _mentions_organisation(block, organisation)
            or _DATE_RE.search(block)
            or _EVENT_RE.search(block)
        ):
            keep.append(block)
    return keep


def select(text: str, organisation: str, budget: int) -> tuple[str, str]:
    """Preuves textuelles pour une victime, et le motif de leur réduction.

    Rend ``(texte, motif)`` où le motif vaut ``""`` si le corps nettoyé tient
    dans le budget, ``PARAGRAPH_SELECTION`` si des paragraphes entiers ont été
    écartés, et ``NO_PARAGRAPH_FITS`` si même le premier n'entre pas — cas où
    la paire doit être différée plutôt que tronquée.
    """
    body = article_body.body(text)
    if not body:
        return "", ""
    if len(body) <= budget:
        return body, ""

    kept: list[str] = []
    used = 0
    for block in relevant_paragraphs(body, organisation):
        cost = len(block) + (2 if kept else 0)
        if used + cost > budget:
            continue
        kept.append(block)
        used += cost
    if not kept:
        return "", "NO_PARAGRAPH_FITS"
    return "\n\n".join(kept), "PARAGRAPH_SELECTION"


def reservation_payload(text: str) -> dict:
    """Réserve explicite de l'article, telle qu'elle sera lue par le modèle."""
    decision = threat_reservation.decision(article_body.body(text))
    if not decision:
        return {}
    return {
        "value": decision["value"],
        "reserved": decision["reserved"],
        "markers": decision["markers"],
        "evidence": decision["evidence"],
    }
