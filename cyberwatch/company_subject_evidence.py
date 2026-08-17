"""Preuve Sector officielle avec attribution explicite du sujet.

Une activité trouvée sur le site officiel n'est pas suffisante : la phrase doit
attribuer cette activité à l'organisation victime elle-même (nom de la victime
ou première personne). Cela ferme notamment le cas STOR Solutions où une page
décrivait Iagona, son fournisseur, comme « fabricant ».
"""
from __future__ import annotations

import re

from . import company_evidence, config
from .normalize import searchable

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?;])\s+|[\r\n]+")
_FIRST_PERSON_RE = re.compile(
    r"\b(nous|notre (?:entreprise|societe|société|groupe|mission|metier|métier)|"
    r"we|our (?:company|business|group|mission))\b",
    re.I,
)
_COPULA_RE = re.compile(
    r"\b(est|sommes|est un|est une|est le|est la|est l[’']|"
    r"is|are|specialise|spécialis[ée]e?|specialized|specialised|"
    r"propose|fournit|concoit|conçoit|developpe|développe|fabrique|exploite)\b",
    re.I,
)
_THIRD_PARTY_RE = re.compile(
    r"\b(son|sa|ses|leur|leurs|notre|nos)?\s*"
    r"(fournisseur|partenaire|prestataire|sous[- ]traitant|client|hebergeur|hébergeur|"
    r"provider|partner|supplier|vendor|contractor)\b|\bavec\s+[A-ZÀ-Ý0-9]",
    re.I,
)
# Compléments mesurés qui corrigent uniquement des variantes morphologiques
# absentes des regex historiques. Ils restent soumis au même garde de sujet.
_EXTRA_PATTERNS = {
    config.SECTOR_RETAIL: (8, r"\bsupermarch[ée]s\b"),
}


def _sentences(text: str) -> list[str]:
    result: list[str] = []
    for part in _SENTENCE_SPLIT_RE.split(text or ""):
        cleaned = company_evidence._clean(part)
        if 15 <= len(cleaned) <= 900:
            result.append(cleaned)
    return result


def _org_is_subject(organisation: str, sentence: str, match_start: int) -> bool:
    prefix = sentence[max(0, match_start - 220):match_start]
    near_prefix = sentence[max(0, match_start - 120):match_start]
    if _THIRD_PARTY_RE.search(near_prefix):
        return False
    if _FIRST_PERSON_RE.search(prefix):
        return True

    tokens = company_evidence._org_tokens(organisation)
    if not tokens:
        return False
    normalized = searchable(prefix)
    required = min(2, len(tokens))
    if sum(token in normalized for token in tokens) < required:
        return False
    return bool(_COPULA_RE.search(prefix[-140:]))


def _activity_matches(sentence: str) -> list[tuple[int, str, re.Match[str]]]:
    matches: list[tuple[int, str, re.Match[str]]] = []
    rules = dict(company_evidence._ACTIVITY_PATTERNS)
    for sector, value in _EXTRA_PATTERNS.items():
        # Le complément ne remplace pas la règle principale : il l'étend.
        weight, pattern = value
        match = re.search(pattern, sentence, re.I)
        if match:
            matches.append((weight, sector, match))
    for sector, (weight, pattern) in rules.items():
        match = re.search(pattern, sentence, re.I)
        if match:
            matches.append((weight, sector, match))
    return matches


def classify_subject_attributed_activity(
    organisation: str,
    text: str,
) -> tuple[str, str] | None:
    """Retourne un secteur seulement si l'activité a pour sujet la victime."""
    for sentence in _sentences(text):
        matches = _activity_matches(sentence)
        if not matches:
            continue
        matches.sort(key=lambda row: (-row[0], row[1], row[2].start()))
        top = matches[0]
        if top[0] < 8:
            continue
        # Deux motifs du même secteur ne créent pas d'ambiguïté. Deux secteurs
        # proches, eux, rendent la preuve non automatique.
        competing = [row for row in matches[1:] if row[1] != top[1]]
        if competing and top[0] < competing[0][0] + 2:
            continue
        if not _org_is_subject(organisation, sentence, top[2].start()):
            continue
        return top[1], sentence[:500]
    return None


def resolve_official_site_subject_attributed(
    organisation: str,
) -> company_evidence.CompanyEvidence | None:
    """Résout le site officiel puis exige une activité attribuée à la victime."""
    try:
        candidates = company_evidence._discover_official_sites(organisation)
    except Exception:
        return None

    for candidate in candidates:
        priority, body, about_links, final_url = company_evidence._page(candidate)
        if not priority and not body:
            continue
        evidence_url = final_url or candidate
        if not company_evidence._identity_matches(
            organisation, evidence_url, priority, body
        ):
            continue

        for text, url in ((priority, evidence_url), (body[:16000], evidence_url)):
            classified = classify_subject_attributed_activity(organisation, text)
            if classified is not None:
                sector, evidence_text = classified
                return company_evidence.CompanyEvidence(
                    sector=sector,
                    evidence_url=url,
                    evidence_text=evidence_text,
                    evidence_source=company_evidence._domain(url) or "official_site",
                    evidence_type="official_subject_activity",
                )

        for link in about_links:
            p_priority, p_body, _links, p_final = company_evidence._page(link)
            if not p_priority and not p_body:
                continue
            page_url = p_final or link
            if not company_evidence._identity_matches(
                organisation, page_url, p_priority, p_body
            ):
                continue
            classified = classify_subject_attributed_activity(
                organisation,
                company_evidence._clean(" ".join((p_priority, p_body[:12000]))),
            )
            if classified is not None:
                sector, evidence_text = classified
                return company_evidence.CompanyEvidence(
                    sector=sector,
                    evidence_url=page_url,
                    evidence_text=evidence_text,
                    evidence_source=company_evidence._domain(page_url) or "official_site",
                    evidence_type="official_subject_activity",
                )
    return None
