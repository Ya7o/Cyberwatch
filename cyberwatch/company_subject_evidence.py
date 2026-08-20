"""Preuve Sector officielle avec attribution explicite du sujet.

Une activité trouvée sur le site officiel n'est pas suffisante : la phrase doit
attribuer cette activité à l'organisation victime elle-même (nom de la victime
ou première personne). Cela ferme notamment le cas STOR Solutions où une page
décrivait Iagona, son fournisseur, comme « fabricant ».
"""
from __future__ import annotations

import re

from . import company_evidence, config, official_site_discovery
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
_EXTRA_PATTERNS = {
    config.SECTOR_RETAIL: (
        9,
        r"\b(supermarch[ée]s|fournisseur de mat[ée]riel agricole|"
        r"vente(?: et r[ée]paration)? de mat[ée]riel agricole|"
        r"distribution de mat[ée]riel agricole|"
        r"large gamme de mat[ée]riel agricole|"
        r"vente et location de (?:solutions|mat[ée]riel) de manutention)\b",
    ),
    config.SECTOR_CONSTRUCTION: (
        11,
        r"\b(leader(?: européen| europeen| mondial)? (?:du |de la )?(?:btp|construction)|"
        r"acteur(?: majeur| de référence| de reference)? (?:du |de la )?(?:btp|construction)|"
        r"construction et (?:concessions?|travaux publics)|"
        r"r[ée]novation (?:sur[- ]mesure )?de l['’]habitat|"
        r"r[ée]novation de l['’]habitat|pose de fen[êe]tres|pose de volets|pose de portes)\b",
    ),
    config.SECTOR_SPORT: (
        9,
        r"\b(salle de r[ée]alit[ée] virtuelle[^.;]{0,80}\besport\b|"
        r"esport[^.;]{0,80}\bsalle de r[ée]alit[ée] virtuelle\b|"
        r"free roaming[^.;]{0,80}\besport\b)\b",
    ),
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
    matched_tokens = sum(token in normalized for token in tokens)
    if matched_tokens < required:
        return False

    near = prefix[-100:]
    if match_start <= 140:
        org_norm = searchable(organisation)
        sentence_start = searchable(sentence[: min(match_start, 120)])
        if org_norm and sentence_start.startswith(org_norm):
            return True
        if matched_tokens >= required and re.search(r"[|:\-–]\s*[^|:\-–]{0,70}$", near):
            return True

    return bool(_COPULA_RE.search(prefix[-140:]))


def _activity_matches(sentence: str) -> list[tuple[int, str, re.Match[str]]]:
    matches: list[tuple[int, str, re.Match[str]]] = []
    rules = dict(company_evidence._ACTIVITY_PATTERNS)
    for sector, value in _EXTRA_PATTERNS.items():
        weight, pattern = value
        match = re.search(pattern, sentence, re.I)
        if match:
            matches.append((weight, sector, match))
    for sector, (weight, pattern) in rules.items():
        match = re.search(pattern, sentence, re.I)
        if match:
            matches.append((weight, sector, match))
    return matches


def classify_subject_attributed_activity_scored(
    organisation: str,
    text: str,
) -> tuple[str, str, int] | None:
    """Retourne le meilleur secteur attribué au sujet avec son score de preuve."""
    for sentence in _sentences(text):
        matches = _activity_matches(sentence)
        if not matches:
            continue
        matches.sort(key=lambda row: (-row[0], row[1], row[2].start()))
        top = matches[0]
        if top[0] < 8:
            continue
        competing = [row for row in matches[1:] if row[1] != top[1]]
        if competing and top[0] < competing[0][0] + 2:
            continue
        if not _org_is_subject(organisation, sentence, top[2].start()):
            continue
        return top[1], sentence[:500], top[0]
    return None


def classify_subject_attributed_activity(
    organisation: str,
    text: str,
) -> tuple[str, str] | None:
    scored = classify_subject_attributed_activity_scored(organisation, text)
    if scored is None:
        return None
    sector, sentence, _score = scored
    return sector, sentence


def strong_subject_attributed_activity(
    organisation: str,
    text: str,
    *,
    minimum_score: int = 10,
) -> tuple[str, str] | None:
    """N'accepte que les formulations officielles suffisamment discriminantes."""
    scored = classify_subject_attributed_activity_scored(organisation, text)
    if scored is None or scored[2] < minimum_score:
        return None
    return scored[0], scored[1]


def resolve_official_site_subject_attributed(
    organisation: str,
    candidate_urls: tuple[str, ...] | list[str] | None = None,
) -> company_evidence.CompanyEvidence | None:
    try:
        candidates = (
            list(candidate_urls)
            if candidate_urls is not None
            else official_site_discovery.discover_official_sites(organisation)
        )
    except Exception:
        return None

    for candidate in candidates:
        if not official_site_discovery.domain_matches_organisation(organisation, candidate):
            continue
        priority, body, about_links, final_url = company_evidence._page(candidate)
        if not priority and not body:
            continue
        evidence_url = final_url or candidate
        if not official_site_discovery.domain_matches_organisation(organisation, evidence_url):
            continue
        if not company_evidence._identity_matches(organisation, evidence_url, priority, body):
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
            if not official_site_discovery.domain_matches_organisation(organisation, link):
                continue
            p_priority, p_body, _links, p_final = company_evidence._page(link)
            if not p_priority and not p_body:
                continue
            page_url = p_final or link
            if not official_site_discovery.domain_matches_organisation(organisation, page_url):
                continue
            if not company_evidence._identity_matches(organisation, page_url, p_priority, p_body):
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
