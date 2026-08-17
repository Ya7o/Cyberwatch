"""Découverte déterministe de sites officiels pour la qualification Sector.

Les sources de découverte (hints, Wikidata, moteurs de recherche, guesses de
nom de domaine) ne sont jamais des preuves. Un domaine n'est proposé au
résolveur de preuve que s'il porte une identité compatible avec l'organisation.
La page elle-même doit ensuite passer les gardes d'identité et d'activité de
``company_subject_evidence`` avant toute qualification.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

import requests

from . import company_evidence
from .normalize import searchable

USER_AGENT = company_evidence.USER_AGENT
WIKIDATA_API = "https://www.wikidata.org/w/api.php"
DISCOVERY_TIMEOUT_SECONDS = 6
MAX_CANDIDATES = 8
MAX_WIKIDATA_ENTITIES = 3

_LEGAL_TOKENS = {
    "sas", "sasu", "sa", "sarl", "eurl", "ltd", "limited", "inc", "corp",
    "corporation", "company", "co", "groupe", "group", "holding",
}
_CONNECTOR_TOKENS = {
    "de", "du", "des", "d", "la", "le", "les", "l", "et", "and", "the",
}
_GENERIC_DOMAIN_TOKENS = {
    "france", "international", "national", "nationale", "officiel", "official",
}


def _words(organisation: str) -> list[str]:
    return [
        token
        for token in searchable(organisation).split()
        if len(token) > 1 and token not in _LEGAL_TOKENS and token not in _CONNECTOR_TOKENS
    ]


def _acronym(organisation: str) -> str:
    words = _words(organisation)
    return "".join(word[0] for word in words if word) if len(words) >= 2 else ""


def _normalise_candidate_url(url: str) -> str:
    value = str(url or "").strip()
    if not value:
        return ""
    if value.startswith("//"):
        value = "https:" + value
    elif not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.netloc:
        return ""
    # Les paramètres de tracking n'aident pas à prouver l'identité. En revanche,
    # un path explicite fourni comme hint peut pointer directement sur la page
    # institutionnelle utile, donc il est conservé.
    return urlunparse((parsed.scheme or "https", parsed.netloc, parsed.path or "/", "", "", ""))


def domain_matches_organisation(organisation: str, url: str) -> bool:
    """Garde de propriété de domaine, sans fuzzy matching.

    Une page qui mentionne la victime n'est pas automatiquement officielle. Le
    domaine doit contenir un token distinctif de l'organisation, sa forme
    compacte ou un acronyme déterministe (ex. Bibliothèque nationale de France
    -> bnf.fr).
    """
    domain = company_evidence._domain(url)
    if not domain or company_evidence._blocked(url):
        return False

    domain_text = searchable(domain.replace(".", " ").replace("-", " "))
    domain_compact = re.sub(r"[^a-z0-9]", "", searchable(domain))
    words = _words(organisation)
    if not words:
        return False

    distinctive = [
        word for word in words
        if len(word) >= 3 and word not in _GENERIC_DOMAIN_TOKENS
    ]
    if any(word in domain_text.split() or word in domain_compact for word in distinctive):
        return True

    compact = "".join(words)
    if len(compact) >= 4 and compact in domain_compact:
        return True

    acronym = _acronym(organisation)
    if len(acronym) >= 3 and (
        domain_compact.startswith(acronym) or acronym in domain_text.split()
    ):
        return True
    return False


def _direct_domain_guesses(organisation: str) -> list[str]:
    words = _words(organisation)
    if not words:
        return []

    aliases: list[str] = []
    distinctive = [w for w in words if w not in _GENERIC_DOMAIN_TOKENS]
    bases = distinctive or words
    for alias in ("-".join(bases), "".join(bases), _acronym(organisation)):
        alias = re.sub(r"[^a-z0-9-]", "", alias)
        if len(alias) >= 3 and alias not in aliases:
            aliases.append(alias)

    result: list[str] = []
    for alias in aliases[:3]:
        for suffix in ("fr", "com", "org"):
            url = f"https://{alias}.{suffix}/"
            if domain_matches_organisation(organisation, url):
                result.append(url)
    return result[:6]


def _wikidata_exact_label(row: dict, organisation: str) -> bool:
    expected = searchable(organisation)
    values = [row.get("label"), (row.get("match") or {}).get("text")]
    return any(searchable(value or "") == expected for value in values)


def _wikidata_official_sites(organisation: str) -> list[str]:
    """Utilise Wikidata uniquement comme annuaire de découverte P856.

    L'identité doit être un label exact ; Wikidata n'est jamais conservé comme
    preuve Sector. Seule la page officielle découverte peut le devenir ensuite.
    """
    try:
        response = requests.get(
            WIKIDATA_API,
            params={
                "action": "wbsearchentities",
                "search": organisation,
                "language": "fr",
                "uselang": "fr",
                "format": "json",
                "limit": 5,
            },
            timeout=DISCOVERY_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
        )
        if response.status_code != 200:
            return []
        payload = response.json()
    except (requests.RequestException, ValueError):
        return []

    search_rows = payload.get("search") if isinstance(payload, dict) else None
    if not isinstance(search_rows, list):
        return []
    entity_ids = [
        str(row.get("id") or "")
        for row in search_rows
        if isinstance(row, dict) and _wikidata_exact_label(row, organisation)
    ][:MAX_WIKIDATA_ENTITIES]
    entity_ids = [value for value in entity_ids if value]
    if not entity_ids:
        return []

    try:
        response = requests.get(
            WIKIDATA_API,
            params={
                "action": "wbgetentities",
                "ids": "|".join(entity_ids),
                "props": "claims",
                "format": "json",
            },
            timeout=DISCOVERY_TIMEOUT_SECONDS,
            headers={"User-Agent": USER_AGENT},
        )
        if response.status_code != 200:
            return []
        payload = response.json()
    except (requests.RequestException, ValueError):
        return []

    entities = payload.get("entities") if isinstance(payload, dict) else None
    if not isinstance(entities, dict):
        return []

    result: list[str] = []
    for entity_id in entity_ids:
        entity = entities.get(entity_id) or {}
        claims = entity.get("claims") if isinstance(entity, dict) else None
        p856 = claims.get("P856") if isinstance(claims, dict) else None
        if not isinstance(p856, list):
            continue
        for claim in p856:
            try:
                value = claim["mainsnak"]["datavalue"]["value"]
            except (KeyError, TypeError):
                continue
            url = _normalise_candidate_url(str(value or ""))
            if url and domain_matches_organisation(organisation, url) and url not in result:
                result.append(url)
    return result[:MAX_CANDIDATES]


def _search_candidates(organisation: str) -> list[str]:
    result: list[tuple[int, str]] = []
    seen: set[str] = set()
    for query in (
        f'"{organisation}" site officiel',
        f'"{organisation}" mentions légales',
        f'"{organisation}" official website',
    ):
        try:
            rows = company_evidence._search_links(query)
        except Exception:
            rows = []
        for title, raw_url in rows:
            url = _normalise_candidate_url(raw_url)
            if not url or url in seen or not domain_matches_organisation(organisation, url):
                continue
            score = company_evidence._candidate_relevance(organisation, title, url)
            if score < 3:
                continue
            seen.add(url)
            result.append((score, url))
    return [url for _score, url in sorted(result, key=lambda row: (-row[0], row[1]))]


def discover_official_sites(
    organisation: str,
    hint_urls: tuple[str, ...] | list[str] = (),
) -> list[str]:
    """Retourne des candidats officiels ordonnés du plus explicite au plus faible."""
    ordered: list[str] = []

    def add(raw_url: str) -> None:
        url = _normalise_candidate_url(raw_url)
        if (
            url
            and url not in ordered
            and not company_evidence._blocked(url)
            and domain_matches_organisation(organisation, url)
        ):
            ordered.append(url)

    for raw_url in hint_urls:
        add(raw_url)

    for url in _wikidata_official_sites(organisation):
        add(url)

    # Les moteurs ne sont interrogés que si aucun annuaire/hint fort n'a trouvé
    # un domaine plausible. Cela réduit le coût réseau et la dépendance au HTML
    # des moteurs de recherche.
    if not ordered:
        for url in _search_candidates(organisation):
            add(url)

    for url in _direct_domain_guesses(organisation):
        add(url)

    return ordered[:MAX_CANDIDATES]
