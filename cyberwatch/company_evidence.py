"""Preuve organisationnelle ciblée pour la qualification Sector.

Cette couche reprend la politique ``evidence-first`` du challenger v3 sans
importer ses CSV dans la base canonique. Les moteurs de recherche ne servent
qu'à découvrir le site officiel d'une organisation ; seule une page du site
officiel peut devenir une preuve canonique.

Aucun fuzzy matching, aucun choix de "meilleur résultat" juridique et aucun
LLM ne sont utilisés ici. En cas de doute sur l'identité ou l'activité,
``None`` est retourné.
"""

from __future__ import annotations

import base64
import html
import os
import re
import sys
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse

import requests

from . import config
from .normalize import searchable

#: Diagnostic temporaire (audit 2026-08-26) : le canal recherche de site
#: officiel tourne (appels réseau réels, budget consommé) mais rend 0
#: résultat sur 19 tentatives cumulées sur deux runs de contrôle. Ce
#: marqueur, désactivé par défaut, sert à isoler où précisément la chaîne
#: échoue (aucun candidat retourné par les moteurs, ou candidats rejetés en
#: aval) avant de choisir un correctif définitif. À retirer une fois la
#: cause confirmée.
_DEBUG_OFFICIAL_SITE = os.environ.get("CYBERWATCH_DEBUG_OFFICIAL_SITE") == "1"


def _debug_official_site(message: str) -> None:
    if _DEBUG_OFFICIAL_SITE:
        print(f"[debug official_site] {message}", file=sys.stderr)

#: Cas réel (audit 2026-08-26) : ce module avait son propre User-Agent
#: dédié, distinct de celui du reste du projet. Les 9 tentatives réelles du
#: run RESET du 26/08 (DuckDuckGo + Bing) sont toutes revenues sans aucun
#: candidat, en un temps trop court pour un vrai scraping abouti. Plutôt que
#: de se déguiser en navigateur anonyme (contraire au principe du projet,
#: cf. ``config.HTTP_USER_AGENT_FALLBACK``), on réutilise le même mécanisme
#: à deux niveaux que ``http.py`` : s'identifier, et ne se replier que sur un
#: agent de repli lui aussi identifiable si l'agent identifié est refusé.
USER_AGENT = config.HTTP_USER_AGENT
SEARCH_TIMEOUT_SECONDS = 10
PAGE_TIMEOUT_SECONDS = 10
MAX_SEARCH_RESULTS = 5
MAX_ABOUT_PAGES = 2

# Les moteurs/annuaires servent au mieux à la découverte. Ils ne sont jamais
# conservés comme preuve officielle.
BLOCKED_DOMAINS = {
    "bing.com",
    "google.com",
    "duckduckgo.com",
    "yahoo.com",
    "facebook.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "tiktok.com",
    "linkedin.com",
    "pappers.fr",
    "societe.com",
    "verif.com",
    "manageo.fr",
    "kompass.com",
    "wikipedia.org",
    "crunchbase.com",
    "glassdoor.com",
    "indeed.com",
    "cyberattaque.org",
    "frenchbreaches.com",
    "bonjourlafuite.eu.org",
    "ransomware.live",
    "annuaire-entreprises.data.gouv.fr",
}

STOP_TOKENS = {
    "groupe", "group", "sas", "sasu", "sa", "sarl", "eurl", "ltd",
    "limited", "inc", "corp", "corporation", "company", "co", "france",
    "holding", "international", "the", "les", "le", "la", "de", "du",
    "des", "and", "et",
}

# Expressions volontairement fortes, adaptées à une page métier officielle.
# Elles sont dérivées du challenger v3 mais restent plus conservatrices : un
# écart net est requis si plusieurs secteurs sont détectés sur la même page.
_ACTIVITY_PATTERNS: dict[str, tuple[int, str]] = {
    config.SECTOR_ADMIN: (
        8,
        r"\b(mairie|municipalit[ée]|commune|préfecture|minist[eè]re|administration publique|"
        r"collectivit[ée]|chambre de commerce|cci\b|city council|local authority|government agency)\b",
    ),
    config.SECTOR_HEALTH: (
        8,
        r"\b(h[oô]pital|hospital|clinique|clinic|pharmaci|laboratoire m[ée]dical|"
        r"medical laboratory|healthcare|sant[ée] humaine|ehpad|veterinary|v[ée]t[ée]rinaire)\b",
    ),
    config.SECTOR_EDUCATION: (
        8,
        r"\b(universit[ée]|university|school|[ée]cole|coll[eè]ge|lyc[ée]e|enseignement|"
        r"formation professionnelle|training provider|academy|acad[ée]mie)\b",
    ),
    config.SECTOR_FINANCE: (
        9,
        r"\b(banque|bank|assurance|insurance|mutuelle|cr[ée]dit|credit union|financial services|"
        r"fintech|asset management|courtier en assurance)\b",
    ),
    config.SECTOR_TRANSPORT: (
        8,
        r"\b(compagnie a[ée]rienne|airline|a[ée]roport|airport|transporteur|transport company|"
        r"logistique|logistics|freight|fret|shipping|entreposage|travel agency|agence de voyages|"
        r"tour operator)\b",
    ),
    config.SECTOR_SPORT: (
        9,
        r"\b(f[ée]d[ée]ration sportive|sports? federation|club de (football|rugby|basket|tennis)|"
        r"football club|rugby club|sports? club|salle de sport|fitness club|activit[ée]s sportives)\b",
    ),
    config.SECTOR_RETAIL: (
        8,
        r"\b(commerce de gros|commerce de d[ée]tail|grossiste|wholesaler|retailer|retail chain|"
        r"magasin|supermarch[ée]|supermarket|e-commerce|boutique en ligne|concessionnaire|dealership|"
        r"distributeur|distribution de produits|vente de mat[ée]riel)\b",
    ),
    config.SECTOR_TECH: (
        9,
        r"\b([ée]diteur de logiciels|software (company|publisher|vendor)|saas|cloud provider|"
        r"h[ée]bergeur|hosting provider|services informatiques|it services|cybers[ée]curit[ée]|"
        r"cybersecurity|t[ée]l[ée]communications?|telecommunications?|datacenter|data center|"
        r"d[ée]veloppement logiciel|software development)\b",
    ),
    config.SECTOR_ENERGY: (
        9,
        r"\b([ée]nergie|energy company|electric utility|[ée]lectricit[ée]|water utility|"
        r"service des eaux|gaz|gas utility|oil and gas|assainissement|waste management|"
        r"gestion des d[ée]chets)\b",
    ),
    config.SECTOR_INDUSTRY: (
        8,
        r"\b(industriel|industrie manufacturi[eè]re|manufacturer|manufacturing|fabricant|"
        r"fabrication de|usine|industrial company|production industrielle|sous-traitance industrielle)\b",
    ),
    config.SECTOR_CONSTRUCTION: (
        8,
        r"\b(btp\b|construction|travaux publics|g[ée]nie civil|civil engineering|promoteur immobilier|"
        r"promotion immobili[eè]re|real estate developer|entreprise du b[âa]timent|"
        r"activit[ée]s immobili[eè]res)\b",
    ),
    config.SECTOR_SERVICES: (
        8,
        r"\b(cabinet de conseil|consulting firm|consultancy|cabinet d.avocats?|law firm|"
        r"expertise comptable|accounting firm|recrutement|recruitment|staffing|professional services|"
        r"services aux entreprises|business services|agence marketing|marketing agency|"
        r"nettoyage industriel|propret[ée]|facility management|prestations? d.accueil|"
        r"s[ée]curit[ée] priv[ée]e|private security|bureau d.[ée]tudes|engineering consultancy)\b",
    ),
}


@dataclass(frozen=True)
class CompanyEvidence:
    sector: str
    evidence_url: str
    evidence_text: str
    evidence_source: str = "official_site"
    evidence_type: str = "official_site"


def _domain(url: str) -> str:
    value = urlparse(url).netloc.lower().split(":", 1)[0]
    return value[4:] if value.startswith("www.") else value


def _blocked(url: str) -> bool:
    domain = _domain(url)
    return not domain or any(
        domain == value or domain.endswith("." + value) for value in BLOCKED_DOMAINS
    )


def _org_tokens(organisation: str) -> list[str]:
    return [
        token
        for token in searchable(organisation).split()
        if len(token) > 2 and token not in STOP_TOKENS
    ]


def _clean(value: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(str(value or ""))).strip()


def _unwrap_search_url(url: str) -> str:
    """Retrouve la destination réelle derrière un lien de moteur de recherche.

    Cas réel (audit 2026-08-26) : Bing renvoyait de vrais résultats (statut
    200, 40-50 liens par requête, moteur non bloqué) mais 100% étaient
    éliminés en aval — ce désenveloppement ne connaissait que le format de
    redirection DuckDuckGo (``uddg=``), donc les liens Bing restaient des
    URLs ``bing.com`` et tombaient dans ``BLOCKED_DOMAINS`` (le moteur
    lui-même, jamais un site officiel), quel que soit leur vraie
    destination. Bing encode celle-ci en base64 urlsafe sans padding,
    préfixée ``a1``, dans le paramètre ``u`` de ses liens ``bing.com/ck/a``.
    """
    if not url:
        return ""
    parsed = urlparse(url)
    if "duckduckgo.com" in parsed.netloc and "uddg=" in parsed.query:
        try:
            return unquote(parse_qs(parsed.query).get("uddg", [""])[0])
        except Exception:
            return ""
    if "bing.com" in parsed.netloc:
        wrapped = parse_qs(parsed.query).get("u", [""])[0]
        if wrapped.startswith("a1"):
            try:
                payload = wrapped[2:]
                padded = payload + "=" * (-len(payload) % 4)
                return base64.urlsafe_b64decode(padded).decode("utf-8", "ignore")
            except Exception:
                return ""
    return url


class _LinksParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._href = ""
        self._parts: list[str] = []
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "a" or self._href:
            return
        values = dict(attrs)
        self._href = values.get("href", "") or ""
        self._parts = []

    def handle_data(self, data: str) -> None:
        if self._href:
            self._parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "a" or not self._href:
            return
        title = _clean(" ".join(self._parts))
        self.links.append((title, _unwrap_search_url(self._href)))
        self._href = ""
        self._parts = []


class _PageParser(HTMLParser):
    _PRIORITY_TAGS = {"title", "h1", "h2", "h3"}
    _IGNORED_TAGS = {"script", "style", "noscript", "svg"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.priority_parts: list[str] = []
        self.body_parts: list[str] = []
        self.about_links: list[str] = []
        self._priority_depth = 0
        self._ignored_depth = 0
        self._href = ""
        self._anchor_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs) -> None:
        tag = tag.lower()
        values = dict(attrs)
        if tag in self._IGNORED_TAGS:
            self._ignored_depth += 1
            return
        if self._ignored_depth:
            return
        if tag in self._PRIORITY_TAGS:
            self._priority_depth += 1
        if tag == "meta":
            key = (values.get("name") or values.get("property") or "").lower()
            if key in {"description", "og:description"} and values.get("content"):
                self.priority_parts.append(str(values["content"]))
        if tag == "a" and not self._href:
            self._href = values.get("href", "") or ""
            self._anchor_parts = []

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self._IGNORED_TAGS:
            if self._ignored_depth:
                self._ignored_depth -= 1
            return
        if self._ignored_depth:
            return
        if tag in self._PRIORITY_TAGS and self._priority_depth:
            self._priority_depth -= 1
        if tag == "a" and self._href:
            label = searchable(" ".join(self._anchor_parts))
            if any(
                marker in label
                for marker in (
                    "a propos", "qui sommes nous", "notre entreprise", "about",
                    "company", "mentions legales", "legal notice", "nos metiers",
                    "expertises", "activites",
                )
            ):
                self.about_links.append(self._href)
            self._href = ""
            self._anchor_parts = []

    def handle_data(self, data: str) -> None:
        if self._ignored_depth:
            return
        text = _clean(data)
        if not text:
            return
        self.body_parts.append(text)
        if self._priority_depth:
            self.priority_parts.append(text)
        if self._href:
            self._anchor_parts.append(text)


def _http_get(url: str, *, timeout: int) -> requests.Response | None:
    for agent in (USER_AGENT, config.HTTP_USER_AGENT_FALLBACK):
        try:
            response = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": agent},
            )
        except requests.RequestException:
            continue
        if response.status_code < 400:
            return response
    return None


def _search_links(query: str) -> list[tuple[str, str]]:
    urls = (
        "https://html.duckduckgo.com/html/?q=" + quote_plus(query),
        "https://www.bing.com/search?q=" + quote_plus(query) + "&count=10",
    )
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for search_url in urls:
        response = _http_get(search_url, timeout=SEARCH_TIMEOUT_SECONDS)
        if response is None:
            _debug_official_site(f"search engine={search_url!r} -> aucune réponse (échec réseau/statut>=400 des deux agents)")
            continue
        parser = _LinksParser()
        try:
            parser.feed(response.text)
        except Exception:
            _debug_official_site(f"search engine={search_url!r} status={response.status_code} len={len(response.text)} -> échec parsing HTML")
            continue
        _debug_official_site(
            f"search engine={search_url!r} status={response.status_code} "
            f"len={len(response.text)} liens_bruts={len(parser.links)}"
        )
        for title, url in parser.links:
            url = _unwrap_search_url(url)
            if not url.startswith(("http://", "https://")) or _blocked(url) or url in seen:
                continue
            seen.add(url)
            results.append((title, url))
    return results


def _candidate_relevance(organisation: str, title: str, url: str) -> int:
    tokens = _org_tokens(organisation)
    if not tokens:
        return 0
    title_and_domain = searchable(f"{title} {_domain(url)}")
    hits = sum(1 for token in tokens if token in title_and_domain)
    if hits < min(2, len(tokens)):
        return 0
    domain_text = searchable(_domain(url))
    domain_hits = sum(1 for token in tokens if token in domain_text)
    score = hits * 3 + domain_hits * 2
    if "site officiel" in searchable(title) or "official" in searchable(title):
        score += 3
    return score


def _discover_official_sites(organisation: str) -> list[str]:
    candidates: dict[str, int] = {}
    for query in (
        f'"{organisation}" site officiel',
        f'"{organisation}" mentions légales',
    ):
        links = _search_links(query)
        _debug_official_site(f"organisation={organisation!r} query={query!r} -> {len(links)} lien(s) brut(s)")
        for title, url in links:
            score = _candidate_relevance(organisation, title, url)
            if score < 3:
                _debug_official_site(f"  rejeté score={score} title={title!r} url={url!r}")
                continue
            candidates[url] = max(score, candidates.get(url, 0))
    result = [
        url
        for url, _score in sorted(
            candidates.items(), key=lambda item: (-item[1], item[0])
        )
    ][:MAX_SEARCH_RESULTS]
    _debug_official_site(f"organisation={organisation!r} -> {len(result)} candidat(s) retenu(s): {result}")
    return result


def _page(url: str) -> tuple[str, str, list[str], str]:
    response = _http_get(url, timeout=PAGE_TIMEOUT_SECONDS)
    if response is None:
        return "", "", [], ""
    final_url = getattr(response, "url", "") or url
    if _blocked(final_url):
        return "", "", [], ""
    content_type = (
        response.headers.get("content-type", "") if hasattr(response, "headers") else ""
    ).lower()
    text = response.text or ""
    if content_type and "html" not in content_type and "<html" not in text[:1000].lower():
        return "", "", [], final_url
    parser = _PageParser()
    try:
        parser.feed(text)
    except Exception:
        return "", "", [], final_url
    priority = _clean(" ".join(parser.priority_parts))
    body = _clean(" ".join(parser.body_parts))
    links = [
        urljoin(final_url, href)
        for href in parser.about_links
        if href and _domain(urljoin(final_url, href)) == _domain(final_url)
    ]
    return priority, body, list(dict.fromkeys(links))[:MAX_ABOUT_PAGES], final_url


def _identity_matches(organisation: str, url: str, priority: str, body: str) -> bool:
    raw = str(organisation or "").strip().casefold().removeprefix("www.")
    domain = _domain(url).casefold()
    if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", raw) and (domain == raw or domain.endswith("." + raw)):
        return True
    tokens = _org_tokens(organisation)
    if not tokens:
        return False
    corpus = searchable(f"{_domain(url)} {priority} {body[:12000]}")
    hits = sum(1 for token in tokens if token in corpus)
    return hits >= min(2, len(tokens))


def _excerpt(text: str, match: re.Match[str]) -> str:
    start = max(0, match.start() - 90)
    end = min(len(text), match.end() + 140)
    return _clean(text[start:end])[:320]


def classify_official_activity(text: str) -> tuple[str, str] | None:
    """Classe un texte métier officiel, sinon ``None``.

    Une seule preuve forte suffit. Si plusieurs secteurs sont présents, le
    meilleur score doit avoir au moins deux points d'avance ; sinon la page est
    considérée trop générale pour une qualification canonique.
    """
    scores: list[tuple[int, str, re.Match[str]]] = []
    for sector, (weight, pattern) in _ACTIVITY_PATTERNS.items():
        match = re.search(pattern, text, re.I)
        if match:
            scores.append((weight, sector, match))
    if not scores:
        return None
    scores.sort(key=lambda row: (-row[0], row[1]))
    top = scores[0]
    if top[0] < 8:
        return None
    if len(scores) > 1 and top[0] < scores[1][0] + 2:
        return None
    return top[1], _excerpt(text, top[2])


#: Cas réel (audit 2026-08-26) : le classificateur déterministe officiel est
#: volontairement strict (deux points d'avance requis) et rate des activités
#: pourtant réelles. La page reste identifiée avec certitude comme officielle
#: (garde d'identité déjà passée) : son titre/meta reste une preuve utile
#: pour l'arbitrage LLM (organisation_sector_llm.py, qui lit déjà
#: Activity_Label sans condition), même sans classification déterministe.
MAX_OFFICIAL_TEXT_CHARS = 400


def resolve_official_site(organisation: str) -> CompanyEvidence | None:
    """Résout un secteur depuis le site officiel, sans jamais lever d'erreur.

    Si aucun candidat identité-validé ne se classe déterministement, le titre
    + meta description du premier candidat validé est tout de même retourné
    (``sector=""``, ``evidence_type="official_site_text"``) : un texte, pas
    un secteur. Ce type de preuve n'entre jamais dans
    ``STRONG_EVIDENCE_TYPES`` et n'est jamais confondu avec
    ``official_subject_activity`` (organisation_sector.py ne cherche que cette
    valeur exacte pour la preuve forte).
    """
    try:
        candidates = _discover_official_sites(organisation)
    except Exception as exc:
        _debug_official_site(f"organisation={organisation!r} -> exception à la découverte: {exc!r}")
        return None

    fallback: CompanyEvidence | None = None
    for candidate in candidates:
        priority, body, about_links, final_url = _page(candidate)
        if not priority and not body:
            _debug_official_site(f"  candidat={candidate!r} -> page vide/injoignable")
            continue
        if not _identity_matches(organisation, final_url or candidate, priority, body):
            _debug_official_site(f"  candidat={candidate!r} final_url={final_url!r} -> identité non validée")
            continue

        classified = classify_official_activity(priority)
        evidence_url = final_url or candidate

        if classified is None:
            about_corpus_parts: list[str] = []
            about_url = ""
            for link in about_links:
                p_priority, p_body, _links, p_final = _page(link)
                if not p_priority and not p_body:
                    continue
                if not _identity_matches(organisation, p_final or link, p_priority, p_body):
                    continue
                about_corpus_parts.extend([p_priority, p_body[:12000]])
                if not about_url:
                    about_url = p_final or link
            if about_corpus_parts:
                classified = classify_official_activity(_clean(" ".join(about_corpus_parts)))
                if classified is not None and about_url:
                    evidence_url = about_url

        if classified is None:
            classified = classify_official_activity(body[:16000])

        if classified is None:
            if fallback is None and priority:
                fallback = CompanyEvidence(
                    sector="",
                    evidence_url=evidence_url,
                    evidence_text=priority[:MAX_OFFICIAL_TEXT_CHARS],
                    evidence_source=_domain(evidence_url) or "official_site",
                    evidence_type="official_site_text",
                )
            continue
        sector, evidence_text = classified
        return CompanyEvidence(
            sector=sector,
            evidence_url=evidence_url,
            evidence_text=evidence_text,
            evidence_source=_domain(evidence_url) or "official_site",
        )
    return fallback
