"""Collecteur Google News RSS — support des couches `ENTITY_WATCH` et
`REGIONAL_WATCH`.

La méthode d'origine prévoyait des requêtes de moteur de recherche, exécutables
à la main mais pas en script : aucun moteur ne propose d'accès gratuit et stable.
Google News RSS le remplace — gratuit, sans clé, et surtout **déterministe dans
sa forme** : la requête exécutée est écrite telle quelle dans `SOURCES`, ce que
le §22 exige.

Les quatre requêtes Q1–Q4 de la méthode sont fusionnées en deux requêtes reliées
par `OR`. Google News traite nativement cet opérateur, donc le rappel est
équivalent pour moitié moins d'appels — le levier principal de maîtrise de la
volumétrie du projet.
"""

from __future__ import annotations

import re
from urllib.parse import quote_plus, urlparse

from .. import config, status
from ..normalize import _contains, searchable
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window
from .feed import parse_feed

GOOGLE_NEWS_ENDPOINT = "https://news.google.com/rss/search"

#: Les deux requêtes exécutées par entité, fusion documentée de Q1–Q4 (§14.3).
QUERY_ATTACK_FR = (
    '(cyberattaque OR piratage OR ransomware OR rançongiciel OR '
    '"incident informatique" OR "incident de sécurité" OR intrusion OR '
    '"système d\'information")'
)
QUERY_LEAK_FR = (
    '("fuite de données" OR "données personnelles" OR CNIL OR exfiltration OR '
    'DDoS OR "déni de service" OR phishing OR fraude OR "messagerie compromise")'
)

QUERY_ATTACK_EN = (
    '(cyberattack OR hacking OR ransomware OR "cyber attack" OR '
    '"security incident" OR intrusion OR breach)'
)
QUERY_LEAK_EN = (
    '("data breach" OR "data leak" OR phishing OR scam OR fraud OR DDoS OR '
    '"denial of service")'
)

#: Paramètres régionaux par langue.
LOCALES = {
    "fr": {"hl": "fr", "gl": "FR", "ceid": "FR:fr"},
    "en": {"hl": "en-GB", "gl": "GB", "ceid": "GB:en"},
}

#: Suffixe éditorial « Titre - Publication » ajouté par Google News.
_TITLE_SUFFIX_RE = re.compile(r"\s+-\s+[^-]{2,40}$")


def build_url(query: str, lang: str = "fr", when_days: int | None = None) -> str:
    """URL du flux Google News pour une requête donnée.

    `when:Nd` restreint la recherche aux N derniers jours lorsque la fenêtre est
    courte : moins de bruit et des réponses plus légères sur les runs quotidiens.
    """
    full_query = query
    if when_days and when_days <= 45:
        full_query = f"{query} when:{when_days}d"
    locale = LOCALES.get(lang, LOCALES["fr"])
    params = "&".join(f"{key}={value}" for key, value in locale.items())
    return f"{GOOGLE_NEWS_ENDPOINT}?q={quote_plus(full_query)}&{params}"


def entity_queries(entity: str, lang: str = "fr", context: str = "") -> list[str]:
    """Les deux requêtes fixes d'une entité surveillée.

    Le contexte territorial (« La Réunion », « Mayotte »…) est ajouté à la
    requête : sans lui, « Mairie de Saint-Denis » ramènerait massivement des
    résultats de Seine-Saint-Denis.
    """
    scope = f' {context}' if context else ""
    attack = QUERY_ATTACK_EN if lang == "en" else QUERY_ATTACK_FR
    leak = QUERY_LEAK_EN if lang == "en" else QUERY_LEAK_FR
    return [f'"{entity}"{scope} {attack}', f'"{entity}"{scope} {leak}']


def domain_queries(domain: str, territory: str, lang: str = "fr") -> list[str]:
    """Les deux requêtes fixes d'un domaine média surveillé (§15.3, §16.2)."""
    attack = QUERY_ATTACK_EN if lang == "en" else QUERY_ATTACK_FR
    leak = QUERY_LEAK_EN if lang == "en" else QUERY_LEAK_FR
    return [
        f"site:{domain} {territory} {attack}",
        f"site:{domain} {territory} {leak}",
    ]


def clean_title(title: str) -> str:
    """Retire le suffixe « - Nom du média » ajouté par Google News."""
    return _TITLE_SUFFIX_RE.sub("", title or "").strip()


def mentions_entity(entry: RawEntry, entity: str, aliases: list[str]) -> bool:
    """Vrai si l'entité est réellement citée dans le titre ou le résumé.

    Traduction déterministe de la règle d'item du §14.3 : « un résultat devient
    un item si l'entité est réellement concernée ». Sans cette vérification,
    une requête ramènerait des articles où l'entité n'apparaît pas.
    """
    blob = searchable(f"{entry.title} {entry.summary}")
    for candidate in [entity, *aliases]:
        key = searchable(candidate)
        if key and _contains(blob, key):
            return True
    return False


class NewsRssCollector(Collector):
    """Exécute un ensemble fixe de requêtes Google News.

    Deux modes selon `spec.params` :
      - `entities` : surveillance nominative, deux requêtes par entité, avec
        vérification que l'entité est bien citée et production de l'état de
        veille par entité ;
      - `queries`  : requêtes libres déjà formées (couches régionales).
    """

    name = "newsrss"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="google-news-rss")
        lang = spec.params.get("lang", "fr")
        when_days = window.days if window.days <= 45 else None

        entities = spec.params.get("entities") or []
        plain_queries = spec.params.get("queries") or []

        default_context = spec.params.get("context", "")
        tasks: list[tuple[str, list[str], list[str]]] = []
        for entity in entities:
            if isinstance(entity, dict):
                name = entity["name"]
                aliases = entity.get("aliases", [])
                context = entity.get("context", default_context)
            else:
                name, aliases, context = entity, [], default_context
            tasks.append((name, aliases, entity_queries(name, lang, context)))
        for query in plain_queries:
            tasks.append(("", [], [query]))

        result.units_expected = sum(len(queries) for _n, _a, queries in tasks)
        seen_urls: set[str] = set()
        failures: dict[str, int] = {}

        for name, aliases, queries in tasks:
            entity_entries: list[RawEntry] = []
            queries_done = 0
            entity_status = status.OK

            for query in queries:
                if budget.exhausted or client.run_budget.exhausted:
                    entity_status = status.PARTIAL
                    result.reason_code = (
                        status.REASON_BUDGET_RUN
                        if client.run_budget.exhausted
                        else status.REASON_BUDGET_SOURCE
                    )
                    break

                response = client.fetch(build_url(query, lang, when_days), budget)
                if not response.ok:
                    entity_status = status.PARTIAL
                    # Conserver la cause réelle du refus : sans elle, la source
                    # ressortirait en échec sans raison exploitable.
                    result.reason_code = response.reason_code
                    failures[response.reason_code] = (
                        failures.get(response.reason_code, 0) + 1
                    )
                    continue

                queries_done += 1
                result.units_done += 1

                for entry in parse_feed(response.text, spec):
                    entry.title = clean_title(entry.title)
                    if not window.contains(entry.published):
                        continue
                    if name and not mentions_entity(entry, name, aliases):
                        continue
                    if entry.url in seen_urls:
                        continue
                    seen_urls.add(entry.url)

                    if name:
                        entry.entity = name
                        entry.organisation = name
                        entity_entries.append(entry)
                    result.entries.append(entry)

            if name:
                result.watch_rows.append(
                    {
                        "entity": name,
                        "queries_expected": len(queries),
                        "queries_done": queries_done,
                        "status": (
                            status.OK if queries_done == len(queries) else entity_status
                        ),
                        "items_found": len(entity_entries),
                        "latest_date": max(
                            (e.published for e in entity_entries), default=""
                        ),
                    }
                )

            if client.run_budget.exhausted:
                break

        result.reached_boundary = (
            result.units_done >= result.units_expected
            and result.reason_code == status.REASON_OK
        )
        result.calls = budget.requests_made
        if not result.reached_boundary:
            detail = f"{result.units_done}/{result.units_expected} requêtes exécutées"
            if failures:
                causes = ", ".join(
                    f"{code} x{count}"
                    for code, count in sorted(
                        failures.items(), key=lambda kv: -kv[1]
                    )
                )
                detail = f"{detail} ; refus : {causes}"
            result.comment = detail
        return result
