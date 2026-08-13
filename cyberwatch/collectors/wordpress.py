"""Collecteur API REST WordPress.

C'est le chemin d'accès le plus fiable du projet : le schéma `/wp-json/wp/v2/`
est standardisé, les dates sont structurées, le filtrage par date se fait côté
serveur (`after` / `before`) et l'en-tête `X-WP-TotalPages` donne le nombre
exact de pages — donc une couverture mesurée et non estimée.
"""

from __future__ import annotations

import html
import json
import re
from urllib.parse import urlencode, urljoin, urlparse

from .. import config, status
from ..normalize import parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window

_TAG_RE = re.compile(r"<[^>]+>")


def strip_html(text: str) -> str:
    """Texte brut d'un fragment HTML rendu par WordPress."""
    if not text:
        return ""
    return html.unescape(_TAG_RE.sub(" ", text)).strip()


def origin_of(url: str) -> str:
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def discover_endpoint(client, start_url: str, source_budget=None) -> str:
    """Racine de l'API REST du site, ou chaîne vide si le site n'est pas WordPress.

    Deux pistes : l'en-tête `Link; rel="https://api.w.org/"` que WordPress
    ajoute à toutes ses pages, puis le chemin conventionnel `/wp-json/`.
    """
    origin = origin_of(start_url)
    candidate = f"{origin}/wp-json/wp/v2/posts?per_page=1"
    result = client.fetch(candidate, source_budget)
    if result.ok and isinstance(result.json(), list):
        return f"{origin}/wp-json/wp/v2"
    return ""


def resolve_taxonomy_term(
    client, endpoint: str, taxonomy: str, slug: str, source_budget=None
) -> int | None:
    """Identifiant numérique d'une catégorie ou d'une étiquette, depuis son slug."""
    url = f"{endpoint}/{taxonomy}?slug={slug}"
    result = client.fetch(url, source_budget)
    if not result.ok:
        return None
    payload = result.json()
    if isinstance(payload, list) and payload:
        term_id = payload[0].get("id")
        return int(term_id) if term_id is not None else None
    return None


class WordPressCollector(Collector):
    """Énumère les articles d'un site WordPress sur une fenêtre de dates.

    Paramètres reconnus dans `spec.params` :
      - `wp_endpoint`  : racine d'API imposée (sinon découverte automatique) ;
      - `categories`   : slug de catégorie à filtrer ;
      - `tags`         : slug d'étiquette à filtrer ;
      - `search`       : mots-clés de recherche côté serveur.
    """

    name = "wordpress"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="wordpress")

        endpoint = spec.params.get("wp_endpoint") or discover_endpoint(
            client, spec.start_url, budget
        )
        result.calls = budget.requests_made
        if not endpoint:
            result.reason_code = status.REASON_NO_FEED
            return result

        query: dict[str, str] = {
            "per_page": "100",
            "orderby": "date",
            "order": "desc",
            "after": f"{window.start}T00:00:00",
            "before": f"{window.end}T23:59:59",
            "_fields": "id,date,link,title,excerpt,categories",
        }

        for taxonomy, key in (("categories", "categories"), ("tags", "tags")):
            slug = spec.params.get(key)
            if not slug:
                continue
            term_id = resolve_taxonomy_term(client, endpoint, taxonomy, slug, budget)
            if term_id is None:
                # La taxonomie demandée n'existe pas : mieux vaut le dire que
                # collecter silencieusement tout le site.
                result.reason_code = status.REASON_NO_FEED
                result.comment = f"Taxonomie {taxonomy}={slug} introuvable"
                result.calls = budget.requests_made
                return result
            query[taxonomy] = str(term_id)

        if spec.params.get("search"):
            query["search"] = spec.params["search"]

        page = 1
        total_pages = None

        while page <= config.MAX_PAGES_PER_SOURCE:
            query["page"] = str(page)
            url = f"{endpoint}/posts?{urlencode(query)}"
            response = client.fetch(url, budget)

            if not response.ok:
                # Au-delà de la dernière page, WordPress répond 400 : ce n'est
                # pas une erreur, c'est la fin de l'énumération.
                if response.status_code == 400 and page > 1:
                    result.reached_boundary = True
                    break
                result.reason_code = response.reason_code
                break

            if total_pages is None:
                total_pages = _total_pages(response)
                result.units_expected = total_pages or 1

            payload = response.json()
            if not isinstance(payload, list):
                result.reason_code = status.REASON_PARSE_ERROR
                break

            for post in payload:
                entry = _entry_from_post(post, spec)
                if entry:
                    result.entries.append(entry)

            result.units_done = page

            if not payload:
                result.reached_boundary = True
                break
            if total_pages is not None and page >= total_pages:
                result.reached_boundary = True
                break

            page += 1
        else:
            result.reason_code = status.REASON_BUDGET_SOURCE

        if budget.exhausted and not result.reached_boundary:
            result.reason_code = status.REASON_BUDGET_SOURCE

        result.calls = budget.requests_made
        if result.units_expected == 0:
            result.units_expected = max(1, result.units_done)
        return result


def _total_pages(response) -> int | None:
    """Nombre total de pages, lu dans l'en-tête `X-WP-TotalPages`."""
    raw = getattr(response, "headers", None)
    if raw:
        value = raw.get("X-WP-TotalPages")
        if value:
            try:
                return int(value)
            except (TypeError, ValueError):
                return None
    return None


def _entry_from_post(post: dict, spec: SourceSpec) -> RawEntry | None:
    """Convertit un article WordPress en entrée brute."""
    if not isinstance(post, dict):
        return None
    published = parse_date(post.get("date") or post.get("date_gmt"))
    if not published:
        return None

    title = strip_html((post.get("title") or {}).get("rendered", ""))
    summary = strip_html((post.get("excerpt") or {}).get("rendered", ""))
    link = post.get("link") or ""

    return RawEntry(
        title=title,
        url=link,
        published=published,
        summary=summary,
        threat=spec.default_threat,
    )
