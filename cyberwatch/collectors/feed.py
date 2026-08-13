"""Collecteur RSS / Atom.

Deuxième chemin d'accès par ordre de préférence. Le schéma est standard, donc
aucun sélecteur propre au site n'est nécessaire.

Limite structurelle assumée : un flux ne publie que ses dernières entrées. S'il
ne redescend pas jusqu'au début de la fenêtre demandée, la source est déclarée
`PARTIAL` avec une couverture estimée sur la part de fenêtre réellement vue —
jamais `OK`, qui laisserait croire à une énumération complète.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import feedparser

from .. import status
from ..normalize import parse_date
from .base import (
    CollectResult,
    Collector,
    RawEntry,
    SourceSpec,
    Window,
    coverage_from_days,
)
from .wordpress import origin_of, strip_html

#: Chemins de flux les plus répandus, essayés dans cet ordre.
COMMON_FEED_PATHS = ["feed/", "rss", "rss.xml", "feed.xml", "atom.xml", "index.xml"]

_FEED_LINK_RE = re.compile(
    r"""<link[^>]+type=["']application/(?:rss|atom)\+xml["'][^>]*>""",
    flags=re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", flags=re.IGNORECASE)


def discover_feeds(client, page_url: str, source_budget=None) -> list[str]:
    """URLs de flux d'une page, par autodécouverte puis chemins conventionnels."""
    candidates: list[str] = []

    response = client.fetch(page_url, source_budget)
    if response.ok:
        for tag in _FEED_LINK_RE.findall(response.text):
            match = _HREF_RE.search(tag)
            if match:
                candidates.append(urljoin(page_url, match.group(1)))

    base = page_url if page_url.endswith("/") else page_url + "/"
    for path in COMMON_FEED_PATHS:
        candidates.append(urljoin(base, path))
        candidates.append(urljoin(origin_of(page_url) + "/", path))

    seen = set()
    unique = []
    for url in candidates:
        if url not in seen:
            seen.add(url)
            unique.append(url)
    return unique


def parse_feed(text: str, spec: SourceSpec) -> list[RawEntry]:
    """Entrées brutes d'un flux RSS ou Atom."""
    parsed = feedparser.parse(text)
    entries = []
    for raw in parsed.entries:
        published = parse_date(
            raw.get("published")
            or raw.get("updated")
            or raw.get("created")
            or ""
        )
        if not published and raw.get("published_parsed"):
            import time as _time

            published = parse_date(
                _time.strftime("%Y-%m-%d", raw["published_parsed"])
            )
        if not published:
            continue

        summary = strip_html(raw.get("summary", "") or raw.get("description", ""))
        entries.append(
            RawEntry(
                title=strip_html(raw.get("title", "")),
                url=raw.get("link", "") or "",
                published=published,
                summary=summary,
                threat=spec.default_threat,
            )
        )
    return entries


class FeedCollector(Collector):
    """Lit le premier flux exploitable trouvé pour la source."""

    name = "feed"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="feed")

        explicit = spec.params.get("feed_url")
        candidates = [explicit] if explicit else discover_feeds(
            client, spec.start_url, budget
        )

        for feed_url in candidates:
            if budget.exhausted:
                result.reason_code = status.REASON_BUDGET_SOURCE
                break

            response = client.fetch(feed_url, budget)
            if not response.ok:
                continue

            entries = parse_feed(response.text, spec)
            if not entries:
                continue

            result.access_method = f"feed:{feed_url}"
            in_window = [e for e in entries if window.contains(e.published)]
            result.entries = in_window
            result.units_done = 1
            result.units_expected = 1

            oldest = min(e.published for e in entries)
            # La borne n'est atteinte que si le flux remonte avant le début de
            # la fenêtre : sinon des entrées plus anciennes existent hors flux.
            if oldest <= window.start:
                result.reached_boundary = True
            else:
                result.units_expected = 100
                result.units_done = coverage_from_days(entries, window)
                result.comment = (
                    f"Le flux ne remonte que jusqu'au {oldest} ; "
                    f"début de fenêtre demandé : {window.start}"
                )
            result.calls = budget.requests_made
            return result

        if result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_NO_FEED
        result.calls = budget.requests_made
        return result
