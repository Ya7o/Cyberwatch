"""Collecteur RSS / Atom.

Le flux reste l'autorité d'énumération. Pour FrenchBreaches uniquement, les
entrées déjà retenues dans la fenêtre peuvent ensuite être hydratées avec leur
page détaillée afin d'alimenter la couche auxiliaire ``source_facts``. Un échec
de cette hydratation n'altère jamais le statut de collecte du flux.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin

import feedparser

from .. import status
from ..normalize import parse_date
from .editorial_html import EXTRACTOR_VERSION, editorial_text, usable_detail
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window, coverage_from_days
from .wordpress import origin_of, strip_html

COMMON_FEED_PATHS = ["feed/", "rss", "rss.xml", "feed.xml", "atom.xml", "index.xml"]
_FEED_LINK_RE = re.compile(
    r"""<link[^>]+type=["']application/(?:rss|atom)\+xml["'][^>]*>""",
    flags=re.IGNORECASE,
)
_HREF_RE = re.compile(r"""href=["']([^"']+)["']""", flags=re.IGNORECASE)
_DYNAMIC_BLOCK_RE = re.compile(
    r"<(?:script|style|noscript)\b[^>]*>.*?</(?:script|style|noscript)>",
    flags=re.IGNORECASE | re.DOTALL,
)
_ARTICLE_ROOT_RE = re.compile(r"<(?:article|main)\b[^>]*>(.*?)</(?:article|main)>", re.IGNORECASE | re.DOTALL)
_NON_EDITORIAL_RE = re.compile(r"<(?:header|footer|nav|aside|form)\b[^>]*>.*?</(?:header|footer|nav|aside|form)>", re.IGNORECASE | re.DOTALL)
_TECHNICAL_FRAGMENT_RE = re.compile(
    r"\s*(?:—|-|\|)\s*[^.]*\b(?:header\s+html|vitesse\s+d['’]apparition|javascript|css|chargement\s+visuel|performance\s+web)\b.*$",
    re.IGNORECASE,
)
_FRENCHBREACHES_SUFFIX_MARKERS = (
    "Alertes liées",
    "Si cet article vous a plu",
    "← Retour aux alertes",
)

_EXPLICIT_VICTIM_RE = re.compile(
    r"\b(?:fuite(?:\s+de\s+données)?|cyberattaque|attaque)\s+"
    r"(?:touche|touchant|visant|attribuée?\s+à|contre)\s+"
    r"(?P<victim>[^,\n]{2,100})(?=,\s+(?:la|le|un|une|service|réseau|plateforme)\b)",
    flags=re.IGNORECASE,
)


def explicit_frenchbreaches_victim(text: str) -> str:
    """Return the victim explicitly bound to the incident in the article lead."""
    match = _EXPLICIT_VICTIM_RE.search(text or "")
    if not match:
        return ""
    victim = strip_html(match.group("victim")).strip(" .:;–—-")
    if len(victim) < 2 or len(victim.split()) > 12:
        return ""
    return victim


def stable_frenchbreaches_detail_text(html_text: str) -> str:
    """Texte éditorial stable d'une fiche, sans blocs dynamiques hors article."""
    text = editorial_text(html_text)
    # Certains thèmes injectent une note de performance dans le contenu rendu.
    # Elle ne constitue jamais une preuve d'incident.
    text = _TECHNICAL_FRAGMENT_RE.sub("", text).strip()
    cut = len(text)
    for marker_text in _FRENCHBREACHES_SUFFIX_MARKERS:
        pos = text.find(marker_text)
        if pos > 0:
            cut = min(cut, pos)
    return text[:cut].strip()


def discover_feeds(client, page_url: str, source_budget=None) -> list[str]:
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
    parsed = feedparser.parse(text)
    entries = []
    for raw in parsed.entries:
        published = parse_date(raw.get("published") or raw.get("updated") or raw.get("created") or "")
        if not published and raw.get("published_parsed"):
            import time as _time
            published = parse_date(_time.strftime("%Y-%m-%d", raw["published_parsed"]))
        if not published:
            continue
        summary = strip_html(raw.get("summary", "") or raw.get("description", ""))
        native_id = raw.get("id") or raw.get("guid") or ""
        entries.append(
            RawEntry(
                title=strip_html(raw.get("title", "")),
                url=raw.get("link", "") or "",
                source_item_id=str(native_id).strip(),
                published=published,
                summary=summary,
                threat=spec.default_threat,
            )
        )
    return entries


def _hydrate_frenchbreaches_details(client, entries: list[RawEntry], budget) -> tuple[int, int]:
    """Ajoute le texte des pages détaillées sans changer l'énumération du flux."""
    attempted = 0
    hydrated = 0
    for entry in entries:
        metadata = dict(entry.source_metadata or {})
        detail = {"status": "BUDGET_BLOCKED" if budget.exhausted else "NO_URL",
                  "extractor_version": EXTRACTOR_VERSION, "fallback": "RSS"}
        metadata["detail_hydration"] = detail
        entry.source_metadata = metadata
        if budget.exhausted or not entry.url:
            continue
        attempted += 1
        response = client.fetch(entry.url, budget)
        if not response.ok:
            detail["status"] = "HTTP_ERROR"
            continue
        text = stable_frenchbreaches_detail_text(response.text)
        detail["chars"] = len(text)
        if not usable_detail(text, entry.title):
            detail["status"] = "CONTENT_INCOMPLETE"
            continue
        entry.content = text[:40000]
        # Some feed titles name a territory (for example "Aveyron") while the
        # article lead names the affected service. Keep the source's explicit
        # grammatical subject so sector resolution and dedup use the victim.
        explicit_victim = explicit_frenchbreaches_victim(entry.content)
        if explicit_victim:
            entry.organisation = explicit_victim
        detail.update(status="HYDRATED", fallback="", truncated=len(text) > 40000)
        hydrated += 1
    return attempted, hydrated


def _enrich_frenchbreaches_rich_facts(entries: list[RawEntry]) -> int:
    """Attach generic rich facts after hydration; failures stay source-local."""
    from ..rich_facts import enrich_provenance
    from .frenchbreaches_rich import extract_frenchbreaches_rich_facts

    enriched = 0
    for entry in entries:
        text = "\n".join(part for part in (entry.title, entry.summary, entry.content) if part)
        rich = extract_frenchbreaches_rich_facts(text)
        if not rich:
            continue
        metadata = dict(entry.source_metadata or {})
        metadata["rich_facts"] = enrich_provenance(
            rich,
            source_id="FRENCHBREACHES",
            item_id=str(entry.source_item_id or ""),
        )
        entry.source_metadata = metadata
        enriched += 1
    return enriched


class FeedCollector(Collector):
    name = "feed"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="feed")

        explicit = spec.params.get("feed_url")
        candidates = [explicit] if explicit else discover_feeds(client, spec.start_url, budget)

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
            in_window = [entry for entry in entries if window.contains(entry.published)]
            result.entries = in_window
            result.items_seen = len(entries)
            result.items_in_window = len(in_window)
            result.units_done = 1
            result.units_expected = 1

            oldest = min(entry.published for entry in entries)
            result.oldest_available_date = oldest
            if oldest <= window.start:
                result.reached_boundary = True
            elif spec.params.get("feed_has_no_pagination"):
                result.reached_boundary = True
                result.comment = (
                    f"Flux sans pagination disponible : {len(entries)} entrées "
                    f"captées (la plus ancienne remonte au {oldest})."
                )
            else:
                result.units_expected = 100
                result.units_done = coverage_from_days(entries, window)
                result.comment = (
                    f"Le flux ne remonte que jusqu'au {oldest} ; "
                    f"début de fenêtre demandé : {window.start}"
                )

            if spec.source_id == "FRENCHBREACHES" and in_window:
                attempted, hydrated = _hydrate_frenchbreaches_details(client, in_window, budget)
                enriched = _enrich_frenchbreaches_rich_facts(in_window)
                detail = f"details_hydrates={hydrated}/{attempted}; rich_facts={enriched}/{len(in_window)}"
                degraded = sum(e.source_metadata.get("detail_hydration", {}).get("status") != "HYDRATED" for e in in_window)
                detail += f"; details_degrades={degraded}"
                result.comment = f"{result.comment}; {detail}" if result.comment else detail

            result.calls = budget.requests_made
            return result

        if result.reason_code == status.REASON_OK:
            result.reason_code = status.REASON_NO_FEED
        result.calls = budget.requests_made
        return result
