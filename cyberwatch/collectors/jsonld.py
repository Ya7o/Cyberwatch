"""Collecteur HTML générique fondé sur les données structurées schema.org.

Troisième et dernier chemin d'accès automatique. Plutôt que de deviner des
sélecteurs CSS propres à chaque site — fragiles et invérifiables — ce collecteur
lit les blocs `<script type="application/ld+json">` que la quasi-totalité des
sites de presse publient pour le référencement. Le schéma `NewsArticle` y
fournit `headline`, `datePublished` et `url` de façon normalisée.

Un repli sur les balises `<time datetime="...">` couvre les sites sans JSON-LD.
"""

from __future__ import annotations

import html
import json
import re
from urllib.parse import urljoin

from .. import config, status
from ..normalize import parse_date
from .base import CollectResult, Collector, RawEntry, SourceSpec, Window
from .wordpress import strip_html

_LDJSON_RE = re.compile(
    r"""<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>""",
    flags=re.IGNORECASE | re.DOTALL,
)

#: Types schema.org considérés comme des articles datés.
ARTICLE_TYPES = {
    "newsarticle", "article", "blogposting", "report", "webpage",
    "liveblogposting", "techarticle",
}

_TIME_TAG_RE = re.compile(
    r"""<time[^>]*datetime=["']([^"']+)["'][^>]*>(.*?)</time>""",
    flags=re.IGNORECASE | re.DOTALL,
)
_LINK_NEAR_RE = re.compile(
    r"""<a[^>]+href=["']([^"']+)["'][^>]*>(.*?)</a>""",
    flags=re.IGNORECASE | re.DOTALL,
)


def _iter_json_objects(payload):
    """Parcourt récursivement un JSON-LD, y compris les `@graph` imbriqués."""
    if isinstance(payload, list):
        for item in payload:
            yield from _iter_json_objects(item)
    elif isinstance(payload, dict):
        yield payload
        for key in ("@graph", "itemListElement", "mainEntity"):
            if key in payload:
                yield from _iter_json_objects(payload[key])


def extract_jsonld_entries(text: str, base_url: str, spec: SourceSpec) -> list[RawEntry]:
    """Articles datés extraits des blocs JSON-LD d'une page."""
    entries: list[RawEntry] = []
    seen_urls: set[str] = set()

    for block in _LDJSON_RE.findall(text):
        try:
            payload = json.loads(html.unescape(block.strip()))
        except (ValueError, TypeError):
            continue

        for node in _iter_json_objects(payload):
            node_type = node.get("@type", "")
            if isinstance(node_type, list):
                types = {str(t).lower() for t in node_type}
            else:
                types = {str(node_type).lower()}
            if not types & ARTICLE_TYPES:
                continue

            published = parse_date(
                node.get("datePublished")
                or node.get("dateCreated")
                or node.get("dateModified")
                or ""
            )
            if not published:
                continue

            url = node.get("url") or node.get("mainEntityOfPage") or ""
            if isinstance(url, dict):
                url = url.get("@id", "")
            url = urljoin(base_url, str(url)) if url else ""
            if url and url in seen_urls:
                continue
            if url:
                seen_urls.add(url)

            headline = strip_html(str(node.get("headline") or node.get("name") or ""))
            summary = strip_html(str(node.get("description") or ""))

            entries.append(
                RawEntry(
                    title=headline,
                    url=url,
                    published=published,
                    summary=summary,
                    threat=spec.default_threat,
                    location=spec.location_rule,
                )
            )

    return entries


#: Dates écrites en clair dans le HTML, sans balise dédiée. Couvre l'ISO, les
#: formats numériques courants et les dates en toutes lettres, en français
#: comme en anglais.
_MONTHS = (
    "janvier|fevrier|février|mars|avril|mai|juin|juillet|aout|août|septembre|"
    "octobre|novembre|decembre|décembre|"
    "january|february|march|april|may|june|july|august|september|october|"
    "november|december|"
    "jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec"
)
_TEXT_DATE_RE = re.compile(
    r"(?<![\d/-])("
    r"\d{4}-\d{2}-\d{2}"
    r"|\d{1,2}[/.]\d{1,2}[/.]\d{4}"
    rf"|\d{{1,2}}(?:er)?\s+(?:{_MONTHS})\.?\s+\d{{4}}"
    rf"|(?:{_MONTHS})\.?\s+\d{{1,2}},?\s+\d{{4}}"
    r")(?![\d/-])",
    flags=re.IGNORECASE,
)


def extract_dated_link_entries(
    text: str, base_url: str, spec: SourceSpec
) -> list[RawEntry]:
    """Dernier repli : dates écrites en clair, associées au lien le plus proche.

    Beaucoup de sites institutionnels — les CERT en particulier — publient une
    liste d'alertes en HTML statique, sans données structurées ni balise
    `<time>`. La date y est du texte ordinaire à côté du lien. Ce repli reste
    générique : il ne présume d'aucune classe CSS propre à un site.
    """
    entries: list[RawEntry] = []
    seen: set[str] = set()

    for match in _TEXT_DATE_RE.finditer(text):
        published = parse_date(match.group(1))
        if not published:
            continue

        start = max(0, match.start() - 1500)
        end = min(len(text), match.end() + 1500)
        window = text[start:end]

        best_url = ""
        best_title = ""
        best_distance = None
        anchor = match.start() - start

        for link in _LINK_NEAR_RE.finditer(window):
            href = link.group(1)
            label = strip_html(link.group(2))
            if not href or href.startswith("#") or "javascript:" in href.lower():
                continue
            if len(label) < 12:
                continue
            # Distance au bord le plus proche du lien : une date placée juste
            # après un lien lui appartient, même si le lien suivant commence
            # plus près de son point de départ.
            if link.start() <= anchor <= link.end():
                distance = 0
            else:
                distance = min(abs(link.start() - anchor), abs(link.end() - anchor))
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_url = urljoin(base_url, href)
                best_title = label

        if not best_url or best_url in seen:
            continue
        seen.add(best_url)

        entries.append(
            RawEntry(
                title=best_title,
                url=best_url,
                published=published,
                threat=spec.default_threat,
                location=spec.location_rule,
            )
        )

    return entries


def extract_time_tag_entries(text: str, base_url: str, spec: SourceSpec) -> list[RawEntry]:
    """Repli : balises `<time datetime>` associées au lien le plus proche.

    Moins précis que le JSON-LD, mais suffisant pour énumérer une liste
    d'articles datés sur les sites qui ne publient pas de données structurées.
    """
    entries: list[RawEntry] = []
    seen: set[str] = set()

    for match in _TIME_TAG_RE.finditer(text):
        published = parse_date(match.group(1))
        if not published:
            continue

        # Fenêtre de contexte autour de la balise, où chercher le lien.
        start = max(0, match.start() - 1200)
        end = min(len(text), match.end() + 1200)
        context = text[start:end]

        best_url = ""
        best_title = ""
        for link in _LINK_NEAR_RE.finditer(context):
            href = link.group(1)
            label = strip_html(link.group(2))
            if not href or href.startswith("#") or "javascript:" in href:
                continue
            if len(label) < 15:
                continue
            best_url = urljoin(base_url, href)
            best_title = label
            break

        if not best_url or best_url in seen:
            continue
        seen.add(best_url)

        entries.append(
            RawEntry(
                title=best_title,
                url=best_url,
                published=published,
                threat=spec.default_threat,
                location=spec.location_rule,
            )
        )

    return entries


#: Schémas de pagination essayés, dans l'ordre.
PAGINATION_PATTERNS = ["{base}page/{n}/", "{base}?page={n}", "{base}?paged={n}"]


def page_url(base: str, pattern: str, number: int) -> str:
    normalized = base if base.endswith("/") else base + "/"
    if "?" in base and pattern.startswith("{base}?"):
        normalized = base + "&"
        pattern = pattern.replace("{base}?", "{base}")
    return pattern.format(base=normalized, n=number)


class JsonLdCollector(Collector):
    """Parcourt une liste paginée en lisant les données structurées.

    La pagination est considérée valide tant qu'une page apporte des entrées
    inédites ; deux pages successives sans nouveauté signifient que le schéma
    d'URL testé n'est pas celui du site, ce qui donne `PAGINATION_BROKEN`
    plutôt qu'un faux `OK`.
    """

    name = "jsonld"

    def collect(self, client, spec: SourceSpec, window: Window) -> CollectResult:
        budget = client.source_budget()
        result = CollectResult(access_method="jsonld")

        max_pages = min(
            int(spec.params.get("max_pages", config.MAX_PAGES_PER_SOURCE)),
            config.MAX_PAGES_PER_SOURCE,
        )
        patterns = (
            [spec.params["pagination"]]
            if spec.params.get("pagination")
            else PAGINATION_PATTERNS
        )

        first = client.fetch(spec.start_url, budget)
        if not first.ok:
            result.reason_code = first.reason_code
            result.calls = budget.requests_made
            return result

        # Trois extracteurs génériques, du plus fiable au plus approximatif.
        extractors = [
            ("jsonld", extract_jsonld_entries),
            ("time-tag", extract_time_tag_entries),
            ("dated-link", extract_dated_link_entries),
        ]
        entries: list[RawEntry] = []
        method = ""
        for name, extractor in extractors:
            entries = extractor(first.text, spec.start_url, spec)
            if entries:
                method = name
                break

        if not entries:
            result.reason_code = status.REASON_NO_DATE
            result.calls = budget.requests_made
            return result

        extract = dict(extractors)[method]

        result.access_method = method
        seen_urls = {e.url for e in entries if e.url}
        collected = list(entries)
        result.units_done = 1
        page = 2

        # Une page contenant déjà une entrée antérieure à la fenêtre prouve que
        # la borne est atteinte : inutile de paginer davantage.
        reached = any(window.is_before_start(e.published) for e in entries)

        working_pattern = None
        while not reached and page <= max_pages and not budget.exhausted:
            fetched_any = False

            for pattern in ([working_pattern] if working_pattern else patterns):
                url = page_url(spec.start_url, pattern, page)
                response = client.fetch(url, budget)
                if not response.ok:
                    continue

                page_entries = extract(response.text, url, spec)
                fresh = [e for e in page_entries if e.url and e.url not in seen_urls]
                if not fresh:
                    continue

                working_pattern = pattern
                fetched_any = True
                seen_urls.update(e.url for e in fresh)
                collected.extend(fresh)
                result.units_done = page
                if any(window.is_before_start(e.published) for e in fresh):
                    reached = True
                break

            if not fetched_any:
                # Aucun schéma de pagination ne produit de nouveauté.
                if page == 2:
                    result.reason_code = status.REASON_PAGINATION
                    result.comment = "Aucun schéma de pagination reconnu au-delà de la page 1"
                else:
                    reached = True
                break

            page += 1

        if budget.exhausted and not reached:
            result.reason_code = status.REASON_BUDGET_SOURCE

        result.entries = [e for e in collected if window.contains(e.published)]
        result.reached_boundary = reached
        result.units_expected = max(result.units_done, page - 1 if reached else max_pages)
        if reached:
            result.units_expected = result.units_done
        result.calls = budget.requests_made
        return result
