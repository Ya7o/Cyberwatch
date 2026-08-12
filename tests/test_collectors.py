"""Collecteurs testés hors ligne, sur des formats standards.

Ces tests n'atteignent jamais le réseau : ils exercent les parseurs sur des
échantillons des trois formats standardisés que la chaîne d'accès sait lire, et
vérifient que les plafonds de volumétrie s'appliquent réellement.
"""

import json

import pytest

from cyberwatch import config, status
from cyberwatch.collectors.base import SourceSpec, Window
from cyberwatch.collectors.feed import FeedCollector, parse_feed
from cyberwatch.collectors.jsonld import (
    JsonLdCollector,
    extract_jsonld_entries,
    extract_time_tag_entries,
)
from cyberwatch.collectors.newsrss import (
    NewsRssCollector,
    build_url,
    clean_title,
    entity_queries,
    mentions_entity,
)
from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector
from cyberwatch.collectors.wordpress import WordPressCollector, strip_html
from cyberwatch.http import Budget, FetchResult

WINDOW = Window("2026-01-01", "2026-08-12")


class FakeClient:
    """Client HTTP simulé : associe des motifs d'URL à des réponses figées."""

    def __init__(self, routes, run_budget=None):
        self.routes = routes
        self.run_budget = run_budget or Budget(1000, 600)
        self.calls = []

    def fetch(self, url, source_budget=None, headers=None):
        self.calls.append(url)
        self.run_budget.consume()
        if source_budget is not None:
            source_budget.consume()
        for pattern, response in self.routes.items():
            if pattern in url:
                return response(url) if callable(response) else response
        return FetchResult(False, url, 404, "", status.REASON_HTTP_404)

    def source_budget(self):
        return Budget(
            config.MAX_REQUESTS_PER_SOURCE, config.MAX_SECONDS_PER_SOURCE
        )


def ok(text, headers=None):
    return FetchResult(True, "", 200, text, status.REASON_OK, 0.0, headers or {})


# --------------------------------------------------------------------------
# Échantillons de formats standards
# --------------------------------------------------------------------------

WP_POSTS = json.dumps(
    [
        {
            "id": 1,
            "date": "2026-03-05T10:00:00",
            "link": "https://exemple.fr/a",
            "title": {"rendered": "Mairie de Saint-Leu : fuite de donn&eacute;es"},
            "excerpt": {"rendered": "<p>Une fuite de donn&eacute;es a &eacute;t&eacute; constat&eacute;e.</p>"},
        },
        {
            "id": 2,
            "date": "2026-02-01T09:00:00",
            "link": "https://exemple.fr/b",
            "title": {"rendered": "Cyberattaque contre un h&ocirc;pital"},
            "excerpt": {"rendered": "<p>Ransomware.</p>"},
        },
    ]
)

RSS_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0"><channel>
  <title>Exemple</title>
  <item>
    <title>Cyberattaque contre Air Austral</title>
    <link>https://exemple.re/1</link>
    <pubDate>Thu, 05 Mar 2026 08:00:00 +0400</pubDate>
    <description>Un incident informatique majeur.</description>
  </item>
  <item>
    <title>Fuite de données à la mairie</title>
    <link>https://exemple.re/2</link>
    <pubDate>Mon, 05 Jan 2026 08:00:00 +0400</pubDate>
    <description>Données personnelles exposées.</description>
  </item>
</channel></rss>
"""

JSONLD_PAGE = """<html><head>
<script type="application/ld+json">
{"@context":"https://schema.org","@type":"NewsArticle",
 "headline":"Ransomware contre le CHU","datePublished":"2026-04-10T12:00:00+04:00",
 "url":"https://media.re/article-1","description":"Le CHU est touché."}
</script>
<script type="application/ld+json">
{"@context":"https://schema.org","@graph":[
 {"@type":"NewsArticle","headline":"Fuite de données à la région",
  "datePublished":"2025-12-20","url":"https://media.re/article-2"}]}
</script>
</head><body></body></html>
"""

TIME_TAG_PAGE = """<html><body>
<article>
  <time datetime="2026-05-02">2 mai 2026</time>
  <a href="/actu/cyberattaque-mairie">Cyberattaque contre la mairie de Saint-Paul</a>
</article>
</body></html>
"""

RANSOMWARE_PAYLOAD = json.dumps(
    [
        {
            "victim": "Entreprise Alpha",
            "attackdate": "2026-05-01",
            "group_name": "lockbit",
            "country": "FR",
            "activity": "Manufacturing",
            "post_url": "https://ransomware.live/alpha",
        },
        {
            "victim": "Beta Ltd",
            "attackdate": "2025-01-01",
            "group_name": "akira",
            "country": "FR",
        },
    ]
)

GOOGLE_NEWS_FEED = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <item>
    <title>Le CHU de La Réunion victime d'une cyberattaque - Zinfos974</title>
    <link>https://news.google.com/rss/articles/ABC</link>
    <pubDate>Wed, 04 Mar 2026 06:00:00 GMT</pubDate>
    <description>Le CHU de La Réunion a subi une intrusion.</description>
  </item>
  <item>
    <title>Conseil régional : nouveau budget - LINFO</title>
    <link>https://news.google.com/rss/articles/DEF</link>
    <pubDate>Wed, 04 Mar 2026 06:00:00 GMT</pubDate>
    <description>Budget voté.</description>
  </item>
</channel></rss>
"""


# --------------------------------------------------------------------------
# WordPress
# --------------------------------------------------------------------------


class TestWordPress:
    def test_strip_html(self):
        assert strip_html("<p>Bonjour &amp; bonsoir</p>") == "Bonjour & bonsoir"

    def test_collecte_et_borne_atteinte(self):
        client = FakeClient(
            {"/wp-json/wp/v2/posts": ok(WP_POSTS, {"X-WP-TotalPages": "1"})}
        )
        spec = SourceSpec("TEST", config.LAYER_CORE, "France",
                          "https://exemple.fr/liste", "wordpress")
        result = WordPressCollector().collect(client, spec, WINDOW)

        assert len(result.entries) == 2
        assert result.entries[0].published == "2026-03-05"
        assert result.entries[0].title == "Mairie de Saint-Leu : fuite de données"
        assert result.reached_boundary is True
        assert result.resolve() == (status.OK, 100)

    def test_site_non_wordpress_donne_fail(self):
        client = FakeClient({})
        spec = SourceSpec("TEST", config.LAYER_CORE, "France",
                          "https://exemple.fr/liste", "wordpress")
        result = WordPressCollector().collect(client, spec, WINDOW)
        assert result.reason_code == status.REASON_NO_FEED
        assert result.resolve()[0] == status.FAIL


# --------------------------------------------------------------------------
# Flux RSS / Atom
# --------------------------------------------------------------------------


class TestFeed:
    def test_parse_rss(self):
        spec = SourceSpec("TEST", config.LAYER_CORE, "La Réunion")
        entries = parse_feed(RSS_FEED, spec)
        assert len(entries) == 2
        assert entries[0].title == "Cyberattaque contre Air Austral"
        assert entries[0].published == "2026-03-05"

    def test_flux_remontant_avant_la_borne_donne_ok(self):
        window = Window("2026-02-01", "2026-08-12")
        client = FakeClient({"exemple.re": ok(RSS_FEED)})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion",
                          "https://exemple.re/cyber", "feed",
                          params={"feed_url": "https://exemple.re/feed/"})
        result = FeedCollector().collect(client, spec, window)
        assert result.reached_boundary is True
        assert result.resolve() == (status.OK, 100)

    def test_flux_trop_court_donne_partial(self):
        """Un flux qui ne redescend pas jusqu'à la borne n'est jamais OK."""
        window = Window("2025-01-01", "2026-08-12")
        client = FakeClient({"exemple.re": ok(RSS_FEED)})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion",
                          "https://exemple.re/cyber", "feed",
                          params={"feed_url": "https://exemple.re/feed/"})
        result = FeedCollector().collect(client, spec, window)

        assert result.reached_boundary is False
        source_status, coverage = result.resolve()
        assert source_status == status.PARTIAL
        assert coverage < 100
        assert "ne remonte que" in result.comment


# --------------------------------------------------------------------------
# JSON-LD et repli sur les balises time
# --------------------------------------------------------------------------


class TestJsonLd:
    def test_extraction_jsonld(self):
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion")
        entries = extract_jsonld_entries(JSONLD_PAGE, "https://media.re/", spec)
        assert len(entries) == 2
        assert entries[0].title == "Ransomware contre le CHU"
        assert entries[0].published == "2026-04-10"

    def test_extraction_graph_imbrique(self):
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion")
        entries = extract_jsonld_entries(JSONLD_PAGE, "https://media.re/", spec)
        assert any(e.url.endswith("article-2") for e in entries)

    def test_repli_balise_time(self):
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion")
        entries = extract_time_tag_entries(TIME_TAG_PAGE, "https://media.re/", spec)
        assert len(entries) == 1
        assert entries[0].published == "2026-05-02"
        assert entries[0].url == "https://media.re/actu/cyberattaque-mairie"

    def test_repli_dates_en_texte_brut(self):
        """Cas des sites de CERT : HTML statique, sans JSON-LD ni balise time."""
        from cyberwatch.collectors.jsonld import extract_dated_link_entries

        page = """<html><body><ul>
          <li><a href="/alerts/ransomware">Ransomware warning for local banks</a> — 12 August 2026</li>
          <li>05/07/2026 : <a href="/alerts/phishing">Phishing campaign targeting citizens</a></li>
        </ul><footer>&copy; 2026 CERT-SC</footer></body></html>"""
        spec = SourceSpec("TEST", config.LAYER_CORE, "Seychelles")
        entries = extract_dated_link_entries(page, "https://cert-sc.sc/alerts/", spec)

        assert len(entries) == 2
        # Chaque date s'accroche au lien dont elle est la plus proche, y compris
        # lorsqu'elle est placée après le lien.
        by_url = {e.url: e.published for e in entries}
        assert by_url["https://cert-sc.sc/alerts/ransomware"] == "2026-08-12"
        assert by_url["https://cert-sc.sc/alerts/phishing"] == "2026-07-05"

    def test_annee_seule_ignoree(self):
        """Un « © 2026 » de pied de page n'est pas une date d'article."""
        from cyberwatch.collectors.jsonld import extract_dated_link_entries

        spec = SourceSpec("TEST", config.LAYER_CORE, "Seychelles")
        page = '<a href="/a">Un titre suffisamment long</a> &copy; 2026'
        assert extract_dated_link_entries(page, "https://x/", spec) == []

    def test_chaine_des_trois_extracteurs(self):
        """Le collecteur retombe sur les dates en clair si rien d'autre ne marche."""
        page = """<html><body>
          <a href="/alerts/a">Alerte de sécurité sur un service public</a> 2026-04-10
          <a href="/alerts/b">Ancienne alerte hors fenêtre</a> 2025-10-01
        </body></html>"""
        client = FakeClient({"cert.example/alerts": ok(page)})
        spec = SourceSpec("TEST", config.LAYER_CORE, "Seychelles",
                          "https://cert.example/alerts/", "jsonld")
        result = JsonLdCollector().collect(client, spec, WINDOW)

        assert result.access_method == "dated-link"
        assert result.reached_boundary is True
        assert result.resolve() == (status.OK, 100)
        assert len(result.entries) == 1  # celle de 2025 est hors fenêtre

    def test_borne_atteinte_par_entree_anterieure(self):
        """Une entrée antérieure à la fenêtre prouve que la borne est atteinte."""
        client = FakeClient({"media.re/liste": ok(JSONLD_PAGE)})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion",
                          "https://media.re/liste", "jsonld")
        result = JsonLdCollector().collect(client, spec, WINDOW)
        assert result.reached_boundary is True
        assert result.resolve() == (status.OK, 100)
        # L'entrée de décembre 2025 est hors fenêtre et n'est pas retenue.
        assert all(WINDOW.contains(e.published) for e in result.entries)

    def test_page_sans_date_donne_fail(self):
        client = FakeClient({"media.re/liste": ok("<html><body>rien</body></html>")})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion",
                          "https://media.re/liste", "jsonld")
        result = JsonLdCollector().collect(client, spec, WINDOW)
        assert result.reason_code == status.REASON_NO_DATE
        assert result.resolve()[0] == status.FAIL


# --------------------------------------------------------------------------
# Google News RSS
# --------------------------------------------------------------------------


class TestNewsRss:
    def test_deux_requetes_par_entite(self):
        """Fusion documentée de Q1-Q4 : deux requêtes, pas quatre."""
        queries = entity_queries("CHU de La Réunion", "fr", "La Réunion")
        assert len(queries) == 2
        assert all('"CHU de La Réunion"' in q for q in queries)
        assert all("La Réunion" in q for q in queries)

    def test_contexte_territorial_present(self):
        """Sans contexte, « Mairie de Saint-Denis » ramènerait la métropole."""
        queries = entity_queries("Mairie de Saint-Denis", "fr", "La Réunion")
        assert all("La Réunion" in q for q in queries)

    def test_url_sans_cle_api(self):
        url = build_url('"test" (cyberattaque)', "fr", 14)
        assert url.startswith("https://news.google.com/rss/search?q=")
        assert "hl=fr" in url and "when%3A14d" in url

    def test_titre_nettoye(self):
        assert clean_title("Cyberattaque contre le CHU - Zinfos974") == (
            "Cyberattaque contre le CHU"
        )

    def test_mention_entite_verifiee(self):
        from cyberwatch.collectors.base import RawEntry

        entry = RawEntry(title="Le CHU de La Réunion victime d'une attaque")
        assert mentions_entity(entry, "CHU de La Réunion", [])
        assert not mentions_entity(entry, "Air Austral", [])

    def test_collecte_filtre_les_articles_hors_sujet(self):
        client = FakeClient({"news.google.com": ok(GOOGLE_NEWS_FEED)})
        spec = SourceSpec(
            "WATCH", config.LAYER_ENTITY_WATCH, "La Réunion",
            "https://news.google.com/rss/search", "newsrss",
            location_rule="La Réunion",
            params={"entities": [{"name": "CHU de La Réunion", "aliases": [],
                                  "context": "La Réunion"}]},
        )
        result = NewsRssCollector().collect(client, spec, WINDOW)

        # Seul l'article citant l'entité est retenu.
        assert len(result.entries) == 1
        assert "CHU" in result.entries[0].title
        assert result.units_expected == 2
        assert result.reached_boundary is True

    def test_etat_de_veille_produit(self):
        client = FakeClient({"news.google.com": ok(GOOGLE_NEWS_FEED)})
        spec = SourceSpec(
            "WATCH", config.LAYER_ENTITY_WATCH, "La Réunion",
            "https://news.google.com/rss/search", "newsrss",
            params={"entities": [{"name": "CHU de La Réunion", "aliases": [],
                                  "context": "La Réunion"}]},
        )
        result = NewsRssCollector().collect(client, spec, WINDOW)
        assert len(result.watch_rows) == 1
        row = result.watch_rows[0]
        assert row["entity"] == "CHU de La Réunion"
        assert row["queries_expected"] == 2
        assert row["queries_done"] == 2
        assert row["status"] == status.OK


# --------------------------------------------------------------------------
# ransomware.live
# --------------------------------------------------------------------------


class TestRansomwareLive:
    def test_collecte_et_filtrage_fenetre(self):
        client = FakeClient({"ransomware.live": ok(RANSOMWARE_PAYLOAD)})
        spec = SourceSpec("RANSOMWARE_LIVE", config.LAYER_CORE, "Multi",
                          collector="ransomware_live", params={"countries": ["FR"]})
        result = RansomwareLiveCollector().collect(client, spec, WINDOW)

        assert len(result.entries) == 1  # celui de 2025 est hors fenêtre
        entry = result.entries[0]
        assert entry.organisation == "Entreprise Alpha"
        assert entry.threat == config.THREAT_RANSOMWARE
        assert entry.location == config.LOC_FRANCE
        assert "lockbit" in entry.title

    def test_api_injoignable_donne_fail(self):
        client = FakeClient({})
        spec = SourceSpec("RANSOMWARE_LIVE", config.LAYER_CORE, "Multi",
                          collector="ransomware_live", params={"countries": ["FR"]})
        result = RansomwareLiveCollector().collect(client, spec, WINDOW)
        assert result.resolve()[0] == status.FAIL


# --------------------------------------------------------------------------
# Plafonds de volumétrie
# --------------------------------------------------------------------------


class TestBudgets:
    def test_budget_epuise_est_signale(self):
        budget = Budget(max_requests=3, max_seconds=600)
        for _ in range(3):
            budget.consume()
        assert budget.exhausted

    def test_plafond_de_pages_respecte(self):
        """Une pagination infinie s'arrête au plafond et rend PARTIAL."""
        page = JSONLD_PAGE.replace('"datePublished":"2025-12-20"',
                                   '"datePublished":"2026-04-01"')

        def unique_page(url):
            # Chaque page renvoie une URL inédite : la pagination ne s'épuise jamais.
            return ok(page.replace("article-1", f"article-{abs(hash(url)) % 10**6}")
                          .replace("article-2", f"article-b-{abs(hash(url)) % 10**6}"))

        client = FakeClient({"media.re": unique_page})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion",
                          "https://media.re/liste", "jsonld",
                          params={"max_pages": 5})
        result = JsonLdCollector().collect(client, spec, WINDOW)

        assert result.reached_boundary is False
        assert result.units_done <= 5
        source_status, coverage = result.resolve()
        assert source_status == status.PARTIAL
        assert coverage < 100

    def test_repli_agent_sur_403(self):
        """403 alors que robots.txt autorise : on se re-présente autrement.

        Le refus vient d'un pare-feu filtrant sur l'agent, pas d'une politique
        d'exclusion. Le repli conserve l'identification du projet.
        """
        from cyberwatch.http import HttpClient

        calls = []

        class Response:
            def __init__(self, code, text=""):
                self.status_code = code
                self.text = text
                self.headers = {}

        client = HttpClient(respect_robots=False, polite_delay=0)

        def fake_get(url, timeout=None, headers=None):
            agent = (headers or {}).get("User-Agent", config.HTTP_USER_AGENT)
            calls.append(agent)
            if agent == config.HTTP_USER_AGENT:
                return Response(403)
            return Response(200, "<html>ok</html>")

        client.session.get = fake_get
        result = client.fetch("https://exemple.fr/page")

        assert result.ok is True
        assert len(calls) == 2
        assert calls[1] == config.HTTP_USER_AGENT_FALLBACK
        # L'identité du projet reste visible dans l'agent de repli.
        assert "Cyberwatch" in config.HTTP_USER_AGENT_FALLBACK

    def test_budget_de_run_bloque_les_requetes(self):
        run_budget = Budget(max_requests=1, max_seconds=600)
        run_budget.consume()
        from cyberwatch.http import HttpClient

        client = HttpClient(run_budget=run_budget)
        result = client.fetch("https://exemple.fr")
        assert result.ok is False
        assert result.reason_code == status.REASON_BUDGET_RUN
