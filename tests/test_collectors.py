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
from cyberwatch.collectors.ransomware_live import RansomwareLiveCollector, _entry_from_record
import cyberwatch.collectors.ransomware_live as ransomware_live
from cyberwatch.collectors.wordpress import WordPressCollector, entry_from_post, strip_html
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

    def test_content_est_optionnel_et_vient_de_la_meme_requete(self):
        payload = json.dumps([{
            "id": 42, "date": "2026-04-10T09:00:00", "link": "https://exemple.re/a",
            "title": {"rendered": "Services perturbés"},
            "excerpt": {"rendered": "Situation inhabituelle."},
            "content": {"rendered": "<p>La mairie est victime d'une cyberattaque.</p>"},
        }])
        client = FakeClient({
            "categories?slug=numerique": ok('[{"id": 7}]'),
            "/posts?": ok(payload, {"X-WP-TotalPages": "1"}),
        })
        spec = SourceSpec("TEST_LOCAL_MEDIA", config.LAYER_LOCAL_MEDIA, "Mayotte",
                          "https://exemple.re/numerique/", "wordpress",
                          params={"wp_endpoint": "https://exemple.re/wp-json/wp/v2",
                                  "categories": "numerique", "include_content": True})

        result = WordPressCollector().collect(client, spec, WINDOW)

        assert len(client.calls) == 2
        assert "content%2Ccategories" in client.calls[-1]
        assert result.entries[0].content == "La mairie est victime d'une cyberattaque."
        assert result.entries[0].source_item_id == "42"

    def test_content_reste_vide_pour_les_autres_collecteurs_wordpress(self):
        post = {
            "id": 9, "date": "2026-04-10", "link": "https://exemple.re/a",
            "title": {"rendered": "Cyberattaque.org : incident"},
            "excerpt": {"rendered": "Extrait"},
            "content": {"rendered": "<p>Corps non demandé</p>"},
        }
        spec = SourceSpec("CYBERATTAQUE_ORG", config.LAYER_CORE, "France")
        assert entry_from_post(post, spec).content == ""

    def test_recherches_declaratives_sont_dedupliquees_par_identifiant_natif(self):
        client = FakeClient({"/wp-json/wp/v2/posts": ok(WP_POSTS, {"X-WP-TotalPages": "1"})})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "Mayotte", "https://exemple.fr/", "wordpress", params={"search_terms": ["cyberattaque", "piratage"]})
        result = WordPressCollector().collect(client, spec, WINDOW)
        assert result.resolve() == (status.OK, 100)
        assert len(result.entries) == 2
        assert sum("search=" in url for url in client.calls) == 2


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
        assert result.items_seen == 2
        assert result.items_in_window == 1

    def test_flux_conserve_seen_avant_filtre_temporel(self):
        window = Window("2026-03-05", "2026-08-12")
        client = FakeClient({"exemple.re": ok(RSS_FEED)})
        spec = SourceSpec("TEST", config.LAYER_LOCAL_MEDIA, "La Réunion",
                          "https://exemple.re/cyber", "feed",
                          params={"feed_url": "https://exemple.re/feed/"})

        result = FeedCollector().collect(client, spec, window)

        assert result.items_seen == 2
        assert result.items_in_window == 1
        assert len(result.entries) == 1

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
    def test_date_discovered_est_prioritaire_comme_sur_la_carte_publique(self):
        entry = _entry_from_record({
            "victim": "Entreprise Alpha",
            "country": "FR",
            "discovered": "2026-08-12T16:28:01+00:00",
            "published": "2025-12-31T12:00:00+00:00",
            "attackdate": "2025-11-30",
        }, SourceSpec("RANSOMWARE_LIVE", config.LAYER_CORE, "Multi"), "FR")

        assert entry is not None
        assert entry.published == "2026-08-12"

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

    def test_api_429_est_reprise_apres_le_delai_source(self, monkeypatch):
        responses = iter([
            FetchResult(False, "", 429, "", status.REASON_HTTP_429),
            ok(RANSOMWARE_PAYLOAD),
        ])
        client = FakeClient({"ransomware.live": lambda _url: next(responses)})
        spec = SourceSpec("RANSOMWARE_LIVE", config.LAYER_CORE, "Multi",
                          collector="ransomware_live", params={"countries": ["FR"]})
        waits = []
        monkeypatch.setattr(ransomware_live.time, "sleep", waits.append)

        result = RansomwareLiveCollector().collect(client, spec, WINDOW)

        assert result.resolve()[0] == status.OK
        assert waits == [config.RANSOMWARE_LIVE_RATE_LIMIT_SECONDS]
        assert "rate_limit_retries=1" in result.comment

    def test_pays_404_apres_endpoint_valide_est_vide_et_reste_ok(self):
        def response(url):
            if url.endswith("/FR"):
                return ok(RANSOMWARE_PAYLOAD)
            return FetchResult(False, "", 404, "", status.REASON_HTTP_404)

        client = FakeClient({"ransomware.live": response})
        spec = SourceSpec("RANSOMWARE_LIVE", config.LAYER_CORE, "Multi",
                          collector="ransomware_live", params={"countries": ["FR", "RE"]})

        result = RansomwareLiveCollector().collect(client, spec, WINDOW)

        assert result.resolve()[0] == status.OK
        assert result.reason_code == status.REASON_OK
        assert result.units_done == result.units_expected == 2


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


# --------------------------------------------------------------------------
# Veille par flux directs des médias
# --------------------------------------------------------------------------

MEDIA_FEED = """<?xml version="1.0"?>
<rss version="2.0"><channel>
  <item>
    <title>Le CHU de La Réunion victime d'une cyberattaque</title>
    <link>https://media.re/1</link>
    <pubDate>Wed, 04 Mar 2026 06:00:00 GMT</pubDate>
    <description>Une intrusion a paralysé les services.</description>
  </item>
  <item>
    <title>Air Austral inaugure une nouvelle ligne</title>
    <link>https://media.re/2</link>
    <pubDate>Wed, 04 Mar 2026 06:00:00 GMT</pubDate>
    <description>Ouverture commerciale.</description>
  </item>
  <item>
    <title>Fuite de données chez un opérateur national</title>
    <link>https://media.re/3</link>
    <pubDate>Wed, 04 Mar 2026 06:00:00 GMT</pubDate>
    <description>Des données personnelles exposées.</description>
  </item>
</channel></rss>
"""


class TestMediaWatch:
    """Remplace les requêtes Google News, interdites par le robots.txt."""

    def _spec(self, domains, entities, require_entity=True):
        return SourceSpec(
            "WATCH", config.LAYER_ENTITY_WATCH, "La Réunion",
            f"https://{domains[0]}/", "mediawatch",
            location_rule="La Réunion",
            params={"domains": domains, "entities": entities,
                    "require_entity": require_entity},
        )

    def test_entite_reconnue_dans_le_flux(self):
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({"media.re": ok(MEDIA_FEED)})
        spec = self._spec(
            ["media.re"],
            [{"name": "CHU de La Réunion", "aliases": ["CHU Réunion"]}],
        )
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert len(result.entries) == 1
        assert result.entries[0].entity == "CHU de La Réunion"
        assert result.entries[0].organisation == "CHU de La Réunion"

    def test_article_non_cyber_ecarte_meme_si_entite_citee(self):
        """Une commune citée pour une inauguration n'est pas un incident."""
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({"media.re": ok(MEDIA_FEED)})
        spec = self._spec(["media.re"], [{"name": "Air Austral", "aliases": []}])
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert result.entries == []
        assert result.watch_rows[0]["items_found"] == 0

    def test_veille_regionale_sans_entite_requise(self):
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({"media.re": ok(MEDIA_FEED)})
        spec = self._spec(["media.re"], [], require_entity=False)
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        # Les deux articles cyber sont retenus, l'article commercial non.
        assert len(result.entries) == 2

    def test_media_injoignable_reduit_la_couverture(self):
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({"media.re": ok(MEDIA_FEED)})
        spec = self._spec(["media.re", "absent.re"], [], require_entity=False)
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        source_status, coverage = result.resolve()
        assert source_status == status.PARTIAL
        assert coverage < 100
        assert "1/2 médias interrogés" in result.comment

    def test_aucun_media_joignable_donne_fail(self):
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({})
        spec = self._spec(["absent.re"], [], require_entity=False)
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert result.resolve()[0] == status.FAIL
        assert result.reason_code != status.REASON_OK

    def test_etat_de_veille_par_entite(self):
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({"media.re": ok(MEDIA_FEED)})
        spec = self._spec(
            ["media.re"],
            [{"name": "CHU de La Réunion", "aliases": []},
             {"name": "Air Austral", "aliases": []}],
        )
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        rows = {r["entity"]: r for r in result.watch_rows}
        assert rows["CHU de La Réunion"]["items_found"] == 1
        assert rows["Air Austral"]["items_found"] == 0
        # Chaque entité surveillée est présente, touchée ou non.
        assert len(rows) == 2

    # ----------------------------------------------------------------
    # Chemin API : c'est lui qui rouvre l'historique.
    # Le sondage en CI a montré que les trois médias mahorais exposent une
    # API REST remontant à janvier, quand les médias réunionnais n'offrent
    # qu'un flux d'une semaine. Le collecteur doit donc préférer l'API quand
    # elle existe, et le dire dans son compte rendu.
    # ----------------------------------------------------------------

    def _wp_client(self, posts=None):
        payload = json.dumps(
            posts
            if posts is not None
            else [
                {
                    "id": 7,
                    "date": "2026-01-15T08:00:00",
                    "link": "https://media.yt/7",
                    "title": {"rendered": "Cyberattaque contre le CHU de Mayotte"},
                    "excerpt": {"rendered": "<p>Rançongiciel.</p>"},
                }
            ]
        )
        return FakeClient({"media.yt/wp-json/wp/v2/posts": ok(payload, {"X-WP-TotalPages": "1"})})

    def test_api_wordpress_preferee_au_flux(self):
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = self._wp_client()
        spec = self._spec(
            ["media.yt"], [{"name": "CHU de Mayotte", "aliases": []}]
        )
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert result.access_method == "media-api"
        assert len(result.entries) == 1
        assert result.entries[0].published == "2026-01-15"
        # Fenêtre énumérée de bout en bout : la source peut prétendre à OK.
        assert result.resolve() == (status.OK, 100)

    def test_api_vide_reste_un_zero_verifie(self):
        """Une API qui répond sans résultat ne fait pas retomber sur le flux."""
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = self._wp_client(posts=[])
        spec = self._spec(["media.yt"], [], require_entity=False)
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert result.entries == []
        assert result.resolve() == (status.OK, 100)

    def test_api_wordpress_parcourt_toutes_les_pages_de_recherche(self):
        """Une API >100 résultats n'est complète qu'après la page finale."""
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        def posts(url):
            page = 2 if "page=2" in url else 1
            start, stop = (101, 102) if page == 2 else (1, 101)
            payload = [
                {
                    "id": identifier,
                    "date": "2026-02-01T08:00:00",
                    "link": f"https://media.yt/{identifier}",
                    "title": {"rendered": f"Cyberattaque CHU de Mayotte {identifier}"},
                    "excerpt": {"rendered": "Incident informatique."},
                }
                for identifier in range(start, stop)
            ]
            return ok(json.dumps(payload), {"X-WP-TotalPages": "2"})

        client = FakeClient({"media.yt/wp-json/wp/v2/posts": posts})
        spec = self._spec(["media.yt"], [], require_entity=False)
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert len(result.entries) == 101
        assert any("page=2" in url for url in client.calls)
        assert result.resolve() == (status.OK, 100)

    def test_media_sans_api_reste_limite_a_son_flux(self):
        """Le flux ne remonte qu'à ses dernières entrées : jamais un OK."""
        from cyberwatch.collectors.mediawatch import MediaWatchCollector

        client = FakeClient({"media.re": ok(MEDIA_FEED)})
        spec = self._spec(["media.re"], [], require_entity=False)
        result = MediaWatchCollector().collect(client, spec, WINDOW)

        assert result.access_method == "media-feed"
        assert result.resolve()[0] == status.PARTIAL
        assert "ne remontant qu'au media.re au 2026-03-04" in result.comment


class TestPasDeLocalisationPrerenseignee:
    """Un collecteur ne recopie jamais la règle fixe de la source.

    Régression : les collecteurs génériques préremplissaient `entry.location`
    avec `spec.location_rule`. Le runner y voyait une localisation « publiée par
    la source » — rang 1 du §10 — ce qui écrasait le rang 2, le territoire de
    l'entité reconnue. Air Austral restait donc « France métropolitaine » alors
    même que la correction de rang 2 était en place et testée.
    """

    SPEC = SourceSpec(
        "TEST", config.LAYER_CORE, "France", "https://x/", "autodetect",
        location_rule=config.LOC_FRANCE,
    )

    def test_wordpress(self):
        from cyberwatch.collectors.wordpress import entry_from_post

        post = {
            "date": "2026-05-31T10:00:00", "link": "https://x/1",
            "title": {"rendered": "Air Austral"}, "excerpt": {"rendered": ""},
        }
        assert entry_from_post(post, self.SPEC).location == ""

    def test_feed(self):
        entries = parse_feed(RSS_FEED, self.SPEC)
        assert entries and all(e.location == "" for e in entries)

    def test_jsonld(self):
        entries = extract_jsonld_entries(JSONLD_PAGE, "https://x/", self.SPEC)
        assert entries and all(e.location == "" for e in entries)

    def test_ransomware_live_conserve_le_pays_reel(self):
        """Seule exception légitime : l'API publie un vrai pays."""
        client = FakeClient({"ransomware.live": ok(RANSOMWARE_PAYLOAD)})
        spec = SourceSpec("RANSOMWARE_LIVE", config.LAYER_CORE, "Multi",
                          collector="ransomware_live", params={"countries": ["FR"]})
        result = RansomwareLiveCollector().collect(client, spec, WINDOW)
        assert result.entries[0].location == config.LOC_FRANCE
