from cyberwatch import official_site_discovery


class _Response:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_domain_identity_uses_distinctive_token_and_rejects_news_domain():
    assert official_site_discovery.domain_matches_organisation(
        "Gîtes de France", "https://www.gites-de-france.com/"
    )
    assert not official_site_discovery.domain_matches_organisation(
        "Gîtes de France", "https://actualites-tourisme.fr/gites-de-france"
    )


def test_domain_identity_accepts_deterministic_acronym():
    assert official_site_discovery.domain_matches_organisation(
        "Bibliothèque Nationale de France", "https://www.bnf.fr/"
    )


def test_wikidata_is_only_discovery_and_requires_exact_label(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(kwargs.get("params", {}).get("action"))
        if kwargs["params"]["action"] == "wbsearchentities":
            return _Response({
                "search": [
                    {"id": "Q1", "label": "Atout France", "match": {"text": "Atout France"}},
                    {"id": "Q2", "label": "Atout France Holding", "match": {"text": "Atout France Holding"}},
                ]
            })
        return _Response({
            "entities": {
                "Q1": {
                    "claims": {
                        "P856": [{
                            "mainsnak": {
                                "datavalue": {"value": "https://www.atout-france.fr/"}
                            }
                        }]
                    }
                }
            }
        })

    monkeypatch.setattr(official_site_discovery.requests, "get", fake_get)
    sites = official_site_discovery._wikidata_official_sites("Atout France")

    assert sites == ["https://www.atout-france.fr/"]
    assert calls == ["wbsearchentities", "wbgetentities"]


def test_discovery_prefers_valid_hint_without_search(monkeypatch):
    monkeypatch.setattr(
        official_site_discovery,
        "_wikidata_official_sites",
        lambda organisation: [],
    )
    monkeypatch.setattr(
        official_site_discovery,
        "_search_candidates",
        lambda organisation: (_ for _ in ()).throw(AssertionError("search inattendue")),
    )
    monkeypatch.setattr(
        official_site_discovery,
        "_direct_domain_guesses",
        lambda organisation: [],
    )

    sites = official_site_discovery.discover_official_sites(
        "Intermarché",
        [
            "https://actualites-exemple.fr/intermarche",
            "https://www.intermarche.com/qui-sommes-nous?utm_source=x",
        ],
    )

    assert sites == ["https://www.intermarche.com/qui-sommes-nous"]


def test_search_candidates_keep_only_identity_bearing_domains(monkeypatch):
    monkeypatch.setattr(
        official_site_discovery.company_evidence,
        "_search_links",
        lambda query: [
            ("Actiale - site officiel", "https://www.actiale.fr/"),
            ("Actiale : actualité", "https://www.example-news.fr/actiale"),
        ],
    )
    monkeypatch.setattr(
        official_site_discovery.company_evidence,
        "_candidate_relevance",
        lambda organisation, title, url: 10,
    )

    assert official_site_discovery._search_candidates("Actiale") == [
        "https://www.actiale.fr/"
    ]
