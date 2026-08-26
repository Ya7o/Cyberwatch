"""Tests du fallback de preuve organisationnelle canonique."""

from __future__ import annotations

from cyberwatch import ai, company_evidence, config, org_enrichment
from cyberwatch.collectors.base import RawEntry, SourceSpec


def test_http_get_se_replie_sur_l_agent_alternatif_si_le_premier_est_refuse(monkeypatch):
    """Cas réel (audit 2026-08-26) : les 9 tentatives réelles du run RESET du
    26/08 sont toutes revenues sans candidat. Le module reste toujours
    identifiable (jamais de déguisement en navigateur anonyme) mais doit
    pouvoir se replier sur l'agent alternatif du projet, comme http.py, si le
    premier agent est refusé."""
    calls = []

    class FakeResponse:
        def __init__(self, status_code):
            self.status_code = status_code
            self.text = "<html></html>"

    def fake_get(url, timeout, allow_redirects, headers):
        calls.append(headers["User-Agent"])
        if headers["User-Agent"] == company_evidence.USER_AGENT:
            return FakeResponse(403)
        return FakeResponse(200)

    monkeypatch.setattr(company_evidence.requests, "get", fake_get)

    response = company_evidence._http_get("https://example.org/", timeout=5)

    assert response is not None
    assert response.status_code == 200
    assert calls == [company_evidence.USER_AGENT, config.HTTP_USER_AGENT_FALLBACK]


def test_unwrap_search_url_decode_le_lien_bing():
    """Cas réel (audit 2026-08-26) : Bing renvoyait de vrais résultats
    (40-50 liens/requête, non bloqué) mais 100% étaient jetés en aval car
    ce désenveloppement ne connaissait que le format DuckDuckGo — les liens
    Bing restaient des URLs bing.com et tombaient dans BLOCKED_DOMAINS
    quelle que soit leur vraie destination."""
    wrapped = (
        "https://www.bing.com/ck/a?!&&p=abc"
        "&u=a1aHR0cHM6Ly9leGFtcGxlLmNvbS9tZW50aW9ucy1sZWdhbGVz&ntb=1"
    )

    assert company_evidence._unwrap_search_url(wrapped) == (
        "https://example.com/mentions-legales"
    )


def test_unwrap_search_url_bing_sans_parametre_u_reste_inchange():
    url = "https://www.bing.com/search?q=test"
    assert company_evidence._unwrap_search_url(url) == url


def test_classification_officielle_intermarche_commerce():
    result = company_evidence.classify_official_activity(
        "Intermarché est une enseigne de supermarchés. "
        "Retrouvez votre magasin et faites vos courses en ligne."
    )
    assert result is not None
    sector, evidence = result
    assert sector == config.SECTOR_RETAIL
    assert "supermarch" in evidence.lower() or "magasin" in evidence.lower()


def test_page_officielle_ambigue_reste_inconnue():
    assert company_evidence.classify_official_activity(
        "Le groupe exploite une banque et un magasin de détail."
    ) is None


def test_resolve_official_site_exige_identite_et_page_officielle(monkeypatch):
    monkeypatch.setattr(
        company_evidence,
        "_discover_official_sites",
        lambda org: ["https://www.intermarche.com/"],
    )
    monkeypatch.setattr(
        company_evidence,
        "_page",
        lambda url: (
            "Intermarché - vos courses en ligne et votre magasin",
            "Intermarché est une enseigne de supermarchés française.",
            [],
            "https://www.intermarche.com/",
        ),
    )

    evidence = company_evidence.resolve_official_site("Intermarché")

    assert evidence is not None
    assert evidence.sector == config.SECTOR_RETAIL
    assert evidence.evidence_url == "https://www.intermarche.com/"
    assert evidence.evidence_source == "intermarche.com"


def test_page_officielle_non_classable_reste_une_preuve_texte(monkeypatch):
    """Cas réel (audit 2026-08-26, Klark.ai) : le classificateur officiel
    strict rate une activité pourtant réelle. La page reste identifiée avec
    certitude comme officielle (garde d'identité déjà passée) : son titre +
    meta reste une preuve texte pour l'arbitrage LLM, jamais un secteur en
    soi (sector="", evidence_type="official_site_text")."""
    monkeypatch.setattr(
        company_evidence, "_discover_official_sites", lambda org: ["https://klark.ai/"],
    )
    monkeypatch.setattr(
        company_evidence, "_page",
        lambda url: (
            "Klark - plateforme d'intelligence artificielle pour la relation client",
            "Klark aide les équipes support à répondre plus vite.",
            [],
            "https://klark.ai/",
        ),
    )

    evidence = company_evidence.resolve_official_site("Klark.ai")

    assert evidence is not None
    assert evidence.sector == ""
    assert evidence.evidence_type == "official_site_text"
    assert "intelligence artificielle" in evidence.evidence_text
    assert evidence.evidence_url == "https://klark.ai/"


def test_page_officielle_classable_prime_sur_le_texte_seul(monkeypatch):
    """Un candidat qui classe déterministement doit toujours l'emporter sur
    le fallback texte d'un autre candidat, même découvert avant lui."""
    pages = {
        "https://faux-site.example/": (
            "Bienvenue chez Klark, une entreprise innovante",
            "",
            [],
            "https://faux-site.example/",
        ),
        "https://klark.ai/": (
            "Klark - vos courses en ligne et votre magasin",
            "Klark est une enseigne de supermarchés française.",
            [],
            "https://klark.ai/",
        ),
    }
    monkeypatch.setattr(
        company_evidence, "_discover_official_sites",
        lambda org: ["https://faux-site.example/", "https://klark.ai/"],
    )
    monkeypatch.setattr(company_evidence, "_page", lambda url: pages[url])

    evidence = company_evidence.resolve_official_site("Klark")

    assert evidence is not None
    assert evidence.sector == config.SECTOR_RETAIL
    assert evidence.evidence_url == "https://klark.ai/"


def test_org_enrichment_utilise_site_officiel_apres_not_found_registre(monkeypatch):
    state = org_enrichment.OrgEnrichmentState(
        enabled=True,
        max_calls=10,
        official_site_max_calls=10,
    )
    monkeypatch.setattr(org_enrichment, "_fetch", lambda *a, **k: {"results": []})
    monkeypatch.setattr(
        company_evidence,
        "resolve_official_site",
        lambda org: company_evidence.CompanyEvidence(
            sector=config.SECTOR_RETAIL,
            evidence_url="https://www.intermarche.com/",
            evidence_text="enseigne de supermarchés",
            evidence_source="intermarche.com",
        ),
    )

    record = org_enrichment.resolve(
        "intermarche",
        "Intermarché",
        "2026-08-16T23:00:00+04:00",
        state,
    )

    assert record is not None
    assert record.Match_Status == org_enrichment.MATCHED
    assert record.Validated_Sector == config.SECTOR_RETAIL
    assert record.Validated_Via == "official_site"
    assert record.Evidence_URL == "https://www.intermarche.com/"
    assert state.calls_not_found == 0
    assert state.official_site_matched == 1


def test_preuve_officielle_est_reutilisee_par_meme_organisation(monkeypatch):
    state = org_enrichment.OrgEnrichmentState(
        enabled=True,
        max_calls=10,
        official_site_max_calls=10,
    )
    registry_calls = []
    official_calls = []
    monkeypatch.setattr(
        org_enrichment,
        "_fetch",
        lambda *a, **k: registry_calls.append(1) or {"results": []},
    )
    monkeypatch.setattr(
        company_evidence,
        "resolve_official_site",
        lambda org: official_calls.append(org) or company_evidence.CompanyEvidence(
            sector=config.SECTOR_RETAIL,
            evidence_url="https://www.intermarche.com/",
            evidence_text="réseau de supermarchés",
            evidence_source="intermarche.com",
        ),
    )

    first = org_enrichment.resolve(
        "intermarche", "Intermarché", "2026-08-16T23:00:00+04:00", state
    )
    second = org_enrichment.resolve(
        "intermarche", "Intermarché", "2026-08-16T23:01:00+04:00", state
    )

    assert first is not None and second is not None
    assert second.Validated_Sector == config.SECTOR_RETAIL
    assert len(registry_calls) == 1
    assert official_calls == ["Intermarché"]
    assert state.cache_hits == 1


def test_nom_voisin_ne_reutilise_pas_cache_sans_alias_valide(monkeypatch):
    state = org_enrichment.OrgEnrichmentState(
        enabled=True,
        max_calls=10,
        official_site_max_calls=10,
    )
    monkeypatch.setattr(org_enrichment, "_fetch", lambda *a, **k: {"results": []})

    def official(org):
        if org == "Intermarché":
            return company_evidence.CompanyEvidence(
                sector=config.SECTOR_RETAIL,
                evidence_url="https://www.intermarche.com/",
                evidence_text="réseau de supermarchés",
                evidence_source="intermarche.com",
            )
        return None

    monkeypatch.setattr(company_evidence, "resolve_official_site", official)

    record = org_enrichment.resolve(
        "intermarche", "Intermarché", "2026-08-16T23:00:00+04:00", state
    )
    drive = org_enrichment.resolve(
        "intermarche drive",
        "Intermarché Drive",
        "2026-08-16T23:01:00+04:00",
        state,
    )

    assert record is not None and record.Validated_Sector == config.SECTOR_RETAIL
    assert drive is not None
    assert drive.Match_Status == org_enrichment.NOT_FOUND
    assert drive.Validated_Sector == ""


def test_budget_officiel_epuise_ne_fige_pas_not_found(monkeypatch):
    state = org_enrichment.OrgEnrichmentState(
        enabled=True,
        max_calls=10,
        official_site_max_calls=0,
    )
    monkeypatch.setattr(org_enrichment, "_fetch", lambda *a, **k: {"results": []})
    monkeypatch.setattr(
        company_evidence,
        "resolve_official_site",
        lambda org: (_ for _ in ()).throw(AssertionError("appel inattendu")),
    )

    record = org_enrichment.resolve(
        "intermarche",
        "Intermarché",
        "2026-08-16T23:00:00+04:00",
        state,
    )

    assert record is None
    assert "intermarche" not in state.cache


def test_ai_applique_preuve_officielle_sans_appel_openai(make_item, monkeypatch):
    item = make_item(
        source="BONJOURLAFUITE",
        org="Intermarché",
        sector=config.SECTOR_UNKNOWN,
        threat=config.THREAT_LEAK,
        location=config.LOC_FRANCE,
    )
    entry = RawEntry(
        title="Intermarché",
        summary="Données concernées : noms, emails.",
        published="2026-08-10",
        organisation="Intermarché",
    )
    spec = SourceSpec(
        source_id="BONJOURLAFUITE",
        layer=config.LAYER_CORE,
        zone=config.LOC_FRANCE,
        default_threat=config.THREAT_LEAK,
        location_rule=config.LOC_FRANCE,
    )
    org_state = org_enrichment.OrgEnrichmentState(enabled=True)
    record = org_enrichment.OrgEnrichmentRecord(
        Organisation_Key=item.Organisation_Key,
        Query_Name="Intermarché",
        Matched_Name="Intermarché",
        Activity_Label="réseau de supermarchés",
        Evidence_Source="intermarche.com",
        Evidence_URL="https://www.intermarche.com/",
        Match_Status=org_enrichment.MATCHED,
        Validated_Sector=config.SECTOR_RETAIL,
        Validated_Via="official_site",
        Cache_Version=org_enrichment.ORG_ENRICHMENT_CACHE_VERSION,
    )
    monkeypatch.setattr(org_enrichment, "resolve", lambda *a, **k: record)
    monkeypatch.setattr(
        ai,
        "_call_openai",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("appel OpenAI inattendu")),
    )

    state = ai.AiRunState(enabled=False, org_enrichment=org_state)
    ai.qualify_item(item, entry, spec, state)

    assert item.Sector == config.SECTOR_RETAIL
    assert state.sector_resolved_enrichment_cache == 1
    assert state.calls_attempted == 0
