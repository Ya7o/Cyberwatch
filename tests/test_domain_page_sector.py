"""Preuve Secteur depuis la page officielle quand le nom EST un domaine.

Cas déclencheur réel : "Klark.ai" (reset 2026-08-25) restait Secteur Inconnu
alors que le nom collecté est lui-même le domaine officiel de l'organisation.
Aucun test ici ne touche le réseau : le worker est appelé avec une réponse
HTTP simulée.
"""
from __future__ import annotations

import pytest

from cyberwatch import (
    config,
    domain_page_sector as dps,
    official_site_discovery,
    organisation_sector as osec,
    store,
)


@pytest.fixture(autouse=True)
def _isolate_data_dir(monkeypatch, tmp_path):
    """resolve_all_organisation_sectors lit par défaut le cache LLM (P1) et
    le cache page officielle depuis un chemin dérivé de store.ITEMS_CSV :
    jamais data/ réel dans les tests (même précaution que
    test_organisation_sector.py). Un run de reset réel peuple
    data/organisation_sector_llm.csv avant que les tests ne s'exécutent ;
    sans cette isolation, un test comme "preuve seule -> Inconnu" devient
    non déterministe selon ce que la passe précédente a écrit pour la même
    organisation (constaté en CI : "Klark AI" y obtenait déjà un candidat
    LLM réel, faisant échouer l'assertion UNKNOWN)."""
    monkeypatch.setattr(store, "ITEMS_CSV", tmp_path / "items.csv")


class _Response:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200


_KLARK_HTML = (
    "<html><head><title>Klark</title>"
    "<meta name=\"description\" content=\"Plateforme SaaS d&#39;intelligence "
    "artificielle pour le service client\">"
    "</head><body>...</body></html>"
)


# --------------------------------------------------------------------------
# Déclencheur : uniquement un nom déjà en forme de domaine
# --------------------------------------------------------------------------


def test_nom_en_forme_de_domaine_est_reconnu():
    assert dps.organisation_is_domain("Klark.ai") == "klark.ai"
    assert dps.organisation_is_domain("iMapper.tech") == "imapper.tech"
    assert dps.organisation_is_domain("Lebonmateriel.fr") == "lebonmateriel.fr"


def test_nom_ordinaire_ne_declenche_jamais_ce_canal():
    """Le canal ne doit jamais dériver vers une découverte de site : sans
    domaine explicite dans le nom, il ne se déclenche pas du tout."""
    for name in ("Klark AI", "Groupe Bernard", "Emil Frey France", "", "Mairie de Drancy"):
        assert dps.organisation_is_domain(name) == ""


def test_selection_ignore_les_organisations_deja_qualifiees(make_item):
    connu = make_item(org="Klark.ai", sector=config.SECTOR_TECH)
    assert dps.select_organisations([connu]) == []


def test_selection_dedoublonne_les_graphies_de_la_meme_organisation(make_item):
    """Cas réel : "Klark AI" (FRENCHBREACHES) et "Klark.ai"
    (CYBERATTAQUE_ORG) partagent la même Organisation_Key. L'organisation ne
    doit être testée qu'une fois, via la graphie exploitable."""
    sans_domaine = make_item(source="FRENCHBREACHES", org="Klark AI", sector=config.SECTOR_UNKNOWN)
    avec_domaine = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="2", org="Klark.ai",
        sector=config.SECTOR_UNKNOWN, url="https://example.org/b",
    )
    assert sans_domaine.Organisation_Key == avec_domaine.Organisation_Key
    assert dps.select_organisations([sans_domaine, avec_domaine]) == [
        (avec_domaine.Organisation_Key, "Klark.ai"),
    ]


# --------------------------------------------------------------------------
# Extraction : titre + meta description uniquement
# --------------------------------------------------------------------------


def test_extraction_titre_et_description():
    title, description = dps.extract_page_activity(_KLARK_HTML)
    assert title == "Klark"
    assert description == "Plateforme SaaS d'intelligence artificielle pour le service client"


def test_apostrophe_ne_tronque_pas_la_description():
    """Une description française contient presque toujours une apostrophe ;
    la citation fermante doit être la même que l'ouvrante."""
    html = "<meta name='description' content=\"Editeur d'applications et de logiciels cloud\">"
    assert dps.extract_page_activity(html)[1] == "Editeur d'applications et de logiciels cloud"


def test_page_sans_metadonnees_ne_produit_rien():
    assert dps.extract_page_activity("<html><head></head><body>bonjour</body></html>") == ("", "")


# --------------------------------------------------------------------------
# Résolution : réseau simulé, jamais bloquante
# --------------------------------------------------------------------------


def test_resolution_non_applicable_sans_domaine_dans_le_nom(monkeypatch):
    monkeypatch.setattr(
        dps.company_evidence, "_http_get",
        lambda *a, **k: pytest.fail("aucun accès réseau ne doit être tenté"),
    )
    assert dps.resolve_domain_page("Groupe Bernard") is None


def test_resolution_extrait_un_secteur_depuis_la_page(monkeypatch):
    monkeypatch.setattr(official_site_discovery, "domain_matches_organisation", lambda *a: True)
    monkeypatch.setattr(dps.company_evidence, "_http_get", lambda *a, **k: _Response(_KLARK_HTML))
    monkeypatch.setattr(
        dps.context_sector, "classify_explicit_activity",
        lambda text: config.SECTOR_TECH if "logiciel" in text or "intelligence" in text else config.SECTOR_UNKNOWN,
    )

    row = dps.resolve_domain_page("Klark.ai")

    assert row["Status"] == dps.STATUS_MATCHED
    assert row["Sector"] == config.SECTOR_TECH
    assert row["URL"] == "https://klark.ai/"


def test_page_injoignable_ne_leve_jamais(monkeypatch):
    """Isolation des sources : une panne réseau est un statut, pas une
    exception qui ferait tomber la collecte."""
    monkeypatch.setattr(official_site_discovery, "domain_matches_organisation", lambda *a: True)
    monkeypatch.setattr(dps.company_evidence, "_http_get", lambda *a, **k: None)

    row = dps.resolve_domain_page("Klark.ai")

    assert row["Status"] == dps.STATUS_UNREACHABLE
    assert row["Sector"] == ""


def test_domaine_non_attribuable_ne_lit_jamais_la_page(monkeypatch):
    """Garde d'identité : sans propriété de domaine établie, la page n'est
    même pas téléchargée."""
    monkeypatch.setattr(official_site_discovery, "domain_matches_organisation", lambda *a: False)
    monkeypatch.setattr(
        dps.company_evidence, "_http_get",
        lambda *a, **k: pytest.fail("la page ne doit pas être lue"),
    )

    row = dps.resolve_domain_page("Klark.ai")

    assert row["Status"] == dps.STATUS_NO_EVIDENCE


def test_page_sans_activite_classable_reste_sans_preuve(monkeypatch):
    """Un argumentaire commercial trop générique ne devient jamais un
    secteur : `classify_explicit_activity` refuse, le canal n'invente rien."""
    monkeypatch.setattr(official_site_discovery, "domain_matches_organisation", lambda *a: True)
    monkeypatch.setattr(
        dps.company_evidence, "_http_get",
        lambda *a, **k: _Response("<title>Bienvenue</title><meta name='description' content='Innover ensemble'>"),
    )

    row = dps.resolve_domain_page("Klark.ai")

    assert row["Status"] == dps.STATUS_NO_EVIDENCE
    assert row["Sector"] == ""


# --------------------------------------------------------------------------
# Câblage dans l'arbitrage (organisation_sector.py), toujours hors-ligne
# --------------------------------------------------------------------------


def _cache_row(item, sector=config.SECTOR_TECH):
    return {
        "Organisation_Key": item.Organisation_Key, "Organisation": item.Organisation_Raw,
        "URL": "https://klark.ai/", "Status": dps.STATUS_MATCHED, "Sector": sector,
        "Page_Title": "Klark", "Page_Description": "Plateforme SaaS d'intelligence artificielle",
        "Fetched_At": "2026-08-25T00:00:00+00:00",
    }


def test_preuve_page_seule_reste_inconnu(make_item):
    """Preuve MEDIUM hors STRONG_EVIDENCE_TYPES. L'arbitrage applique donc
    §9 Cas 4 : un signal faible seul, sans candidat LLM convergent, laisse
    l'organisation Inconnu. Ce canal ne peut jamais, à lui seul, publier un
    secteur — il ne fait qu'ajouter une preuve à l'arbitrage existant."""
    item = make_item(org="Klark.ai", sector=config.SECTOR_UNKNOWN)

    decisions = osec.resolve_all_organisation_sectors(
        [item], reference={}, source_fact_rows=[], org_cache_rows=[],
        domain_page_rows=[_cache_row(item)],
    )
    decision = decisions[item.Organisation_Key]

    assert osec.EVIDENCE_DOMAIN_PAGE not in osec.STRONG_EVIDENCE_TYPES
    assert decision.status == osec.STATUS_UNKNOWN
    assert decision.sector == config.SECTOR_UNKNOWN

    changed, _provenance = osec.apply_organisation_sector_decisions([item], decisions)
    assert changed == 0
    assert item.Sector == config.SECTOR_UNKNOWN


def test_preuve_page_convergente_avec_le_llm_donne_un_tentative(make_item):
    """La valeur réelle de ce canal : faire converger un second signal
    indépendant avec le candidat LLM, ce qui fait passer l'organisation de
    Inconnu à TENTATIVE (candidat journalisé, toujours pas appliqué)."""
    item = make_item(org="Klark.ai", sector=config.SECTOR_UNKNOWN)
    llm_row = {
        "Organisation_Key": item.Organisation_Key, "Organisation": item.Organisation_Raw,
        "Sector": config.SECTOR_TECH, "Confidence": "0.60", "Basis": "explicit_activity",
        "Reason": "plateforme SaaS", "Model": "gpt-5-nano",
    }

    decisions = osec.resolve_all_organisation_sectors(
        [item], reference={}, source_fact_rows=[], org_cache_rows=[],
        llm_cache_rows=[llm_row], domain_page_rows=[_cache_row(item)],
    )
    decision = decisions[item.Organisation_Key]

    assert decision.status == osec.STATUS_TENTATIVE
    assert decision.sector == config.SECTOR_TECH
    assert osec.EVIDENCE_DOMAIN_PAGE in decision.evidence_types


def test_preuve_page_ne_supplante_pas_une_preuve_forte_contradictoire(make_item):
    """Une preuve forte (référentiel humain) prime : la page ne l'écrase pas
    et ne transforme pas non plus le résultat en conflit non résolu."""
    from cyberwatch import enrichment

    item = make_item(org="Klark.ai", sector=config.SECTOR_UNKNOWN)
    reference = {
        item.Organisation_Key: enrichment.Enrichment(
            organisation="Klark.ai", sector=config.SECTOR_HEALTH, location="", scope="France",
            reason="validation humaine", validation_url="https://klark.ai/about",
        )
    }

    decisions = osec.resolve_all_organisation_sectors(
        [item], reference=reference, source_fact_rows=[], org_cache_rows=[],
        domain_page_rows=[_cache_row(item)],
    )

    assert decisions[item.Organisation_Key].sector == config.SECTOR_HEALTH
