"""Moteur de niveau 2, de la découverte au secteur publié.

Aucun test n'accède au réseau : le client HTTP, le résolveur DNS et les appels
de modèle sont tous injectés.
"""
import json

import pytest
import requests

from cyberwatch import config, llm_runtime, org_identity, sector_resolution, sector_semantic
from cyberwatch import blf_org_enrichment as blf
from cyberwatch import organisation_activity as oa
from cyberwatch import organisation_activity_external as engine_module
from cyberwatch import organisation_activity_llm as quote_llm
from cyberwatch import organisation_activity_store as evidence_store
from cyberwatch.http import Budget, FetchResult
from cyberwatch.model import Item
from cyberwatch import status as status_codes

SITE = "https://exemple-passpass.fr/qui-sommes-nous"
QUOTE = "PassPass est un service de vente de titres de transport."
PAGE = f"<html><article><h1>À propos</h1><p>{QUOTE}</p><p>Nous contacter.</p></article></html>"
DNS = {"exemple-passpass.fr": ["93.184.216.34"],
       "recherche-entreprises.api.gouv.fr": ["93.184.216.34"]}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("réseau interdit"))
    monkeypatch.setattr(org_identity, "ORGANISATION_IDENTITY_REGISTRY", {})
    monkeypatch.setenv("SECTOR_SEMANTIC_CACHE_PATH", str(tmp_path / "semantic.json"))
    monkeypatch.setenv("SECTOR_SEMANTIC_TRACE_PATH", str(tmp_path / "semantic-trace.json"))
    monkeypatch.setenv("EXTERNAL_ACTIVITY_TRACE_PATH", str(tmp_path / "external-trace.json"))
    monkeypatch.setenv("BLF_EXTERNAL_ACTIVITY_ENABLED", "1")
    monkeypatch.setenv("EXTERNAL_ACTIVITY_SHADOW_MODE", "1")


def resolver(host):
    if host not in DNS:
        raise OSError("NXDOMAIN")
    return DNS[host]


class FakeClient:
    """Doublure duck-typée rendant de vrais `FetchResult`, budget compris."""

    def __init__(self, routes, budget=None):
        self.routes = routes
        self.run_budget = budget or Budget(12, 60, "external_activity")
        self.calls = []

    def fetch(self, url, source_budget=None, headers=None, **kwargs):
        self.calls.append(url)
        self.run_budget.consume()
        if source_budget is not None and source_budget is not self.run_budget:
            source_budget.consume()
        for pattern, response in self.routes.items():
            if pattern in url:
                return response(url) if callable(response) else response
        return FetchResult(False, url, 404, "", status_codes.REASON_HTTP_404)


def ok(text, ctype="text/html"):
    return FetchResult(True, "", 200, text, status_codes.REASON_OK, 0.0,
                       {"Content-Type": ctype})


def _item(org="PassPass", key="passpass", item_id="ITM-blf"):
    return Item(Item_ID=item_id, Source_ID="BONJOURLAFUITE", Organisation_Raw=org,
                Organisation_Key=key, Published_Date="2026-09-12",
                Sector=config.SECTOR_UNKNOWN, Threat=config.THREAT_UNKNOWN,
                Location=config.LOC_REUNION, URL="https://bonjourlafuite.eu.org/")


def _fact(item, website=SITE):
    return {"Item_ID": item.Item_ID, "Source_ID": item.Source_ID,
            "Victim_Website": website, "Source_Sector_Raw": "",
            "Activity_Description": "", "Activity_Sector_Match": "",
            "Activity_Sector_Semantic": "", "Evidence_JSON": "{}",
            "Source_Metadata_JSON": "{}"}


def _engine(items, facts, routes, *, rows=None, quote_call=None, budget=None, now=""):
    client = FakeClient(routes, budget=budget)
    return engine_module.build_engine(
        items, facts, {}, run_id="RUN-T", client=client, rows=rows or {},
        resolver=resolver, quote_call=quote_call, now=now or "2026-09-12T00:00:00+00:00"), client


def origin(fact):
    return blf.metadata(fact["Source_Metadata_JSON"])[blf.KEY]["origin"]


def record(fact):
    return blf.metadata(fact["Source_Metadata_JSON"])[blf.KEY]


# --------------------------------------------------------------------------
# Mode shadow
# --------------------------------------------------------------------------

def test_le_mode_shadow_calcule_un_candidat_sans_publier_de_secteur():
    item, = [_item()]
    fact = _fact(item)
    engine, client = _engine([item], [fact], {SITE: ok(PAGE)})
    blf.enrich([item], [fact], provider=engine)

    assert client.calls == [SITE]
    assert not fact["Activity_Description"]
    assert origin(fact) == oa.ORIGIN_EXTERNAL_NOT_APPLIED
    shadow = record(fact)["shadow"]
    assert shadow["activity_description"] == QUOTE
    assert shadow["candidate_sector"] == config.SECTOR_TRANSPORT
    assert shadow["candidate_sector_origin"] == "rule"

    decision = sector_resolution.resolve_item(item, fact, {})
    assert (decision.sector, decision.status, decision.reason) == (
        config.SECTOR_UNKNOWN, "unknown", "NO_ACTIVITY_EVIDENCE")


def test_le_mode_actif_publie_le_secteur_par_la_chaine_existante(monkeypatch):
    monkeypatch.setenv("EXTERNAL_ACTIVITY_SHADOW_MODE", "0")
    item = _item()
    fact = _fact(item)
    engine, _ = _engine([item], [fact], {SITE: ok(PAGE)})
    assert blf.enrich([item], [fact], provider=engine) == [item.Item_ID]

    assert fact["Activity_Description"] == QUOTE
    assert json.loads(fact["Evidence_JSON"])["Activity_Description"] == QUOTE
    assert origin(fact) == oa.ORIGIN_EXTERNAL_APPLIED
    decision = sector_resolution.resolve_item(item, fact, {})
    assert (decision.sector, decision.status, decision.reason) == (
        config.SECTOR_TRANSPORT, "inferred", "ACTIVITY_RULE")
    assert decision.evidence_url == SITE


def test_shadow_puis_actif_ne_coute_aucun_appel_supplementaire(monkeypatch):
    """La parité de clé de cache est ce qui fait de l'activation un simple
    basculement de drapeau : le mapper taxonomique retrouve son verdict."""
    calls = []

    def taxonomy(_system, _user):
        # Un modèle conforme recopie la citation qu'on lui a fournie ; en
        # substituer une autre déclenche `EVIDENCE_SUBSTITUTED` et le verdict
        # retombe à Inconnu — garde déjà en place dans `sector_semantic._clean`.
        calls.append(1)
        return {"sector": config.SECTOR_TECH, "confidence": 0.9,
                "reason": "motif", "evidence": quote}

    quote = ("Acme est un opérateur de constellations de nanosatellites "
             "destinées à l'observation de la Terre.")
    page = f"<html><article><p>{quote}</p></article></html>"
    monkeypatch.setattr(sector_semantic, "_enabled", lambda: True)

    item = _item(org="Acme", key="acme", item_id="ITM-acme")
    fact = _fact(item)
    engine, _ = _engine([item], [fact], {SITE: ok(page)})
    # Le candidat shadow passe par le mapper existant, donc un appel.
    original = sector_semantic.map_activity

    def spy(organisation, activity, proof, **kwargs):
        return original(organisation, activity, proof, **{**kwargs, "call": taxonomy})

    monkeypatch.setattr(sector_semantic, "map_activity", spy)
    blf.enrich([item], [fact], provider=engine)
    shadow = record(fact)["shadow"]
    assert shadow["candidate_sector"] == config.SECTOR_TECH
    assert len(calls) == 1

    # Même entrée en mode actif : le cache répond, aucun appel de plus.
    verdict = original(shadow["organisation"], shadow["activity_description"],
                       shadow["evidence_quote"], source_sector_raw="", call=taxonomy)
    assert verdict["origin"] == "cache"
    assert len(calls) == 1


# --------------------------------------------------------------------------
# Idempotence, cache et retrait
# --------------------------------------------------------------------------

def test_deux_runs_identiques_produisent_des_faits_identiques(monkeypatch):
    monkeypatch.setenv("EXTERNAL_ACTIVITY_SHADOW_MODE", "0")
    item = _item()
    fact = _fact(item)
    engine, client = _engine([item], [fact], {SITE: ok(PAGE)})
    blf.enrich([item], [fact], provider=engine)
    first = dict(fact)
    rows = evidence_store.load(engine.evidence_rows())

    engine2, client2 = _engine([item], [fact], {SITE: ok(PAGE)}, rows=rows,
                               now="2026-09-13T00:00:00+00:00")
    blf.enrich([item], [fact], provider=engine2)
    assert fact == first
    assert client2.calls == []          # le cache dispense de toute requête
    assert engine2.counters.cache_hits == 1
    assert client.calls == [SITE]


def test_une_ligne_retiree_retire_l_activite_deja_appliquee(monkeypatch):
    monkeypatch.setenv("EXTERNAL_ACTIVITY_SHADOW_MODE", "0")
    item = _item()
    fact = _fact(item)
    engine, _ = _engine([item], [fact], {SITE: ok(PAGE)})
    blf.enrich([item], [fact], provider=engine)
    fact["Activity_Sector_Semantic"] = config.SECTOR_TRANSPORT
    assert fact["Activity_Description"] == QUOTE

    withdrawn = evidence_store.upsert({}, evidence_store.outcome_row(
        item.Organisation_Raw, "passpass", status=evidence_store.STATUS_WITHDRAWN,
        rejection_code=oa.EXTERNAL_WITHDRAWN))
    engine2, client2 = _engine([item], [fact], {SITE: ok(PAGE)}, rows=withdrawn)
    blf.enrich([item], [fact], provider=engine2)

    assert not fact["Activity_Description"]
    assert not fact["Activity_Sector_Semantic"]
    assert origin(fact) == oa.ORIGIN_EXTERNAL_NOT_APPLIED
    assert record(fact)["external_status"] == oa.EXTERNAL_WITHDRAWN
    assert client2.calls == []
    assert sector_resolution.resolve_item(item, fact, {}).sector == config.SECTOR_UNKNOWN


def test_plusieurs_items_d_une_organisation_ne_relancent_rien():
    first, second = _item(item_id="ITM-1"), _item(item_id="ITM-2")
    facts = [_fact(first), _fact(second)]
    engine, client = _engine([first, second], facts, {SITE: ok(PAGE)})
    for item, fact in zip((first, second), facts):
        engine.resolve(item)
    assert client.calls == [SITE]


# --------------------------------------------------------------------------
# Refus
# --------------------------------------------------------------------------

@pytest.mark.parametrize("page,expected", [
    ("<html><article><p>Just a moment...</p></article></html>", oa.EXTERNAL_CHALLENGE_BODY),
    ("<html><article><p>Widget Corp conçoit des systèmes industriels pour "
     "ses clients européens depuis 1998.</p></article></html>",
     oa.EXTERNAL_IDENTITY_NOT_NAMED),
    ("<html><article><p>PassPass Groupe est spécialisé dans la fabrication de "
     "logiciels de billettique pour les réseaux de transport urbain.</p>"
     "</article></html>", oa.EXTERNAL_IDENTITY_HOMONYM),
    ("<html><article><p>PassPass fait appel à un prestataire chargé du suivi "
     "des commandes de ses usagers.</p></article></html>", oa.EXTERNAL_NO_QUOTE),
])
def test_une_page_non_probante_laisse_le_secteur_inconnu(page, expected):
    item = _item()
    fact = _fact(item)
    engine, _ = _engine([item], [fact], {SITE: ok(page)})
    blf.enrich([item], [fact], provider=engine)
    assert not fact["Activity_Description"]
    assert record(fact)["external_status"] == expected
    assert sector_resolution.resolve_item(item, fact, {}).sector == config.SECTOR_UNKNOWN


def test_une_url_privee_n_est_jamais_telechargee():
    item = _item()
    fact = _fact(item, website="http://169.254.169.254/latest/meta-data/")
    engine, client = _engine([item], [fact], {})
    blf.enrich([item], [fact], provider=engine)
    assert not any("169.254" in url for url in client.calls)
    assert engine.counters.urls_rejected == 1
    assert not fact["Activity_Description"]


def test_une_panne_de_provider_n_est_jamais_fatale():
    item = _item()
    fact = _fact(item)

    class Broken:
        last_status = oa.EXTERNAL_ERROR

        def resolve(self, item):
            raise RuntimeError("panne inattendue")

    assert blf.enrich([item], [fact], provider=Broken()) == []
    assert record(fact)["external_status"] == oa.EXTERNAL_ERROR
    assert not fact["Activity_Description"]


def test_un_resolver_ne_peut_rien_imposer_directement():
    """Un provider qui rend autre chose qu'une preuve vérifiée n'obtient rien."""
    item = _item()
    fact = _fact(item)

    class Liar:
        last_status = oa.EXTERNAL_NO_CANDIDATE

        def resolve(self, item):
            return {"activity_description": QUOTE, "confidence": 0.99}

    blf.enrich([item], [fact], provider=Liar())
    assert not fact["Activity_Description"]


# --------------------------------------------------------------------------
# Budgets et efficience LLM
# --------------------------------------------------------------------------

def test_un_budget_epuise_est_distingue_d_une_absence_de_candidat():
    item = _item()
    fact = _fact(item)
    engine, client = _engine([item], [fact], {SITE: ok(PAGE)},
                             budget=Budget(0, 60, "external_activity"))
    blf.enrich([item], [fact], provider=engine)
    assert client.calls == []
    assert record(fact)["external_status"] == oa.EXTERNAL_BUDGET_EXHAUSTED
    assert engine.counters.budget_blocked == 1


def test_le_moteur_ne_touche_jamais_au_budget_de_la_collecte():
    from cyberwatch import runner  # noqa: F401 — vérifie seulement l'isolement
    item = _item()
    engine = engine_module.build_engine([item], [_fact(item)], {}, run_id="R",
                                        rows={}, resolver=resolver)
    assert engine is not None
    assert engine.budget is not None
    assert engine.budget.max_requests == config.EXTERNAL_ACTIVITY_MAX_REQUESTS
    assert engine.budget.max_requests < config.MAX_REQUESTS_PER_RUN


def test_aucun_appel_llm_sur_le_chemin_deterministe():
    item = _item()
    fact = _fact(item)
    engine, _ = _engine([item], [fact], {SITE: ok(PAGE)},
                        quote_call=lambda *a: pytest.fail("appel LLM interdit"))
    blf.enrich([item], [fact], provider=engine)
    assert engine.counters.llm_calls == 0
    assert engine.counters.quotes_deterministic == 1


def test_le_selecteur_est_appele_au_plus_une_fois_par_organisation():
    """Trois candidats, un seul appel : le compteur vit dans la boucle par
    organisation, pas par page."""
    calls = []
    opaque = "<html><article><p>Bienvenue sur le site de PassPass.</p><p>Notre maison a "\
             "été fondée en 1950 et compte 120 collaborateurs aujourd'hui.</p></article></html>"

    def call(_system, _user):
        calls.append(1)
        return {"found": False, "quote": ""}

    item = _item()
    fact = _fact(item, website="https://exemple-passpass.fr/a")
    fact2 = {**_fact(item, website="https://exemple-passpass.fr/b"), "Item_ID": "ITM-2"}
    other = _item(item_id="ITM-2")
    engine, client = _engine([item, other], [fact, fact2],
                             {"exemple-passpass.fr": ok(opaque)}, quote_call=call)
    engine.resolve(item)
    assert len(calls) == 1
    assert len(client.calls) >= 1


def test_une_citation_inventee_par_le_modele_est_rejetee():
    calls = []

    def call(_system, _user):
        calls.append(1)
        return {"found": True, "quote": "PassPass exploite un réseau de fibre optique."}

    opaque = "<html><article><p>Bienvenue sur le site de PassPass.</p><p>Notre maison a "\
             "été fondée en 1950 et compte 120 collaborateurs aujourd'hui.</p></article></html>"
    item = _item()
    fact = _fact(item)
    engine, _ = _engine([item], [fact], {SITE: ok(opaque)}, quote_call=call)
    blf.enrich([item], [fact], provider=engine)
    assert calls == [1]
    assert not fact["Activity_Description"]
    assert record(fact)["external_status"] == oa.EXTERNAL_QUOTE_NOT_GROUNDED


def test_la_tache_de_citation_reste_sur_le_modele_par_defaut():
    """La renommer avec un marqueur riche la routerait silencieusement vers un
    modèle cinq fois plus cher."""
    assert quote_llm.TASK == "activity_quote"
    assert not any(marker in quote_llm.TASK for marker in llm_runtime.RICH_TASK_MARKERS)
    assert llm_runtime.model_for_task(quote_llm.TASK) == llm_runtime.DEFAULT_MODEL
    assert llm_runtime.DEFAULT_TASK_BUDGETS[quote_llm.TASK]["max_calls"] <= 10


def test_sans_cle_ni_doublure_le_selecteur_n_appelle_rien():
    assert quote_llm.select_quote("PassPass", "un texte") == ("", quote_llm.ORIGIN_DISABLED)


# --------------------------------------------------------------------------
# Périmètre
# --------------------------------------------------------------------------

def test_le_moteur_est_desactive_hors_ligne_et_par_defaut(monkeypatch):
    item = _item()
    assert engine_module.build_engine([item], [], {}, offline=True) is None
    monkeypatch.delenv("BLF_EXTERNAL_ACTIVITY_ENABLED", raising=False)
    assert engine_module.build_engine([item], [], {}) is None


@pytest.mark.parametrize("source", ["FRENCHBREACHES", "CYBERATTAQUE_ORG",
                                    "RANSOMWARE_LIVE", "VEILLE_LLM"])
def test_seul_bonjourlafuite_declenche_le_niveau_2(source):
    item = _item()
    item.Source_ID = source
    engine, client = _engine([item], [_fact(item)], {SITE: ok(PAGE)})
    assert engine is None or engine.resolve(item) is None
    assert client.calls == []


def test_un_conflit_historique_n_est_jamais_contourne():
    """Déjà verrouillé côté niveau 1 ; re-vérifié avec le vrai moteur."""
    item = _item()
    fact = _fact(item)
    engine, client = _engine([item], [fact], {SITE: ok(PAGE)})
    meta = {blf.KEY: {"origin": "BLF_ACTIVITY_CONFLICT"}}
    fact["Source_Metadata_JSON"] = json.dumps(meta)
    other = Item(Item_ID="ITM-h1", Source_ID="FRENCHBREACHES", Organisation_Raw="PassPass",
                 Organisation_Key="passpass", Published_Date="2026-01-01",
                 URL="https://example.org/a")
    third = Item(Item_ID="ITM-h2", Source_ID="FRENCHBREACHES", Organisation_Raw="PassPass",
                 Organisation_Key="passpass", Published_Date="2026-02-01",
                 URL="https://example.org/b")
    activity_a = QUOTE
    activity_b = "PassPass est une entreprise spécialisée dans la fabrication de logiciels."
    facts = [fact,
             {"Item_ID": "ITM-h1", "Source_ID": "FRENCHBREACHES",
              "Activity_Description": activity_a,
              "Evidence_JSON": json.dumps({"Activity_Description": activity_a})},
             {"Item_ID": "ITM-h2", "Source_ID": "FRENCHBREACHES",
              "Activity_Description": activity_b,
              "Evidence_JSON": json.dumps({"Activity_Description": activity_b})}]
    blf.enrich([item, other, third], facts, provider=engine)
    assert origin(fact) == "BLF_ACTIVITY_CONFLICT"
    assert client.calls == []
