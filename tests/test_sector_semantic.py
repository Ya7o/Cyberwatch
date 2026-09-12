"""Contrat du rapprochement sémantique de second niveau.

Deux exigences distinctes. D'abord le portillon : le mapper ne doit s'ouvrir
que là où une activité est prouvée ET où le déterministe est réellement muet —
tout le reste est une régression de preuve. Ensuite la dégradation : sans clé,
sans budget ou sur panne, la réponse est Inconnu, jamais une exception ni une
supposition. Aucun test n'accède au réseau.
"""
from __future__ import annotations

import json

import pytest
import requests

from cyberwatch import config, llm_runtime, sector_resolution, sector_semantic
from cyberwatch.model import Item

SALT = ("Salt Mobile SA est un opérateur suisse de téléphonie mobile, "
        "internet fixe et télévision.")
INEDIT = "Acme est un opérateur de constellations de nanosatellites en orbite basse."


@pytest.fixture(autouse=True)
def _isolated_cache(monkeypatch, tmp_path):
    monkeypatch.setenv("SECTOR_SEMANTIC_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SECTOR_SEMANTIC_TRACE_PATH", str(tmp_path / "trace.json"))


def _item(name: str = "Acme") -> Item:
    return Item(Item_ID="ITM-test", Source_ID="TEST", Organisation_Raw=name,
                Organisation_Key=name.casefold(), Sector=config.SECTOR_UNKNOWN)


def _fact(proof: str, **extra) -> dict:
    fact = {"Item_ID": "ITM-test", "Activity_Description": proof,
            "Evidence_JSON": json.dumps({"Activity_Description": proof})}
    fact.update(extra)
    return fact


def _answer(sector=config.SECTOR_TECH, confidence=0.88, evidence=None, reason="motif"):
    def call(_system, _user):
        return {"sector": sector, "confidence": confidence,
                "reason": reason, "evidence": INEDIT if evidence is None else evidence}
    return call


# ---------------------------------------------------------------------------
# Portillon : quand le mapper doit rester fermé
# ---------------------------------------------------------------------------

def test_aucun_trou_quand_le_deterministe_sait_mapper():
    proof = "Aqualter est une entreprise spécialisée dans la gestion de l'eau."
    assert sector_semantic.gap(_item("Aqualter"), _fact(proof), {}) is None


def test_aucun_trou_quand_seule_la_citation_est_classable():
    """GreenGo : `rule` muet mais `proof_rule` parle — le déterministe répond."""
    proof = "GreenGo est une plateforme de réservation d'hébergements de tourisme durable."
    fact = _fact("GreenGo opère dans le voyage.")
    fact["Evidence_JSON"] = json.dumps({"Activity_Description": proof})
    assert sector_semantic.gap(_item("GreenGo"), fact, {}) is None


def test_aucun_trou_quand_le_premier_appel_a_deja_tranche():
    fact = _fact(INEDIT, Activity_Sector_Match=config.SECTOR_TECH)
    assert sector_semantic.gap(_item(), fact, {}) is None


def test_aucun_trou_quand_la_preuve_ne_rattache_pas_la_victime():
    fact = _fact("Un prestataire chargé du suivi des commandes est concerné.")
    assert sector_semantic.gap(_item(), fact, {}) is None


def test_aucun_trou_sans_activite_prouvee():
    assert sector_semantic.gap(_item(), {"Item_ID": "ITM-test"}, {}) is None


def test_aucun_trou_derriere_une_reference_exacte():
    from types import SimpleNamespace
    reference = {"acme": SimpleNamespace(sector=config.SECTOR_FINANCE,
                                         reason="validée",
                                         validation_url="https://example.org/a")}
    assert sector_semantic.gap(_item(), _fact(INEDIT), reference) is None


def test_aucun_trou_derriere_un_nom_institutionnel_sur():
    proof = "La Ville de Joigny est un opérateur de services de proximité inédits."
    assert sector_semantic.gap(_item("Ville de Joigny"), _fact(proof), {}) is None


def test_la_colonne_deja_remplie_rend_la_passe_idempotente():
    fact = _fact(INEDIT, Activity_Sector_Semantic=config.SECTOR_TECH)
    assert sector_semantic.gap(_item(), fact, {}) is None


def test_un_trou_reel_est_detecte():
    found = sector_semantic.gap(_item(), _fact(INEDIT), {})
    assert found == (INEDIT, INEDIT)


# ---------------------------------------------------------------------------
# CAS 4 : le déterministe n'a pas à être exhaustif
# ---------------------------------------------------------------------------

def test_une_activite_inedite_est_mappee_puis_resolue_de_bout_en_bout():
    item, fact = _item(), _fact(INEDIT)
    assert sector_resolution.sector_policy.classify_sector_activity(INEDIT) == (
        config.SECTOR_UNKNOWN)
    changed = sector_semantic.annotate_source_facts([item], [fact], {}, call=_answer())
    assert changed == ["ITM-test"]
    assert fact["Activity_Sector_Semantic"] == config.SECTOR_TECH
    decision = sector_resolution.resolve_item(item, fact, {})
    assert (decision.sector, decision.status, decision.reason) == (
        config.SECTOR_TECH, "inferred", "SEMANTIC_ACTIVITY_MATCH")
    assert decision.confidence == 0.80
    assert decision.evidence == INEDIT  # aucune preuve inventée


def test_la_provenance_est_tracee_dans_les_metadonnees():
    fact = _fact(INEDIT)
    sector_semantic.annotate_source_facts([_item()], [fact], {}, call=_answer())
    meta = json.loads(fact["Source_Metadata_JSON"])[sector_semantic.METADATA_KEY]
    assert meta["sector"] == config.SECTOR_TECH
    assert meta["origin"] == "call"
    assert meta["taxonomy_version"] == sector_semantic.TAXONOMY_VERSION


# ---------------------------------------------------------------------------
# Contrat de sortie : ce que le mapper n'a pas le droit de faire
# ---------------------------------------------------------------------------

def test_une_confiance_insuffisante_laisse_inconnu():
    item, fact = _item(), _fact(INEDIT)
    assert sector_semantic.annotate_source_facts(
        [item], [fact], {}, call=_answer(confidence=0.65)) == []
    assert not fact.get("Activity_Sector_Semantic")
    decision = sector_resolution.resolve_item(item, fact, {})
    assert (decision.sector, decision.reason) == (
        config.SECTOR_UNKNOWN, "ACTIVITY_TAXONOMY_UNRESOLVED")


def test_un_secteur_hors_taxonomie_est_refuse():
    verdict = sector_semantic.map_activity("Acme", INEDIT, INEDIT,
                                           call=_answer(sector="Aéronautique"))
    assert (verdict["sector"], verdict["reason"]) == (
        config.SECTOR_UNKNOWN, "OUT_OF_TAXONOMY")


def test_inconnu_reste_une_reponse_disponible():
    verdict = sector_semantic.map_activity(
        "Acme", INEDIT, INEDIT, call=_answer(sector=config.SECTOR_UNKNOWN, confidence=0.95))
    assert verdict["sector"] == config.SECTOR_UNKNOWN


def test_une_preuve_substituee_invalide_le_verdict():
    verdict = sector_semantic.map_activity(
        "Acme", INEDIT, INEDIT, call=_answer(evidence="Une tout autre phrase."))
    assert (verdict["sector"], verdict["reason"]) == (
        config.SECTOR_UNKNOWN, "EVIDENCE_SUBSTITUTED")


def test_le_schema_ferme_la_taxonomie():
    schema = sector_semantic.schema()
    assert schema["properties"]["sector"]["enum"] == list(config.SECTORS)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(schema["properties"])


def test_l_entree_du_modele_ignore_l_incident():
    """Ni l'attaque, ni les données volées, ni la menace ne sont transmises."""
    captured = {}

    def call(system, user):
        captured["system"], captured["user"] = system, user
        return {"sector": config.SECTOR_TECH, "confidence": 0.9,
                "reason": "r", "evidence": INEDIT}

    sector_semantic.map_activity("Acme", INEDIT, INEDIT,
                                 source_sector_raw="Télécom & Médias", call=call)
    assert INEDIT in captured["user"] and "Télécom & Médias" in captured["user"]
    for interdit in ("ransomware", "rançongiciel", "données volées", "victimes"):
        assert interdit not in captured["user"]
    assert all(name in captured["user"] for name in config.SECTORS)


# ---------------------------------------------------------------------------
# Dégradation : jamais d'exception, jamais un secteur inventé
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("error", [
    llm_runtime.LlmBudgetExceeded("budget épuisé"),
    llm_runtime.LlmError("HTTP 500"),
    RuntimeError("panne inattendue"),
])
def test_une_panne_laisse_inconnu_sans_lever(error):
    def call(_system, _user):
        raise error

    item, fact = _item(), _fact(INEDIT)
    assert sector_semantic.annotate_source_facts([item], [fact], {}, call=call) == []
    assert not fact.get("Activity_Sector_Semantic")


def test_une_panne_n_est_jamais_mise_en_cache():
    def call(_system, _user):
        raise llm_runtime.LlmError("HTTP 500")

    sector_semantic.map_activity("Acme", INEDIT, INEDIT, call=call)
    assert sector_semantic._load_cache() == {}


def test_sans_cle_api_aucune_requete_n_est_emise(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("appel réseau interdit"))
    verdict = sector_semantic.map_activity("Acme", INEDIT, INEDIT)
    assert (verdict["sector"], verdict["origin"]) == (config.SECTOR_UNKNOWN, "disabled")


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

def test_le_cache_evite_un_second_appel():
    calls = []

    def call(_system, _user):
        calls.append(1)
        return {"sector": config.SECTOR_TECH, "confidence": 0.9,
                "reason": "r", "evidence": INEDIT}

    for _ in range(2):
        sector_semantic.map_activity("Acme", INEDIT, INEDIT, call=call)
    assert len(calls) == 1
    assert sector_semantic.map_activity("Acme", INEDIT, INEDIT, call=call)["origin"] == "cache"


def test_une_evolution_de_taxonomie_invalide_la_cle(monkeypatch):
    before = sector_semantic.cache_key(INEDIT, INEDIT)
    monkeypatch.setattr(sector_semantic, "TAXONOMY_VERSION", "0000deadbeef")
    assert sector_semantic.cache_key(INEDIT, INEDIT) != before


def test_un_cache_corrompu_ne_casse_pas_la_passe(monkeypatch, tmp_path):
    path = tmp_path / "cache.json"
    path.write_text("{ pas du json", encoding="utf-8")
    monkeypatch.setenv("SECTOR_SEMANTIC_CACHE_PATH", str(path))
    assert sector_semantic._load_cache() == {}
    assert sector_semantic.map_activity(
        "Acme", INEDIT, INEDIT, call=_answer())["sector"] == config.SECTOR_TECH


# ---------------------------------------------------------------------------
# Invariants d'architecture
# ---------------------------------------------------------------------------

def test_le_mapper_reste_route_vers_le_modele_economique(monkeypatch):
    """Le module dit « semantic », la tâche dit « taxonomy » : piège à verrouiller.

    Tout nom de tâche contenant un marqueur de `RICH_TASK_MARKERS` router ait
    silencieusement vers gpt-5-mini et quintuplerait le coût, sans erreur.
    """
    monkeypatch.delenv("OPENAI_MODEL", raising=False)
    monkeypatch.delenv("SECTOR_TAXONOMY_MODEL", raising=False)
    assert not llm_runtime._is_rich_task(sector_semantic.TASK)
    assert llm_runtime.model_for_task(sector_semantic.TASK) == llm_runtime.DEFAULT_MODEL
    assert sector_semantic.TASK in llm_runtime.DEFAULT_TASK_BUDGETS


def test_resolve_item_ne_touche_jamais_le_reseau(monkeypatch):
    """`check`, le site et la boucle de reprise l'appellent : elle reste pure."""
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("appel réseau interdit"))
    item = _item()
    fact = _fact(INEDIT, Activity_Sector_Semantic=config.SECTOR_TECH)
    first = sector_resolution.resolve_item(item, fact, {})
    second = sector_resolution.resolve_item(_item(), fact, {})
    assert first == second == sector_resolution.resolve_item(_item(), fact, {})
    # Le transport est celui du pipeline réel : `resolve_items` pose
    # `item.Sector`, puis `check` recalcule et ne doit trouver aucun écart.
    sector_resolution.resolve_items([item], [fact], {})
    assert item.Sector == config.SECTOR_TECH
    assert sector_resolution.fact_transport_gaps([item], [fact], {}) == []
    assert sector_resolution.entry_sector_decision is not None


def test_un_conflit_avec_le_deterministe_reste_explicite():
    """Le mapper comble les trous du déterministe, il ne le remplace pas."""
    proof = "Aqualter est une entreprise spécialisée dans la gestion de l'eau."
    fact = _fact(proof, Activity_Sector_Semantic=config.SECTOR_TECH)
    decision = sector_resolution.resolve_item(_item("Aqualter"), fact, {})
    assert (decision.sector, decision.reason) == (
        config.SECTOR_UNKNOWN, "ACTIVITY_SECTOR_CONFLICT")


def test_la_purge_efface_le_cache_et_la_trace():
    from cyberwatch import reset
    assert "sector_semantic_cache.json" in reset.GENERATED_FILES
    assert "sector_semantic_trace.json" in reset.GENERATED_FILES
    assert "SECTOR_SEMANTIC_CACHE_PATH" in reset.RUNTIME_PATH_OPTIONS
