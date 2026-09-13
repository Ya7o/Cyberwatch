"""Benchmark d'activation du niveau 2, rejoué en test.

Ce que ce fichier verrouille n'est pas « le rapport existe » mais « les portes
bloquantes passent encore ». Un durcissement futur qui ferait perdre un cas
justifié, ou un relâchement qui publierait un secteur non prouvé, échoue ici.

Aucun test n'accède au réseau.
"""
import json
import sys
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cyberwatch import config  # noqa: E402
from scripts import evaluate_external_activity as bench  # noqa: E402

CASES = ROOT / "validation" / "external_activity_20" / "cases.json"


@pytest.fixture(autouse=True)
def no_network(monkeypatch, tmp_path):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(requests.Session, "request",
                        lambda *a, **k: pytest.fail("réseau interdit"))
    monkeypatch.setenv("SECTOR_SEMANTIC_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SECTOR_SEMANTIC_TRACE_PATH", str(tmp_path / "trace.json"))
    monkeypatch.setenv("EXTERNAL_ACTIVITY_TRACE_PATH", str(tmp_path / "ext.json"))


@pytest.fixture(scope="module")
def report():
    return bench.evaluate(CASES)


def test_le_corpus_compte_vingt_incidents_et_toutes_ses_fixtures():
    payload = json.loads(CASES.read_text(encoding="utf-8"))
    assert len(payload["cases"]) == 20
    base = CASES.parent
    for case in payload["cases"]:
        for url, entry in case.get("fixtures", {}).items():
            assert "body" in entry or (base / entry["body_file"]).exists(), (case, url)


def test_le_corpus_couvre_toutes_les_familles_exigees():
    """Chaque famille du cahier des charges doit être représentée, sinon un
    rapport vert ne prouverait rien de ce qu'il prétend."""
    payload = json.loads(CASES.read_text(encoding="utf-8"))
    identifiers = " ".join(case["case_id"] for case in payload["cases"])
    for marker in ("nom-simple", "homonyme", "marque", "site-officiel-difficile",
                   "mappee-par-le-mapper", "reellement-ambigue", "piege-prestataire",
                   "piege-filiale", "conflit-de-preuve", "cible-interdite",
                   "reutilisation-du-cache", "registre"):
        assert marker in identifiers, marker
    kinds = {case["kind"] for case in payload["cases"]}
    assert {"prose", "registry", "safety", "cache"} <= kinds


def test_toutes_les_portes_bloquantes_passent(report):
    failed = [gate for gate in report["gates"] if not gate["ok"]]
    assert not failed, failed
    assert report["passed"]


def test_aucun_secteur_n_est_publie_sans_preuve_ni_identite(report):
    """Les deux invariants qui feraient échouer le benchmark à eux seuls."""
    for row in report["results"]:
        if row["Final_Candidate_Sector"] == config.SECTOR_UNKNOWN:
            continue
        assert row["Activity_Description"].strip(), row["Case_ID"]
        assert row["Evidence_Quote"].strip(), row["Case_ID"]
        assert row["Identity_Verified"], row["Case_ID"]
        assert row["Selected_URL"].startswith("https://"), row["Case_ID"]


def test_le_cas_qare_reste_refuse(report):
    """Le cas mesuré sur l'API réelle : concordance de nom sans corroboration."""
    qare = next(row for row in report["results"] if row["Case_ID"].startswith("16-"))
    assert qare["Final_Candidate_Sector"] == config.SECTOR_UNKNOWN
    assert qare["External_Status"] == "EXTERNAL_IDENTITY_UNVERIFIED"
    assert qare["LLM_Calls"] == 0


def test_une_cible_interdite_n_est_jamais_lue(report):
    ssrf = next(row for row in report["results"] if row["Case_ID"].startswith("19-"))
    assert ssrf["Final_Candidate_Sector"] == config.SECTOR_UNKNOWN
    assert not ssrf["Evidence_Quote"]
    # L'hôte qui résout en adresse privée n'est jamais demandé ; celui qui
    # redirige l'est une fois, mais son corps n'est pas exploité.
    assert not any("cartabl-prive" in url for url in ssrf["Requested_URLs"])
    assert not any("169.254" in url for url in ssrf["Requested_URLs"])


def test_le_cache_supprime_la_seconde_requete(report):
    cached = next(row for row in report["results"] if row["Case_ID"].startswith("20-"))
    assert cached["Passes"][0]["requests"] == 1
    assert cached["Passes"][1]["requests"] == 0


def test_le_budget_de_modele_reste_marginal(report):
    """Aucun chemin déterministe ne paie, et aucun cas ne dépasse un appel par
    étage (désignation de citation, puis taxonomie)."""
    assert report["totals"]["llm_calls"] <= 8
    for row in report["results"]:
        assert row["LLM_Quote_Calls"] <= 1, row["Case_ID"]
        assert row["LLM_Sector_Calls"] <= 1, row["Case_ID"]
    deterministic = [row for row in report["results"]
                     if row["Deterministic_Sector"] != config.SECTOR_UNKNOWN]
    assert deterministic
    assert all(row["LLM_Sector_Calls"] == 0 for row in deterministic)


def test_le_rapport_publie_est_a_jour():
    """Le rapport versionné doit correspondre au corpus versionné."""
    published = json.loads(
        (CASES.parent / "report.json").read_text(encoding="utf-8"))
    assert published["cases"] == 20
    assert published["passed"] is True
    assert published["version"] == json.loads(
        CASES.read_text(encoding="utf-8"))["version"]
