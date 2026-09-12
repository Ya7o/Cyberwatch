"""Non-régression de la réparation de preuve, sur le run RUN-20260912T164223.

Ce run a produit 39 champs acceptés et 23 non acceptés. Les 23 sont figés ici :
chacun porte un verdict attendu après réparation. Le jeu sert autant à prouver
que les faux négatifs de citation sont récupérés qu'à empêcher la réparation de
devenir un mécanisme de contournement des validateurs.

Aucun test ne touche le réseau, GitHub ni le LLM : tout rejoue la trace.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from cyberwatch.evidence_repair import candidate_sentences, repair_evidence
from cyberwatch.source_facts_ai_activity import evidence_repair_eligibility
from cyberwatch.source_facts_ai_normalize import _normalize

FIXTURE = Path(__file__).parent / "fixtures" / "source_facts_repair_20260912.json"
CASES = json.loads(FIXTURE.read_text())["cases"]


def _settle(case: dict) -> str:
    """Rejoue un champ : éligibilité, réparation, puis validateurs existants.

    La citation réparée n'est jamais acceptée d'autorité : elle est réinjectée
    dans `_normalize`, qui reste seul juge.
    """
    if not evidence_repair_eligibility(case["field"], case["original_rejection"], case["rejection_kind"]):
        return "rejected"
    evidence = repair_evidence(case["field"], case["proposed_value"], case["context"], case["organisation"])
    if not evidence:
        return "rejected"
    proposal = {**case["proposal"], "evidence": evidence}
    raw = {case["field"]: [proposal] if case["is_list"] else proposal}
    accepted = _normalize(raw, case["context"], {case["field"]}, case["organisation"])
    return "accepted" if case["field"] in accepted else "rejected"


def _ident(case: dict) -> str:
    return f"{case['organisation']}-{case['item_id'][4:10]}-{case['field']}"


def test_le_corpus_fige_les_vingt_trois_champs_non_acceptes():
    assert len(CASES) == 23
    assert {case["initial_outcome"] for case in CASES} <= {"miss", "rejected", "abstained"}


@pytest.mark.parametrize("case", CASES, ids=_ident)
def test_verdict_final_de_chaque_champ_du_run(case):
    assert _settle(case) == case["expected_final"]


# --- Garde-fous explicites -------------------------------------------------
# Ces deux cas étaient récupérés à tort par une réparation naïve « toute phrase
# dont le classifieur déterministe rend la valeur proposée ». Ils sont testés
# nommément parce qu'ils disent *pourquoi* la sélection de phrase est stricte.

def _case(organisation: str, field: str, value: str) -> dict:
    """Le champ de cette organisation portant cette valeur proposée.

    Deux articles distincts peuvent viser la même victime — GreenGo en a un où
    le modèle s'abstient et un où il propose « Phishing / fraude » ; c'est la
    valeur qui désigne le cas, pas l'organisation seule.
    """
    found = [c for c in CASES
             if c["organisation"].startswith(organisation) and c["field"] == field and c["proposed_value"] == value]
    assert len(found) == 1, f"{organisation}/{field}/{value} : {len(found)} cas dans le corpus"
    return found[0]


def test_un_risque_futur_de_phishing_ne_devient_pas_une_menace_constatee():
    """GreenGo : « Le principal risque identifié concerne désormais le phishing
    ciblé. » énonce un risque, pas un incident subi."""
    case = _case("GreenGo", "threat_candidate", "Phishing / fraude")
    assert repair_evidence("threat_candidate", "Phishing / fraude", case["context"], case["organisation"]) == ""


def test_une_exfiltration_non_confirmee_ne_devient_pas_une_fuite_prouvee():
    """Salt : l'article dit explicitement que l'exfiltration n'est pas établie."""
    case = _case("Salt", "threat_candidate", "Fuite de données")
    assert _settle(case) == "rejected"


def test_le_couple_activite_secteur_n_est_jamais_reparable():
    """Une taxonomie refusée ou une identité ambiguë ne se répare pas par une
    citation : ce sont des décisions sémantiques, pas des défauts de preuve."""
    couple = [c for c in CASES if c["field"] in {"activity_sector_match", "activity_description"}]
    assert couple, "le run comporte des refus du couple activité/secteur"
    for case in couple:
        assert not evidence_repair_eligibility(case["field"], case["original_rejection"], case["rejection_kind"])
        assert case["expected_final"] == "rejected"


def test_une_faible_confiance_n_est_jamais_reparable():
    """Ne pas surclasser le modèle quand il doute lui-même (Joigny, 0,32)."""
    low = [c for c in CASES if c["original_rejection"] == "CONFIDENCE_REJECTED"]
    assert low
    for case in low:
        assert not evidence_repair_eligibility(case["field"], case["original_rejection"], case["rejection_kind"])


def test_une_abstention_reste_une_abstention():
    absent = [c for c in CASES if c["original_rejection"] == "EMPTY_MODEL_VALUE"]
    assert absent
    for case in absent:
        assert not evidence_repair_eligibility(case["field"], case["original_rejection"], case["rejection_kind"])


# --- Contrat de la citation ------------------------------------------------

@pytest.mark.parametrize("case", [c for c in CASES if c["expected_final"] == "accepted"], ids=_ident)
def test_une_preuve_reparee_est_une_sous_chaine_exacte_et_bornee(case):
    evidence = repair_evidence(case["field"], case["proposed_value"], case["context"], case["organisation"])
    assert evidence and evidence in " ".join(case["context"].split())
    assert len(evidence) <= 300
    assert "..." not in evidence and "…" not in evidence


@pytest.mark.parametrize("case", [c for c in CASES if c["expected_final"] == "accepted"], ids=_ident)
def test_la_reparation_ne_change_jamais_la_valeur_proposee(case):
    raw = {case["field"]: {**case["proposal"], "evidence": repair_evidence(
        case["field"], case["proposed_value"], case["context"], case["organisation"])}}
    accepted = _normalize(raw, case["context"], {case["field"]}, case["organisation"])
    assert accepted[case["field"]]["value"] == case["proposed_value"]


def test_les_extraits_candidats_ne_enjambent_jamais_un_retour_ligne():
    context = "Titre de section sans ponctuation finale\nUne fuite de données a été confirmée par la société."
    sentences = [sentence for sentence, _ in candidate_sentences(context)]
    assert "Une fuite de données a été confirmée par la société." in sentences
    assert not any("\n" in sentence for sentence in sentences)
    assert not any(sentence.startswith("Titre de section sans ponctuation finale Une") for sentence in sentences)


# --- Branchement sur le vrai chemin d'appel --------------------------------

def _payload(output: dict):
    return {"output_text": json.dumps(output, ensure_ascii=False),
            "usage": {"input_tokens": 10, "output_tokens": 5}}


def _output_for(body: dict, **values):
    listes = {"data_types", "affected_counts", "data_volumes", "file_counts",
              "attack_flow", "incident_summary"}
    return {field: values.get(field, [] if field in listes
                              else {"value": "", "confidence": 0.0, "evidence": ""})
            for field in body["text"]["format"]["schema"]["properties"]}


ARTICLE = (
    "Exemple SA : un pirate revendique la fuite de données de 10 000 clients\n"
    "Un utilisateur d'un forum cybercriminel propose un fichier attribué à Exemple SA.\n"
    "Exemple SA a confirmé une violation de données personnelles le 2 septembre 2026.\n"
)


def test_le_pipeline_repare_la_preuve_d_une_menace_et_conserve_la_valeur(monkeypatch, tmp_path):
    """Bout en bout : le modèle propose la bonne menace avec une citation qui ne
    la prouve pas ; la réparation retrouve la phrase du document et le fait est
    publié sans que la valeur ait bougé."""
    from cyberwatch import source_facts_ai as sfa
    from cyberwatch.collectors.base import RawEntry
    from cyberwatch.model import Item

    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    sfa.reset_runtime_for_tests()

    entry = RawEntry(title="Exemple SA : un pirate revendique la fuite de données", content=ARTICLE)
    item = Item(Item_ID="ITM-repair", Source_ID="CYBERATTAQUE_ORG",
                Organisation_Raw="Exemple SA", Published_Date="2026-09-02")
    # Citation exacte de l'article, mais qui n'énonce pas la fuite : c'est le
    # refus `FIELD_VALIDATION_REJECTED` observé sur Aqualter et Snexi.
    mauvaise = "Un utilisateur d'un forum cybercriminel propose un fichier attribué à Exemple SA."

    def fake_post(body, _runtime=None):
        return _payload(_output_for(body, threat_candidate={
            "value": "Fuite de données", "confidence": 0.95, "evidence": mauvaise}))

    monkeypatch.setattr(sfa, "_post_openai", fake_post)
    result = sfa.enrich(item, entry)

    assert result["threat_candidate"]["value"] == "Fuite de données"
    evidence = result["threat_candidate"]["evidence"]
    assert evidence != mauvaise
    assert evidence in " ".join(ARTICLE.split())
    assert len(evidence) <= 300


# --- Retry LLM strictement extractif ---------------------------------------

def _configure(monkeypatch, tmp_path):
    from cyberwatch import source_facts_ai as sfa

    monkeypatch.setenv("OPENAI_API_KEY", "test")
    monkeypatch.setenv("SOURCE_FACTS_AI_CACHE_PATH", str(tmp_path / "cache.json"))
    monkeypatch.setenv("SOURCE_FACTS_AI_STATS_PATH", str(tmp_path / "stats.json"))
    monkeypatch.setenv("SOURCE_FACTS_RETRY_QUEUE_PATH", str(tmp_path / "retry.json"))
    sfa.reset_runtime_for_tests()
    return sfa


def _entry_item():
    from cyberwatch.collectors.base import RawEntry
    from cyberwatch.model import Item

    return (RawEntry(title="Exemple SA : un pirate revendique la fuite de données", content=ARTICLE),
            Item(Item_ID="ITM-repair", Source_ID="CYBERATTAQUE_ORG",
                 Organisation_Raw="Exemple SA", Published_Date="2026-09-02"))


MAUVAISE = "Un utilisateur d'un forum cybercriminel propose un fichier attribué à Exemple SA."


def test_la_tache_de_reparation_reste_sur_le_modele_par_defaut():
    """`source_facts` est un marqueur de tâche riche : un nom qui le contient
    enverrait ce travail purement extractif sur le modèle cher."""
    from cyberwatch import llm_runtime
    from cyberwatch.evidence_repair_llm import TASK

    assert TASK == "evidence_repair"
    assert llm_runtime.model_for_task(TASK) == llm_runtime.DEFAULT_MODEL
    assert llm_runtime.model_for_task(TASK) != llm_runtime.model_for_task("source_facts")
    assert TASK in llm_runtime.DEFAULT_TASK_BUDGETS


def test_aucun_appel_de_reparation_quand_le_deterministe_suffit(monkeypatch, tmp_path):
    sfa = _configure(monkeypatch, tmp_path)
    entry, item = _entry_item()
    appels = []
    monkeypatch.setattr(sfa, "_post_openai", lambda body, *_: _payload(_output_for(
        body, threat_candidate={"value": "Fuite de données", "confidence": 0.95, "evidence": MAUVAISE})))
    monkeypatch.setattr("cyberwatch.evidence_repair_llm.request_evidence",
                        lambda *a, **k: appels.append(a) or ({}, 0.0))
    result = sfa.enrich(item, entry)
    assert result["threat_candidate"]["value"] == "Fuite de données"
    assert appels == [], "la citation existait dans l'article : aucun appel ne devait partir"


def test_le_retry_ne_peut_pas_imposer_une_citation_introuvable(monkeypatch, tmp_path):
    """Le modèle rend une citation absente de l'article : le validateur la
    refuse, et le champ reste rejeté. Jamais d'acceptation directe du retry."""
    sfa = _configure(monkeypatch, tmp_path)
    entry, item = _entry_item()
    article = "Exemple SA a subi un incident informatique le 2 septembre 2026.\n"
    from cyberwatch.collectors.base import RawEntry
    entry = RawEntry(title="Exemple SA : incident", content=article)
    monkeypatch.setattr(sfa, "_post_openai", lambda body, *_: _payload(_output_for(
        body, threat_candidate={"value": "Fuite de données", "confidence": 0.95,
                                "evidence": "Exemple SA a subi un incident informatique le 2 septembre 2026."})))
    monkeypatch.setattr("cyberwatch.evidence_repair_llm.request_evidence",
                        lambda *a, **k: ({"threat_candidate": "Une fuite massive a été confirmée par Exemple SA."}, 0.0))
    result = sfa.enrich(item, entry) or {}
    assert "threat_candidate" not in result


def test_le_retry_groupe_les_champs_en_un_seul_appel_par_item(monkeypatch, tmp_path):
    sfa = _configure(monkeypatch, tmp_path)
    from cyberwatch.collectors.base import RawEntry
    entry, item = _entry_item()
    entry = RawEntry(title="Exemple SA : incident",
                     content="Exemple SA a subi un incident informatique le 2 septembre 2026.\n")
    appels = []
    monkeypatch.setattr(sfa, "_post_openai", lambda body, *_: _payload(_output_for(
        body,
        threat_candidate={"value": "Fuite de données", "confidence": 0.95,
                          "evidence": "Exemple SA a subi un incident informatique le 2 septembre 2026."},
        summary={"value": "Exemple SA touchée.", "confidence": 0.9, "evidence": "citation absente de l'article"})))
    monkeypatch.setattr("cyberwatch.evidence_repair_llm.request_evidence",
                        lambda *a, **k: appels.append(a[1]) or ({}, 0.0))
    sfa.enrich(item, entry)
    assert len(appels) == 1
    assert set(appels[0]) <= {"threat_candidate", "summary", "incident_summary"}


def test_les_metriques_separent_reparations_et_refus_sains(monkeypatch, tmp_path):
    sfa = _configure(monkeypatch, tmp_path)
    entry, item = _entry_item()
    monkeypatch.setattr(sfa, "_post_openai", lambda body, *_: _payload(_output_for(
        body, threat_candidate={"value": "Fuite de données", "confidence": 0.95, "evidence": MAUVAISE})))
    sfa.enrich(item, entry)
    stats = sfa._runtime().stats()
    for key in ("initial_accepted", "final_accepted", "healthy_abstentions",
                "unsafe_proposals_rejected", "evidence_failures", "repair_eligible",
                "repair_deterministic_success", "repair_llm_calls", "repair_llm_success",
                "repair_failed", "repair_cost_usd",
                "initial_acceptance_rate", "final_acceptance_rate"):
        assert key in stats, key
    assert stats["repair_deterministic_success"] == 1
    assert stats["repair_llm_calls"] == 0
    # La réparation ne gonfle pas l'acceptation de première intention.
    assert stats["final_accepted"] > stats["initial_accepted"]
    assert stats["final_acceptance_rate"] > stats["initial_acceptance_rate"]
