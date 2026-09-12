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
