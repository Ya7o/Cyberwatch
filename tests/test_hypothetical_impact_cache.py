"""Impact hypothétique : rejet par la règle, pas par une correction éditoriale.

Régression Printemps (audit du 10/09/2026) : l'extraction en cache proposait
« des attaques ciblées possibles via des e-mails ou appels frauduleux. » avec
le statut `accepted`. Le contrat d'impact interdit pourtant explicitement le
risque futur. La valeur passait la porte de publication parce que les deux
lexiques d'hypothèse avaient divergé : celui de l'extraction connaît
« possible », celui de la publication non.
"""

import json
from pathlib import Path

import pytest

from cyberwatch import fact_resolution as fr
from cyberwatch import hypothesis_lexicon
from cyberwatch.headline import strip_markdown_emphasis

CACHE = Path("audit/latest_collection_2026-09-10/llm_cache_extractions.json")

IMPACT_PRINTEMPS = "des attaques ciblées possibles via des e-mails ou appels frauduleux."


def test_l_impact_hypothetique_du_cache_est_rejete_par_la_regle_seule():
    assert fr._impact_is_publishable(IMPACT_PRINTEMPS) is False


def test_la_valeur_exacte_du_cache_audite_est_rejetee():
    """Sur la valeur figée par l'audit, pas sur une paraphrase."""
    if not CACHE.exists():
        pytest.skip("preuves d'audit absentes de l'arbre")
    payload = json.loads(CACHE.read_text(encoding="utf-8"))
    valeurs = [
        entry["llm_value"]
        for entry in payload
        if entry.get("field") == "impact" and "possible" in str(entry.get("llm_value", ""))
    ]
    assert valeurs, "la valeur auditée doit rester présente dans les preuves"
    for valeur in valeurs:
        assert fr._impact_is_publishable(valeur) is False


@pytest.mark.parametrize("valeur", [
    "possibles appels ou courriels frauduleux",
    "une éventuelle exposition de données personnelles",
    "des conséquences probables sur les usagers",
    "risque de phishing pour les clients",
])
def test_le_palier_impact_refuse_le_risque_futur(valeur):
    assert fr._impact_is_publishable(valeur) is False


@pytest.mark.parametrize("valeur", [
    "Perturbations des services municipaux",
    "Les agents ne peuvent plus assurer leurs missions dans des conditions normales.",
    "Production arrêtée pendant trois jours",
])
def test_le_palier_impact_conserve_une_consequence_observee(valeur):
    assert fr._impact_is_publishable(valeur) is True


def test_les_paliers_restent_distincts():
    """Fusionner les lexiques détruirait des faits réels (5 incidents mesurés)."""
    assert hypothesis_lexicon.PUBLICATION_RE.search(IMPACT_PRINTEMPS) is None
    assert hypothesis_lexicon.IMPACT_RE.search(IMPACT_PRINTEMPS) is not None
    assert hypothesis_lexicon.EXTRACTION_RE.search(IMPACT_PRINTEMPS) is not None


# --- Markdown résiduel ------------------------------------------------------

@pytest.mark.parametrize("brut, attendu", [
    ("**Impact** : service indisponible", "Impact : service indisponible"),
    ("**Une fuite attribuée à Pass Pass est revendiquée", "Une fuite attribuée à Pass Pass est revendiquée"),
    ("texte __souligné__ ici", "texte souligné ici"),
    ("Perturbations des services municipaux", "Perturbations des services municipaux"),
])
def test_le_markdown_residuel_est_nettoye_y_compris_non_ferme(brut, attendu):
    assert strip_markdown_emphasis(brut) == attendu


def test_un_resume_avec_markdown_nest_plus_perdu():
    """`headline.rejection_reason` rejette tout `**` : nettoyer avant, pas jeter."""
    from cyberwatch.headline import is_publishable_headline

    brut = "**Le Tampon : une cyberattaque perturbe fortement les services de la mairie**"
    assert not is_publishable_headline(brut)
    assert is_publishable_headline(strip_markdown_emphasis(brut))
