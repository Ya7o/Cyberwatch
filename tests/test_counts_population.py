"""Un chiffre de cadrage n'est pas un décompte de victimes.

Régression Le Tampon (audit du 10/09/2026) : l'article Cyberattaque.org indique
« elle compte environ 82 600 habitants ». Ce nombre décrit la commune, pas
l'incident, et ne doit jamais devenir `Affected_Count`.
"""

from pathlib import Path

import pytest

from cyberwatch import fact_resolution_counts as frc

FIXTURES = Path(__file__).parent / "fixtures" / "tampon_20260910"
CYBERATTAQUE_ORG = FIXTURES / "ITM-f2c9b54af4eae1da-context.txt"


@pytest.mark.parametrize("preuve", [
    "Située dans le sud de l’île, elle compte environ 82 600 habitants.",
    "La commune compte 82 600 habitants et appartient à la Communauté d’agglomération du Sud.",
    "Le club revendique 1 200 licenciés.",
    "L'entreprise emploie 350 salariés du groupe.",
])
def test_un_chiffre_de_cadrage_est_reconnu_comme_tel(preuve):
    assert frc._BACKGROUND_COUNT_CONTEXT_RE.search(preuve)
    assert not frc._INCIDENT_COUNT_CONTEXT_RE.search(preuve)


@pytest.mark.parametrize("preuve", [
    "La fuite concerne 82 600 personnes.",
    "L'incident touche 4 100 patients de l'établissement.",
])
def test_un_decompte_lie_a_l_incident_reste_recevable(preuve):
    assert frc._INCIDENT_COUNT_CONTEXT_RE.search(preuve)


def test_la_population_du_tampon_ne_devient_pas_un_nombre_de_victimes():
    """Sur le texte figé, pas sur une paraphrase."""
    contexte = CYBERATTAQUE_ORG.read_text(encoding="utf-8")
    phrase = next(
        ligne for ligne in contexte.splitlines() if "82 600" in ligne
    )
    assert frc._BACKGROUND_COUNT_CONTEXT_RE.search(phrase)
    assert not frc._INCIDENT_COUNT_CONTEXT_RE.search(phrase)
