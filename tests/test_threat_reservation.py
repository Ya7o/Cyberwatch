"""Réserves de menace portées par la phrase — régressions Le Tampon (2026-09-09).

Les textes viennent de `tests/fixtures/tampon_20260910/`, figés par l'audit du
10 septembre 2026 : ils ne sont jamais rechargés depuis les sites.
"""

import json
from pathlib import Path

import pytest

from cyberwatch import config, enrichment, threat_reservation
from cyberwatch.normalize import classify_threat

FIXTURES = Path(__file__).parent / "fixtures" / "tampon_20260910"
FRENCHBREACHES = FIXTURES / "ITM-0c085da888611a12-context.txt"
CYBERATTAQUE_ORG = FIXTURES / "ITM-f2c9b54af4eae1da-context.txt"


def _context(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# --- Portée de la réserve ---------------------------------------------------

def test_premature_de_parler_ne_qualifie_aucune_menace():
    assert classify_threat(
        "Il serait donc prématuré de parler de ransomware ou de fuite de données."
    ) == config.THREAT_UNKNOWN


def test_une_reserve_nefface_pas_une_affirmation_positive_independante():
    """Le garde-fou central : la réserve est portée par sa phrase, pas par l'article."""
    texte = (
        "Il est trop tôt pour parler de ransomware. "
        "L'attaquant a chiffré les serveurs et réclame une rançon."
    )
    assert threat_reservation.net_reserved(texte) == set()
    assert classify_threat(texte) == config.THREAT_RANSOMWARE


@pytest.mark.parametrize("phrase, code", [
    ("Il serait prématuré de parler de ransomware.", "PREMATURE_TO_NAME"),
    ("Il n'est donc pas possible, à ce stade, de déterminer s'il s'agit d'un rançongiciel.",
     "IMPOSSIBLE_TO_DETERMINE"),
    ("La nature exacte de l'attaque et son ampleur restent donc inconnues.", "NATURE_UNKNOWN"),
    ("Dans le cas du Tampon, aucun point d'entrée n'a encore été rendu public.",
     "NO_ENTRY_POINT_PUBLISHED"),
    ("La municipalité n'a pour le moment fait état d'aucune fuite de données.",
     "NOT_COMMUNICATED"),
])
def test_les_formulations_d_incertitude_de_l_audit_sont_reconnues(phrase, code):
    """Le marqueur est reconnu ; il ne réserve que les menaces citées dans SA phrase."""
    assert threat_reservation._marker_for(phrase) == code


def test_une_reserve_en_tete_de_liste_couvre_ses_puces():
    """« n'a pas précisé : … ; … ; … . » — chaque puce hérite de la réserve.

    Sans cette portée, « l'existence ou non d'une exfiltration de données ; »
    redevenait une affirmation de fuite autonome.
    """
    texte = (
        "La Ville du Tampon n'a notamment pas précisé : "
        "le type de cyberattaque dont elle est victime ; "
        "l'existence ou non d'une exfiltration de données ; "
        "si des données ont été consultées, chiffrées ou exfiltrées."
    )
    assert config.THREAT_LEAK in threat_reservation.reserved(texte)


# --- Les deux articles du Tampon --------------------------------------------

def test_cyberattaque_org_du_tampon_decide_inconnu():
    decision = threat_reservation.decision(_context(CYBERATTAQUE_ORG))
    assert decision is not None
    assert decision["value"] == config.THREAT_UNKNOWN
    assert set(decision["reserved"]) >= {config.THREAT_RANSOMWARE, config.THREAT_LEAK}
    assert decision["evidence"]


def test_cyberattaque_confirmee_reste_un_incident_sans_vecteur():
    """Une cyberattaque confirmée n'est pas effacée par la réserve technique.

    L'article du Tampon affirme la cyberattaque et écarte sa nature : le
    marqueur générique subsiste, la menace spécifique non.
    """
    contexte = _context(CYBERATTAQUE_ORG)
    reservees = threat_reservation.reserved(contexte)
    assert config.THREAT_RANSOMWARE in reservees
    assert "cyberattaque" in contexte.lower()


# --- Le défaut de flux ne réécrase pas une réserve --------------------------

def test_le_defaut_frenchbreaches_ne_bat_pas_une_reserve_explicite():
    phrase = "Aucune fuite de données confirmée à ce stade."
    assert classify_threat(phrase, default=config.THREAT_LEAK) != config.THREAT_LEAK


def test_le_contrat_natif_ransomware_live_reste_prioritaire():
    """Une revendication de leak site garde sa provenance malgré la prudence du texte."""
    assert classify_threat(
        "Il serait prématuré de parler de ransomware.",
        default=config.THREAT_RANSOMWARE,
    ) == config.THREAT_RANSOMWARE


def test_la_stabilisation_conserve_un_inconnu_sourcé(make_item):
    """`stabilize_threats` ne rétablit pas la fuite écartée par la source."""
    item = make_item(
        source="FRENCHBREACHES",
        org="Ville du Tampon",
        title="Le Tampon : une cyberattaque perturbe fortement les services de la mairie",
        threat=config.THREAT_UNKNOWN,
    )
    decision = threat_reservation.decision(_context(CYBERATTAQUE_ORG))
    enrichment.stabilize_threats([item], {item.Item_ID: decision})
    assert item.Threat == config.THREAT_UNKNOWN

    autre = make_item(
        source="FRENCHBREACHES",
        org="Ville du Tampon",
        title="Le Tampon : une cyberattaque perturbe fortement les services de la mairie",
        threat=config.THREAT_UNKNOWN,
    )
    enrichment.stabilize_threats([autre], None)
    assert autre.Threat == config.THREAT_LEAK


def test_le_backfill_par_titre_respecte_la_reserve(make_item):
    """Le raccourci `_UNKNOWN_LEAK_MARKERS` n'a aucune gestion de négation."""
    item = make_item(
        source="CYBERATTAQUE_ORG",
        org="Le Tampon",
        title="Aucune fuite de données confirmée à ce stade",
        threat=config.THREAT_UNKNOWN,
    )
    assert enrichment._backfill_unknown_threat(item) == config.THREAT_LEAK
    assert enrichment._backfill_unknown_threat(
        item, {"reserved": [config.THREAT_LEAK]}
    ) == config.THREAT_UNKNOWN


# --- Transport par les métadonnées SourceFacts ------------------------------

def test_la_decision_circule_par_les_metadonnees_existantes():
    decision = threat_reservation.decision(_context(CYBERATTAQUE_ORG))
    rows = [{
        "Item_ID": "ITM-f2c9b54af4eae1da",
        "Source_Metadata_JSON": json.dumps({"threat_reservation": decision}),
    }]
    index = threat_reservation.index_source_facts(rows)
    assert threat_reservation.covers(index["ITM-f2c9b54af4eae1da"], config.THREAT_RANSOMWARE)
    assert not threat_reservation.covers(index["ITM-f2c9b54af4eae1da"], config.THREAT_DDOS)


def test_un_index_tolere_des_metadonnees_illisibles():
    assert threat_reservation.index_source_facts([
        {"Item_ID": "ITM-1", "Source_Metadata_JSON": "{pas du json"},
        {"Item_ID": "", "Source_Metadata_JSON": "{}"},
        {"Item_ID": "ITM-2", "Source_Metadata_JSON": ""},
    ]) == {}
