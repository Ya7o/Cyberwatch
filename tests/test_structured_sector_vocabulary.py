"""Contrat « catégorie structurée d'une source -> taxonomie canonique ».

Deux exigences distinctes. D'abord, toute valeur brute connue reçoit une
décision **explicite** : l'objectif n'est pas que 100 % des libellés produisent
un secteur, mais que 100 % d'entre eux soient tranchés. Ensuite, la
normalisation reste lexicale : elle absorbe la casse et les accents, jamais le
sens. Les cas volontairement ambigus interdisent qu'un `contains` ou une
similarité approximative s'installe plus tard.
"""
import csv
import json
from pathlib import Path

import pytest

from cyberwatch import config
from cyberwatch.normalize import searchable
from cyberwatch.sector import (
    STRUCTURED_SECTOR_INDEX,
    STRUCTURED_SECTOR_STATUSES,
    _derive_taxonomy_aliases,
    classify_source_sector,
    structured_sector_status,
)

VOCABULARY = json.loads(
    (Path(__file__).parent / "fixtures" / "source_sector_vocabulary.json").read_text(encoding="utf-8")
)["vocabulary"]
CORPUS = Path(__file__).resolve().parents[1] / "data" / "source_facts.csv"


def _corpus_values() -> set[str]:
    with CORPUS.open(newline="", encoding="utf-8") as handle:
        return {(row.get("Source_Sector_Raw") or "").strip()
                for row in csv.DictReader(handle)} - {""}


# --------------------------------------------------------------------------
# Couverture du vocabulaire réellement publié par les sources
# --------------------------------------------------------------------------

@pytest.mark.parametrize("entry", VOCABULARY, ids=lambda e: e["raw"])
def test_chaque_libelle_connu_recoit_une_decision_explicite(entry):
    assert structured_sector_status(entry["raw"]) == entry["status"]
    expected = entry.get("sector") or config.SECTOR_UNKNOWN
    assert classify_source_sector(entry["raw"]) == expected


def test_aucun_libelle_connu_ne_tombe_entre_les_mailles():
    unmapped = [e["raw"] for e in VOCABULARY if structured_sector_status(e["raw"]) == "UNMAPPED"]
    assert unmapped == []


def test_le_corpus_courant_n_introduit_aucun_libelle_inconnu():
    """Garde-fou de dérive : une rubrique inédite doit être tranchée, pas subie."""
    if not CORPUS.exists():
        pytest.skip("corpus absent (base purgée)")
    known = {e["raw"] for e in VOCABULARY}
    assert sorted(_corpus_values() - known) == []


# --------------------------------------------------------------------------
# Invariants de construction de l'index
# --------------------------------------------------------------------------

def test_aucun_segment_canonique_n_est_partage_par_deux_secteurs():
    derived = _derive_taxonomy_aliases()  # lève si un segment est ambigu
    assert derived[searchable("Technologie")] == config.SECTOR_TECH
    assert derived[searchable("Industrie")] == config.SECTOR_INDUSTRY
    assert len(derived) >= len(config.SECTORS) - 1


def test_le_vocabulaire_anglophone_concorde_avec_la_taxonomie():
    """Les tables écrites à la main ne doivent jamais contredire la dérivation."""
    derived = _derive_taxonomy_aliases()
    for layer in (config.ACTIVITY_TO_SECTOR, config.STRUCTURED_SECTOR_ALIASES):
        for key, sector in layer.items():
            assert derived.get(key, sector) == sector


def test_l_index_ne_produit_que_des_secteurs_canoniques():
    for key, sector in STRUCTURED_SECTOR_INDEX.items():
        assert sector in config.SECTORS and sector != config.SECTOR_UNKNOWN
        assert searchable(key) == key, f"clé non normalisée : {key!r}"


def test_les_libelles_ambigus_sont_retires_de_l_index():
    for key in config.STRUCTURED_SECTOR_AMBIGUOUS:
        assert key not in STRUCTURED_SECTOR_INDEX
        assert classify_source_sector(key) == config.SECTOR_UNKNOWN
        assert structured_sector_status(key) == "EXPLICITLY_UNRESOLVED"


# --------------------------------------------------------------------------
# Normalisation lexicale : la forme varie, le sens non
# --------------------------------------------------------------------------

@pytest.mark.parametrize("given", [
    "Technologie", "technologie", "TECHNOLOGIE", " Technologie ", "  technologie  ",
    "Technologie.", "Téchnologie", "Numérique / Technologie", "numerique technologie",
    "Numerique  /  Technologie", "Numérique/Technologie", "NUMÉRIQUE / TECHNOLOGIE",
])
def test_les_variantes_de_forme_donnent_le_meme_secteur(given):
    assert classify_source_sector(given) == config.SECTOR_TECH


@pytest.mark.parametrize("given,expected", [
    ("technology", config.SECTOR_TECH),
    ("Industrie", config.SECTOR_INDUSTRY),
    ("MANUFACTURING", config.SECTOR_INDUSTRY),
    ("santé", config.SECTOR_HEALTH),
    ("SANTÉ", config.SECTOR_HEALTH),
    ("sante", config.SECTOR_HEALTH),
    ("Transport", config.SECTOR_TRANSPORT),
    ("Éducation", config.SECTOR_EDUCATION),
    ("education", config.SECTOR_EDUCATION),
    ("retail e commerce", config.SECTOR_RETAIL),
    ("Retail & E-Commerce", config.SECTOR_RETAIL),
    ("public", config.SECTOR_ADMIN),
    ("Secteur public", config.SECTOR_ADMIN),
    ("Government & Defense", config.SECTOR_ADMIN),
    ("Énergie", config.SECTOR_ENERGY),
    ("BTP", config.SECTOR_CONSTRUCTION),
    ("Services aux entreprises", config.SECTOR_SERVICES),
])
def test_les_libelles_structures_surs_sont_normalises(given, expected):
    assert classify_source_sector(given) == expected


@pytest.mark.parametrize("sector", [s for s in config.SECTORS if s != config.SECTOR_UNKNOWN])
def test_un_secteur_canonique_se_traverse_lui_meme(sector):
    assert classify_source_sector(sector) == sector
    assert classify_source_sector(sector.lower()) == sector
    assert structured_sector_status(sector) == "CANONICAL"


# --------------------------------------------------------------------------
# Anti-permissivité : ce qui doit rester Inconnu
# --------------------------------------------------------------------------

@pytest.mark.parametrize("given", [
    "", "   ", "foo", "e", "sector", "secteur",
    # Une sous-chaîne n'est pas un alias : aucun matching approximatif.
    "tech", "techno", "technologies de sante", "technologie médicale",
    "industrie du spectacle", "banque de sang", "transport de patients",
    "commerce equitable des oeuvres", "education physique et sportive",
    "energie du desespoir", "administration systeme", "public relations",
    # Catégories trop larges, volontairement non résolues.
    "services", "divers", "autre", "other", "unknown", "entreprise",
    "secteur privé", "PME", "multi sector", "holding", "distribution",
])
def test_les_libelles_ambigus_ou_inconnus_restent_inconnu(given):
    assert classify_source_sector(given) == config.SECTOR_UNKNOWN


@pytest.mark.parametrize("given", [
    "", "Technologie", "Santé", "services", "Cryogénie quantique", "Retail & E-Commerce",
])
def test_le_statut_rendu_appartient_toujours_au_contrat(given):
    assert structured_sector_status(given) in STRUCTURED_SECTOR_STATUSES


def test_un_libelle_inedit_est_signale_et_non_devine():
    assert structured_sector_status("Cryogénie quantique") == "UNMAPPED"
    assert classify_source_sector("Cryogénie quantique") == config.SECTOR_UNKNOWN
    assert structured_sector_status("") == "ABSENT"
