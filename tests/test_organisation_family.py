from __future__ import annotations

import pytest

from cyberwatch import config, organisation_family


@pytest.mark.parametrize(("name", "family", "sector"), [
    ("SDIS de la Moselle", "FR_SDIS", config.SECTOR_ADMIN),
    ("SDIS 57", "FR_SDIS", config.SECTOR_ADMIN),
    ("Service départemental d’incendie et de secours de la Moselle", "FR_SDIS", config.SECTOR_ADMIN),
    ("ARS Bretagne", "FR_ARS", config.SECTOR_HEALTH),
    ("Agence régionale de santé de La Réunion", "FR_ARS", config.SECTOR_HEALTH),
    ("CHU de Lille", "FR_CHU", config.SECTOR_HEALTH),
    ("CROUS de Lyon", "FR_CROUS", config.SECTOR_EDUCATION),
    ("Préfecture de la Moselle", "FR_PREFECTURE", config.SECTOR_ADMIN),
    ("La Ville de Tarnos", "FR_LOCAL_AUTHORITY", config.SECTOR_ADMIN),
    ("Communauté d'agglomération du Grand Annecy", "FR_INTERCOMMUNALITY", config.SECTOR_ADMIN),
    ("CGT Éduc’Action Créteil", "FR_TRADE_UNION", config.SECTOR_ASSOCIATION),
    ("CFDT Santé Sociaux", "FR_TRADE_UNION", config.SECTOR_ASSOCIATION),
    ("Force ouvrière", "FR_TRADE_UNION", config.SECTOR_ASSOCIATION),
    ("Syndicat professionnel des métiers du numérique", "FR_PROFESSIONAL_UNION", config.SECTOR_ASSOCIATION),
    ("France Travail", "FR_FRANCE_TRAVAIL", config.SECTOR_ADMIN),
    ("ANSSI", "FR_ANSSI", config.SECTOR_ADMIN),
])
def test_reference_family_matches(name, family, sector):
    match = organisation_family.match_organisation_family(name)
    assert match is not None
    assert match.family_id == family
    assert match.sector == sector
    assert match.confidence == "HIGH"


@pytest.mark.parametrize("name", [
    "SDIS Consulting",
    "ARS Technologies",
    "CGT Solutions",
    "CAF Digital",
    "CMA Consulting",
    "Sud Ouest",
])
def test_reference_family_rejects_commercial_or_ambiguous_lookalikes(name):
    assert organisation_family.match_organisation_family(name) is None


def test_reference_is_well_formed():
    assert organisation_family.validate_reference() == []
    assert config.SECTOR_ASSOCIATION in config.SECTORS
