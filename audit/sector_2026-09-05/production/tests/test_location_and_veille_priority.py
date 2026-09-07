"""Règles métier : défaut France et priorité d'enrichissement VEILLE_LLM."""

from cyberwatch import config
from cyberwatch.dedup import build_incidents


def test_veille_llm_wins_sector_and_location_on_dedup(make_item):
    direct = make_item(
        source="FRENCHBREACHES",
        published="2026-08-10",
        org="Organisation Exemple",
        url="https://direct.example/incident",
        sector=config.SECTOR_RETAIL,
        location=config.LOC_FRANCE,
    )
    veille = make_item(
        source="VEILLE_LLM",
        published="2026-08-10",
        org="Organisation Exemple",
        url="https://veille.example/incident",
        sector=config.SECTOR_ADMIN,
        location=config.LOC_REUNION,
    )

    incident = build_incidents([direct, veille])[0]

    assert incident.Secteur == config.SECTOR_ADMIN
    assert incident.Localisation == config.LOC_REUNION
    # VEILLE_LLM reste analytique : priorité d'enrichissement oui, mais pas
    # corroboration éditoriale supplémentaire quand une source directe existe.
    assert incident.Sources == "FRENCHBREACHES"
    assert incident.Source_URLs == "https://direct.example/incident"
    assert incident.Items_Count == 2


def test_veille_llm_unknown_does_not_override_known_direct_value(make_item):
    direct = make_item(
        source="BONJOURLAFUITE",
        published="2026-08-10",
        org="Organisation Exemple",
        url="https://direct.example/incident",
        sector=config.SECTOR_RETAIL,
        location=config.LOC_FRANCE,
    )
    veille = make_item(
        source="VEILLE_LLM",
        published="2026-08-10",
        org="Organisation Exemple",
        url="https://veille.example/incident",
        sector=config.SECTOR_UNKNOWN,
        location=config.LOC_INCONNU,
    )

    incident = build_incidents([direct, veille])[0]

    assert incident.Secteur == config.SECTOR_RETAIL
    assert incident.Localisation == config.LOC_FRANCE
