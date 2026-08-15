"""Règles métier : défaut France et priorité de qualification VEILLE_LLM."""

import pytest

from cyberwatch import config, sources
from cyberwatch.collectors.base import RawEntry
from cyberwatch.dedup import build_incidents
from cyberwatch.runner import entry_to_item


@pytest.mark.parametrize("source_id", ["FRENCHBREACHES", "BONJOURLAFUITE"])
def test_french_leak_sources_default_to_france(source_id):
    spec = sources.by_id(source_id)
    assert spec is not None
    assert spec.location_rule == config.LOC_FRANCE

    item = entry_to_item(
        RawEntry(
            title="Organisation Exemple",
            published="2026-08-15",
            summary="Fuite de données confirmée.",
            url=f"https://example.test/{source_id.lower()}",
        ),
        spec,
        "2026-08-15T16:30:00+04:00",
        known_orgs={},
        entity_index={},
        territories={},
        reference={},
    )

    assert item is not None
    assert item.Location == config.LOC_FRANCE


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
    # VEILLE_LLM reste analytique : priorité de qualification oui, mais pas
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
