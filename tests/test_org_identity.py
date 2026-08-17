"""Identité organisationnelle déterministe utilisée par la déduplication."""

import pytest

from cyberwatch.dedup import MERGE, NO_DECISION, build_incidents, decide_merge
from cyberwatch.normalize import organisation_key
from cyberwatch.org_identity import effective_organisation_key


@pytest.mark.parametrize(
    "raw",
    [
        "Département de la Gironde",
        "Conseil départemental de la Gironde",
        "Département 33",
        "Conseil départemental 33",
        "CD33",
        "CD 33",
    ],
)
def test_department_name_and_code_resolve_to_same_identity(raw):
    assert effective_organisation_key(raw) == "departement 33"


@pytest.mark.parametrize(
    "raw",
    [
        "Département de La Réunion",
        "Conseil départemental de La Réunion",
        "Département 974",
        "Conseil départemental 974",
        "CD974",
    ],
)
def test_overseas_department_code_is_supported(raw):
    assert effective_organisation_key(raw) == "departement 974"


@pytest.mark.parametrize(
    "raw",
    [
        "Région Île-de-France",
        "Conseil régional d'Île-de-France",
        "Région 11",
        "Conseil régional 11",
        "CR11",
    ],
)
def test_region_name_and_code_resolve_to_same_identity(raw):
    assert effective_organisation_key(raw) == "region 11"


def test_entity_type_is_part_of_identity():
    assert effective_organisation_key("Département 75") == "departement 75"
    assert effective_organisation_key("Région 75") == "region 75"
    assert effective_organisation_key("Département 75") != effective_organisation_key("Région 75")


def test_code_alone_never_identifies_an_organisation():
    assert effective_organisation_key("974") == organisation_key("974")
    assert effective_organisation_key("974") != "departement 974"


def test_unknown_organisation_is_accepted_without_reference_entry():
    raw = "Nouvelle Société Inconnue 2027"
    assert effective_organisation_key(raw) == organisation_key(raw)


def test_ambiguous_business_name_is_not_misread_as_region_code():
    raw = "Region 11 Consulting"
    assert effective_organisation_key(raw) == organisation_key(raw)


def test_bare_commune_keeps_historical_identity_policy():
    raw = "Saint-Denis"
    assert effective_organisation_key(raw) == organisation_key(raw)


def test_historical_distinct_keys_merge_at_dedup_time_without_rewriting_items(make_item):
    left = make_item(
        source="SOURCE_A",
        org="Département de la Gironde",
        published="2026-03-01",
        url="https://a.example/incident",
    )
    right = make_item(
        source="SOURCE_B",
        org="Conseil départemental 33",
        published="2026-03-02",
        url="https://b.example/incident",
    )

    # Les clés stockées restent distinctes : la migration ne réécrit donc ni
    # ITEMS ni leurs Item_ID historiques.
    assert left.Organisation_Key != right.Organisation_Key
    assert decide_merge(left, right).action == MERGE

    incidents = build_incidents([left, right])
    assert len(incidents) == 1
    assert incidents[0].Items_Count == 2


def test_different_departments_are_not_merged(make_item):
    left = make_item(
        source="SOURCE_A",
        org="Département de la Gironde",
        published="2026-03-01",
        url="https://a.example/incident",
    )
    right = make_item(
        source="SOURCE_B",
        org="Département des Landes",
        published="2026-03-01",
        url="https://b.example/incident",
    )

    assert decide_merge(left, right).action == NO_DECISION
    assert len(build_incidents([left, right])) == 2
