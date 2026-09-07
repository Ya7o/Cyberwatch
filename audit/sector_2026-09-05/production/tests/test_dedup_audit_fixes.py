"""Régressions issues des audits dedup du 17 août 2026."""

from cyberwatch.collectors.base import RawEntry
from cyberwatch.collectors.cyberattaque_org import (
    organisation_from_cyberattaque_entry,
    organisation_from_title,
)
from cyberwatch.dedup import MERGE, build_incidents, decide_merge
from cyberwatch.normalize import organisation_key


AUDITED_ALIAS_PAIRS = (
    ("AIRCOS", "Aircos Pascual"),
    ("Synergy", "Synergy France"),
    ("Atol", "Atol Mon Opticien"),
    ("Quiberon", "Le Maire de QUIBERON"),
    ("Roubaix", "Ville de Roubaix"),
    ("Kiosque famille de la ville de Roubaix", "Ville de Roubaix"),
    (
        "Ministère des Sports",
        "Ministère des Sports, de la Jeunesse et de la Vie associative",
    ),
    ("Lenormant", "Groupe Lenormant"),
    ("INSERM", "Institut national de la santé et de la recherche médicale"),
    ("ANFR", "Agence Nationale des Fréquences"),
    ("SIA", "Système d’Information sur les Armes"),
    (
        "CCI Nice Côte d’Azur",
        "Chambre de Commerce et d'Industrie Nice Côte d'Azur",
    ),
    ("Métropole de Bordeaux", "Bordeaux Métropole"),
    ("ville-rinxent", "Mairie de Rinxent"),
)


def test_jone_precision_editorial_tail_is_not_part_of_victim_name():
    title = "Jone Précision menacé par un ransomware : 18 Go et plus de 12 500 fichiers revendiqués"
    assert organisation_from_title(title) == "Jone Précision"


def test_amis_de_la_police_editorial_title_uses_explicit_body_victim():
    raw = RawEntry(
        title="Amis de la Police : des adhérents exposés dans une fuite de données",
        content=(
            "L’Amicale Police et Patrimoine fait l’objet d’une revendication "
            "concernant les données de ses adhérents."
        ),
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "Amicale Police et Patrimoine"


def test_editorial_override_requires_body_evidence():
    raw = RawEntry(
        title="Amis de la Police : des adhérents exposés dans une fuite de données",
        content="Le titre ne permet pas d’identifier plus précisément la victime.",
    )
    assert organisation_from_cyberattaque_entry(raw, {}) == "Amis de la Police"


def test_audited_aliases_resolve_to_one_identity():
    for left, right in AUDITED_ALIAS_PAIRS:
        assert organisation_key(left) == organisation_key(right), (left, right)


def test_audited_aliases_merge_cross_source_items(make_item):
    for index, (left_org, right_org) in enumerate(AUDITED_ALIAS_PAIRS):
        left = make_item(
            source="SOURCE_A",
            org=left_org,
            published="2026-08-16",
            url=f"https://a/{index}",
        )
        right = make_item(
            source="SOURCE_B",
            org=right_org,
            published="2026-08-16",
            url=f"https://b/{index}",
        )
        assert decide_merge(left, right).action == MERGE, (left_org, right_org)
        incidents = build_incidents([left, right])
        assert len(incidents) == 1, (left_org, right_org)
        assert incidents[0].Items_Count == 2
