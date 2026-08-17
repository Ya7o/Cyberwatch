"""Régressions issues de l'auditdedup du 17 août 2026."""

from cyberwatch.collectors.cyberattaque_org import organisation_from_title
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
)


def test_jone_precision_editorial_tail_is_not_part_of_victim_name():
    title = "Jone Précision menacé par un ransomware : 18 Go et plus de 12 500 fichiers revendiqués"
    assert organisation_from_title(title) == "Jone Précision"


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
