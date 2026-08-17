from cyberwatch import config
from cyberwatch.duplicate_audit import (
    DUPLICATE_CANDIDATE_CONCATENATION,
    DUPLICATE_CANDIDATE_PERMUTATION,
    RISK_FALSE_MERGE,
    find_audit_candidates,
    find_duplicate_candidates,
)


def test_included_name_is_reported_when_all_strict_conditions_match(make_item):
    items = [
        make_item(source="A", org="Biosynex", published="2026-08-06", url="https://a", threat="Fuite de données"),
        make_item(source="B", org="Biosynex France", published="2026-08-08", url="https://b", threat="Fuite de données"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].days_apart == 2
    assert candidates[0].reason_code == "DUPLICATE_CANDIDATE_NAME_CONTAINMENT"


def test_unknown_threat_is_not_required_for_compatibility(make_item):
    items = [
        make_item(source="A", org="Globex", url="https://a", threat=config.THREAT_UNKNOWN),
        make_item(source="B", org="Globex France", url="https://b", threat="Fuite de données"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_different_known_threats_are_still_reported(make_item):
    items = [
        make_item(source="A", org="Biosynex", url="https://a", threat="Intrusion"),
        make_item(source="B", org="Biosynex France", url="https://b", threat="Fuite de données"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_generic_institutional_names_remain_auditable(make_item):
    items = [
        make_item(source="A", org="Service de santé", url="https://a"),
        make_item(source="B", org="Service de santé de Paris", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].short.Organisation_Raw == "Service de santé"


def test_generic_word_in_long_name_does_not_hide_candidate(make_item):
    items = [
        make_item(source="A", org="Sapeurs pompiers", url="https://a"),
        make_item(source="B", org="Fédération des sapeurs pompiers", url="https://b"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_same_source_or_date_over_fourteen_days_is_excluded(make_item):
    same_source = [
        make_item(source="A", org="Globex", url="https://a"),
        make_item(source="A", org="Globex France", url="https://b"),
    ]
    late = [
        make_item(source="A", org="Globex", published="2026-03-01", url="https://a"),
        make_item(source="B", org="Globex France", published="2026-03-16", url="https://b"),
    ]
    assert find_duplicate_candidates(same_source) == []
    assert find_duplicate_candidates(late) == []


def test_realistic_sub_entities_remain_only_candidates_not_merges(make_item):
    items = [
        make_item(source="A", org="City Pro", url="https://a"),
        make_item(source="B", org="City Pro Marionneau", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].short.Organisation_Raw == "City Pro"


def test_exact_concatenation_is_reported(make_item):
    """Même principe que « france casse » / « francecasse » (désormais
    résolu par un alias, cf. data/organisation_aliases.csv) : mêmes lettres,
    espace en moins, non couvert par l'inclusion de mots (nombre de mots
    différent, pas de sous-séquence contiguë)."""
    items = [
        make_item(source="A", org="Globex Alpha", published="2026-08-16", url="https://a"),
        make_item(source="B", org="GlobexAlpha", published="2026-08-16", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].reason_code == DUPLICATE_CANDIDATE_CONCATENATION


def test_exact_permutation_is_reported(make_item):
    """Même principe que « cravero motoculture » / « motoculture cravero »
    (désormais résolu par un alias) : mêmes mots, ordre différent, non
    couvert par l'inclusion de mots (même longueur)."""
    items = [
        make_item(source="A", org="Solutions Globex", published="2026-08-16", url="https://a"),
        make_item(source="B", org="Globex Solutions", published="2026-08-16", url="https://b"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].reason_code == DUPLICATE_CANDIDATE_PERMUTATION


def test_identical_source_url_is_not_reported_as_false_merge(make_item):
    items = [
        make_item(source="RANSOMWARE_LIVE", org="Voyages Robin", published="2026-02-07", url="https://claim/1"),
        make_item(source="RANSOMWARE_LIVE", org="Voyages Robin", published="2026-02-08", url="https://claim/1"),
    ]
    assert [c for c in find_audit_candidates(items) if c.risk_type == RISK_FALSE_MERGE] == []


def test_same_source_different_urls_remain_auditable(make_item):
    items = [
        make_item(source="BONJOURLAFUITE", org="Relais Colis", published="2026-01-12", url="https://a/1"),
        make_item(source="BONJOURLAFUITE", org="Relais Colis", published="2026-01-15", url="https://a/2"),
    ]
    candidates = [c for c in find_audit_candidates(items) if c.risk_type == RISK_FALSE_MERGE]
    assert len(candidates) == 1
