from cyberwatch import config
from cyberwatch.duplicate_audit import find_duplicate_candidates


def test_included_name_is_reported_when_all_strict_conditions_match(make_item):
    items = [
        make_item(source="A", org="Biosynex", published="2026-08-06", url="https://a", threat="Fuite de données"),
        make_item(source="B", org="Biosynex France", published="2026-08-08", url="https://b", threat="Fuite de données"),
    ]
    candidates = find_duplicate_candidates(items)
    assert len(candidates) == 1
    assert candidates[0].days_apart == 2


def test_unknown_threat_is_compatible(make_item):
    items = [
        make_item(source="A", org="Atol", url="https://a", threat=config.THREAT_UNKNOWN),
        make_item(source="B", org="Atol Mon Opticien", url="https://b", threat="Fuite de données"),
    ]
    assert len(find_duplicate_candidates(items)) == 1


def test_different_known_threats_are_not_reported(make_item):
    items = [
        make_item(source="A", org="Biosynex", url="https://a", threat="Intrusion"),
        make_item(source="B", org="Biosynex France", url="https://b", threat="Fuite de données"),
    ]
    assert find_duplicate_candidates(items) == []


def test_generic_short_name_is_excluded(make_item):
    items = [
        make_item(source="A", org="Service de santé", url="https://a"),
        make_item(source="B", org="Service de santé de Paris", url="https://b"),
    ]
    assert find_duplicate_candidates(items) == []


def test_generic_word_in_the_long_name_is_also_excluded(make_item):
    items = [
        make_item(source="A", org="Sapeurs pompiers", url="https://a"),
        make_item(source="B", org="Fédération des sapeurs pompiers", url="https://b"),
    ]
    assert find_duplicate_candidates(items) == []


def test_same_source_or_date_over_three_days_is_excluded(make_item):
    same_source = [
        make_item(source="A", org="Atol", url="https://a"),
        make_item(source="A", org="Atol Mon Opticien", url="https://b"),
    ]
    late = [
        make_item(source="A", org="Atol", published="2026-03-01", url="https://a"),
        make_item(source="B", org="Atol Mon Opticien", published="2026-03-05", url="https://b"),
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
