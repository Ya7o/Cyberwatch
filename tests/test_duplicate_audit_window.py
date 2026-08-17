from cyberwatch import config
from cyberwatch.duplicate_audit import (
    RISK_MISSED_DUPLICATE,
    find_audit_candidates,
    find_duplicate_candidates,
)


def test_default_audit_window_surfaces_j4_candidate(make_item):
    items = [
        make_item(source="A", org="My Piscine", published="2026-04-23", url="https://a"),
        make_item(source="B", org="My Piscine France", published="2026-04-27", url="https://b"),
    ]

    candidates = find_duplicate_candidates(items)

    assert config.INCIDENT_GAP_DAYS == 14
    assert len(candidates) == 1
    assert candidates[0].days_apart == 4


def test_audit_window_remains_configurable_to_three_days(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-04-01", url="https://a"),
        make_item(source="B", org="Globex France", published="2026-04-05", url="https://b"),
    ]

    assert find_duplicate_candidates(items, max_days=3) == []


def test_default_audit_window_excludes_j15(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-04-01", url="https://a"),
        make_item(source="B", org="Globex France", published="2026-04-16", url="https://b"),
    ]

    assert find_duplicate_candidates(items) == []


def test_j4_to_j14_candidate_is_audit_only_not_automatic_merge(make_item):
    items = [
        make_item(source="A", org="Service Civique", published="2026-05-02", url="https://a"),
        make_item(source="B", org="Agence du Service Civique", published="2026-05-06", url="https://b"),
    ]

    candidates = find_audit_candidates(items)

    assert any(candidate.risk_type == RISK_MISSED_DUPLICATE for candidate in candidates)
