from cyberwatch.duplicate_audit import (
    DUPLICATE_CANDIDATE_SHARED_COMPANY_ID,
    MERGE_REVIEW_WEAK_CANONICAL_NAME,
    RISK_FALSE_MERGE,
    RISK_MISSED_DUPLICATE,
    find_audit_candidates,
)


def test_shared_company_id_surfaces_unresolved_identity(make_item):
    left = make_item(source="A", org="Marque Exemple", published="2026-08-10", url="https://a")
    right = make_item(source="B", org="Societe Exemple SAS", published="2026-08-11", url="https://b")
    company_ids = {
        left.Organisation_Key: "123456789",
        right.Organisation_Key: "123456789",
    }

    candidates = find_audit_candidates([left, right], company_ids=company_ids)

    assert len(candidates) == 1
    assert candidates[0].risk_type == RISK_MISSED_DUPLICATE
    assert candidates[0].reason_code == DUPLICATE_CANDIDATE_SHARED_COMPANY_ID
    assert candidates[0].company_id == "123456789"


def test_shared_company_id_does_not_override_conflicting_native_items(make_item):
    left = make_item(source="A", org="Marque Exemple", published="2026-08-10", url="https://a")
    right = make_item(source="A", org="Societe Exemple SAS", published="2026-08-11", url="https://b")
    left.Source_Item_ID = "1"
    right.Source_Item_ID = "2"
    company_ids = {
        left.Organisation_Key: "123456789",
        right.Organisation_Key: "123456789",
    }

    assert find_audit_candidates([left, right], company_ids=company_ids) == []


def test_weak_name_merge_is_exposed_for_review(make_item):
    left = make_item(source="A", org="Entreprise Exemple", published="2026-08-10", url="https://a")
    right = make_item(source="B", org="Entreprise Exemple", published="2026-08-12", url="https://b")

    candidates = find_audit_candidates([left, right])

    assert len(candidates) == 1
    assert candidates[0].risk_type == RISK_FALSE_MERGE
    assert candidates[0].reason_code == MERGE_REVIEW_WEAK_CANONICAL_NAME
    assert candidates[0].days_apart == 2


def test_strong_same_event_date_merge_is_not_exposed(make_item):
    left = make_item(source="A", org="Entreprise Exemple", published="2026-08-10", url="https://a")
    right = make_item(source="B", org="Entreprise Exemple", published="2026-08-12", url="https://b")
    left.Event_Date = "2026-08-09"
    right.Event_Date = "2026-08-09"

    assert find_audit_candidates([left, right]) == []


def test_current_alias_resolution_does_not_remain_a_missed_duplicate(make_item, monkeypatch):
    left = make_item(source="A", org="Nom Court", published="2026-08-10", url="https://a")
    right = make_item(source="B", org="Nom Court France", published="2026-08-11", url="https://b")

    # Le signal lexical existe, mais si la clé effective est désormais la même
    # il ne doit plus être présenté comme un doublon manqué.
    monkeypatch.setattr(
        "cyberwatch.duplicate_audit._effective_key",
        lambda _item: "identite-canonique",
    )

    candidates = find_audit_candidates([left, right])
    assert all(candidate.risk_type != RISK_MISSED_DUPLICATE for candidate in candidates)
