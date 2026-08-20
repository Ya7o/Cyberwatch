from cyberwatch.rich_facts import (
    dedupe_claims, divergence_groups, evidence_in_text, fact_history,
    normalize_status, primary_claim, validate_claim,
)


def test_validate_claim_requires_literal_evidence_and_number_support():
    text = "La source confirme 42 comptes compromis."
    assert validate_claim({"type": "affected_count", "status": "confirmed", "value": 42, "evidence": text}, text)
    assert validate_claim({"type": "affected_count", "status": "confirmed", "value": 9000, "evidence": text}, text) is None
    assert validate_claim({"type": "statement", "status": "confirmed", "evidence": "inventé"}, text) is None


def test_primary_claim_does_not_delete_divergence():
    claims = [
        {"type": "affected_count", "status": "claimed", "value": 200000, "scope": "clients", "evidence": "a"},
        {"type": "affected_count", "status": "confirmed", "value": 175000, "scope": "clients", "evidence": "b"},
    ]
    assert primary_claim(claims, "affected_count")["value"] == 175000
    groups = divergence_groups(claims)
    assert len(groups) == 1
    assert len(groups[0]["claims"]) == 2


def test_history_is_chronological_and_keeps_claims():
    claims = [
        {"type": "statement", "status": "confirmed", "date": "2026-08-02", "evidence": "b"},
        {"type": "statement", "status": "claimed", "date": "2026-08-01", "evidence": "a"},
    ]
    history = fact_history(claims)
    assert [row["date"] for row in history] == ["2026-08-01", "2026-08-02"]


def test_dedupe_and_status_normalization_are_stable():
    claim = {"type": "statement", "status": "garbage", "evidence": "x"}
    assert normalize_status("garbage") == "unknown"
    assert len(dedupe_claims([claim, claim])) == 1
    assert evidence_in_text("foo  bar", "x foo bar y")
