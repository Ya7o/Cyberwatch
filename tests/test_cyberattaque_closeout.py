from __future__ import annotations

import json

from scripts.audit_cyberattaque_rich_facts import audit_rows, review_sample
from scripts.certify_cyberattaque_rich_facts import certify


def _row(item_id: str, rich: dict) -> dict:
    return {
        "Item_ID": item_id,
        "URL": f"https://example.test/{item_id}",
        "Organisation_Raw": item_id,
        "Source_ID": "CYBERATTAQUE_ORG",
        "Source_Metadata_JSON": json.dumps({"rich_facts": rich}, ensure_ascii=False),
    }


def test_audit_detects_confirmed_hypothesis_and_missing_evidence():
    rows = [_row("a", {
        "version": "2",
        "claims": [
            {"kind": "statement", "status": "confirmed", "evidence": "Les données pourraient être touchées."},
            {"kind": "statement", "status": "reported", "evidence": ""},
        ],
    })]
    audit = audit_rows(rows)
    assert audit["quality_errors"]["confirmed_with_hypothetical_evidence"] == 1
    assert audit["quality_errors"]["records_without_evidence"] == 1
    assert audit["metrics"]["evidence_coverage"] == 0.5


def test_audit_accepts_scaled_numeric_evidence():
    rows = [_row("b", {
        "version": "2",
        "affected_counts": [{"value": 1_800_000, "unit": "accounts", "status": "confirmed", "evidence": "La DGFiP confirme 1,8 million de comptes compromis."}],
        "claims": [],
    })]
    audit = audit_rows(rows)
    assert audit["quality_errors"].get("numeric_value_not_in_evidence", 0) == 0


def test_certification_fails_precision_gate_and_passes_clean_audit():
    bad = {"articles": 10, "metrics": {"rich_coverage": 1, "schema_v2_coverage": 1, "evidence_coverage": 1, "error_rate": 0.01}, "quality_errors": {"confirmed_with_hypothetical_evidence": 1}}
    assert certify(bad)["certified"] is False
    clean = {"articles": 10, "metrics": {"rich_coverage": 1, "schema_v2_coverage": 1, "evidence_coverage": 1, "error_rate": 0}, "quality_errors": {}}
    assert certify(clean)["certified"] is True


def test_review_sample_is_deterministic_and_stratified():
    rows = [
        _row("modal", {"version": "2", "claims": [{"status": "hypothesis", "evidence": "x"}]}),
        _row("timeline", {"version": "2", "claims": [], "timeline": [{"date": "2026-01-01", "evidence": "a"}, {"date": "2026-01-02", "evidence": "b"}]}),
        _row("simple", {"version": "2", "claims": [{"status": "confirmed", "evidence": "x"}]}),
    ]
    first = review_sample(rows, 3)
    second = review_sample(rows, 3)
    assert first == second
    assert {row["stratum"] for row in first} == {"modalite", "chronologie", "simple"}
