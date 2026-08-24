from __future__ import annotations

from cyberwatch.publication_audit import audit_payload


def _incident(**overrides):
    row = {
        "id": "INC-1",
        "org": "Exemple SA",
        "date": "2026-08-01",
        "threat": "Fuite de données",
        "sources": ["CYBERATTAQUE_ORG"],
        "urls": ["https://example.test/article"],
        "source_links": [{"source": "CYBERATTAQUE_ORG", "url": "https://example.test/article"}],
        "source_link_status": [{"source": "CYBERATTAQUE_ORG", "status": "direct"}],
        "summary": "Exemple SA a signalé une fuite de données clients.",
    }
    row.update(overrides)
    return row


def test_publication_audit_accepts_explicit_absence_and_link_reason():
    incident = _incident(
        summary="",
        source_links=[],
        source_link_status=[{"source": "CYBERATTAQUE_ORG", "status": "no_direct_url"}],
    )
    report = {"incidents": [{
        "incident_id": "INC-1",
        "summary_status": "rejected_quality",
        "promotion_gaps": [],
    }]}

    result = audit_payload([incident], {"INC-1": {}}, report)

    assert result["passed"] is True


def test_publication_audit_rejects_silent_summary_and_lost_semantic_field():
    incident = _incident(summary="")
    report = {"incidents": [{
        "incident_id": "INC-1",
        "summary_status": "accepted",
        "promotion_gaps": ["threat_actor"],
    }]}

    result = audit_payload([incident], {"INC-1": {"version": 2}}, report)

    assert result["passed"] is False
    assert {entry["issue"] for entry in result["errors"]} == {
        "silent_summary_absence", "semantic_promotion_gap",
    }


def test_publication_audit_rejects_unknown_sector_without_a_reason():
    result = audit_payload([_incident(sector="Inconnu")], {"INC-1": {}}, {
        "incidents": [{"incident_id": "INC-1", "summary_status": "accepted"}],
    })

    assert result["passed"] is False
    assert result["errors"] == [{"issue": "silent_sector_unknown", "id": "INC-1"}]
