from cyberwatch.rich_facts_consolidation import consolidate_sources


def test_consolidation_preserves_source_divergence_and_primary_projection():
    payload = consolidate_sources([
        {"claims": [{"type": "affected_count", "status": "claimed", "value": 200000, "scope": "clients", "source_id": "A", "evidence": "a"}]},
        {"claims": [{"type": "affected_count", "status": "confirmed", "value": 175000, "scope": "clients", "source_id": "B", "evidence": "b"}]},
    ])
    assert len(payload["claims"]) == 2
    assert payload["primary"]["affected_count"]["value"] == 175000
    assert len(payload["divergences"]) == 1
    assert {c["source_id"] for c in payload["divergences"][0]["claims"]} == {"A", "B"}
