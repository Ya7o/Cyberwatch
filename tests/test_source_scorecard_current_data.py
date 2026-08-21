from cyberwatch import source_scorecard


def test_current_scorecard_runs_offline_on_repository_snapshot():
    payload = source_scorecard.current_scorecard(recent_runs=5)
    active = {row["source_id"] for row in payload["sources"]}
    assert {"FRENCHBREACHES", "BONJOURLAFUITE", "CYBERATTAQUE_ORG", "RANSOMWARE_LIVE", "VEILLE_LLM"} <= active
    assert payload["items"] >= payload["incidents"]
    assert 0.0 <= payload["coverage"]["unknown_sector_pct"] <= 100.0
