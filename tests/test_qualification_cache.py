from cyberwatch import qualification_cache
from cyberwatch.model import Incident, Item
from cyberwatch.qualification_decision import QualificationDecision


class _Report:
    def __init__(self):
        self.items = [Item(Item_ID="I-1", Organisation_Key="org", Threat="Ransomware", Sector="Industrie", Location="France")]
        self.incidents = [Incident(Incident_ID="INC-1", Organisation="Org", Menace="Ransomware", Secteur="Industrie", Localisation="France")]
        self.changes = {"sector": 1}
        self.provenance = [{"Item_ID": "I-1", "Field": "Sector", "Decision": "APPLIED"}]
        self.decisions = [QualificationDecision("I-1", "SRC", "Sector", "Inconnu", "Industrie", "Industrie", "TEST")]
        self.decision_summary = []
        self.incident_id_registry = [{"Incident_ID": "INC-1", "Anchor_Item_ID": "I-1"}]
        self.items_hash = "items-hash"
        self.incidents_hash = "incidents-hash"


def test_cache_matches_only_exact_prequalification_contract():
    payload = qualification_cache.report_to_payload(
        _Report(),
        policy_version="P1",
        dependency_digest="D1",
        prequalification_fingerprints={"I-1": "F1"},
    )
    assert qualification_cache.cache_matches(
        payload,
        policy_version="P1",
        dependency_digest="D1",
        prequalification_fingerprints={"I-1": "F1"},
    ) == (True, "")
    assert qualification_cache.cache_matches(
        payload,
        policy_version="P2",
        dependency_digest="D1",
        prequalification_fingerprints={"I-1": "F1"},
    )[0] is False
    assert qualification_cache.cache_matches(
        payload,
        policy_version="P1",
        dependency_digest="D2",
        prequalification_fingerprints={"I-1": "F1"},
    )[0] is False
    assert qualification_cache.cache_matches(
        payload,
        policy_version="P1",
        dependency_digest="D1",
        prequalification_fingerprints={"I-1": "CHANGED"},
    )[0] is False
    assert qualification_cache.cache_matches(
        payload,
        policy_version="P1",
        dependency_digest="D1",
        prequalification_fingerprints={"I-1": "F1", "I-2": "F2"},
    )[0] is False


def test_cached_report_round_trip_preserves_outputs_and_decisions():
    report = _Report()
    payload = qualification_cache.report_to_payload(
        report,
        policy_version="P1",
        dependency_digest="D1",
        prequalification_fingerprints={"I-1": "F1"},
    )
    parts = qualification_cache.payload_parts(payload)
    assert [item.to_row() for item in parts["items"]] == [item.to_row() for item in report.items]
    assert [incident.to_row() for incident in parts["incidents"]] == [incident.to_row() for incident in report.incidents]
    assert [decision.to_row() for decision in parts["decisions"]] == [decision.to_row() for decision in report.decisions]
    assert parts["provenance"] == report.provenance
    assert parts["incident_id_registry"] == report.incident_id_registry
    assert parts["items_hash"] == report.items_hash
    assert parts["incidents_hash"] == report.incidents_hash


def test_cache_usage_observation_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    qualification_cache.write_usage_observation(hit=True, skipped_items=42)
    payload = qualification_cache.read_usage_observation()
    assert payload["Cache_Hit"] is True
    assert payload["Skipped_Items"] == 42
    assert payload["Cache_Version"] == qualification_cache.CACHE_VERSION
