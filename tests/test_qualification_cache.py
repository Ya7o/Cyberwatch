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


def _payload():
    return qualification_cache.report_to_payload(
        _Report(),
        policy_version="P1",
        dependency_digest="D1",
        engine_digest_value="E1",
        prequalification_fingerprints={"I-1": "F1"},
    )


def _matches(payload, **overrides):
    args = dict(
        policy_version="P1",
        dependency_digest="D1",
        engine_digest_value="E1",
        previous_provenance_digest=payload["Next_Provenance_Digest"],
        previous_registry_digest=payload["Next_Registry_Digest"],
        prequalification_fingerprints={"I-1": "F1"},
    )
    args.update(overrides)
    return qualification_cache.cache_matches(payload, **args)


def test_cache_matches_only_exact_contract():
    payload = _payload()
    assert _matches(payload) == (True, "")
    assert _matches(payload, policy_version="P2")[1] == "policy_version"
    assert _matches(payload, dependency_digest="D2")[1] == "dependency_digest"
    assert _matches(payload, engine_digest_value="E2")[1] == "engine_digest"
    assert _matches(payload, previous_provenance_digest="changed")[1] == "provenance_changed"
    assert _matches(payload, previous_registry_digest="changed")[1] == "incident_registry_changed"
    assert _matches(payload, prequalification_fingerprints={"I-1": "CHANGED"})[1] == "fingerprints_changed"
    assert _matches(payload, prequalification_fingerprints={"I-1": "F1", "I-2": "F2"})[1] == "fingerprints_changed"


def test_cached_report_round_trip_preserves_outputs_and_decisions():
    report = _Report()
    payload = qualification_cache.report_to_payload(
        report,
        policy_version="P1",
        dependency_digest="D1",
        engine_digest_value="E1",
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


def test_rows_digest_is_order_independent():
    left = qualification_cache.rows_digest([{"a": "1", "b": "2"}, {"a": "3"}])
    right = qualification_cache.rows_digest([{"a": "3"}, {"b": "2", "a": "1"}])
    assert left == right


def test_cache_usage_observation_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    qualification_cache.write_usage_observation(hit=True, skipped_items=42)
    payload = qualification_cache.read_usage_observation()
    assert payload["Cache_Hit"] is True
    assert payload["Skipped_Items"] == 42
    assert payload["Cache_Version"] == qualification_cache.CACHE_VERSION
