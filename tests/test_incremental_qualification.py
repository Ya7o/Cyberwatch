import copy

from cyberwatch.incremental_qualification import (
    can_reuse_snapshot,
    parity_failures,
    qualify_delta,
)
from cyberwatch.model import Incident, Item
from cyberwatch.qualification import QualificationReport


def _item(**changes):
    values = dict(
        Item_ID="ITM-1",
        Source_ID="SRC",
        Source_Item_ID="1",
        Published_Date="2026-08-20",
        Event_Date="2026-08-20",
        Organisation_Raw="Example SA",
        Organisation_Key="example-sa",
        Threat_Raw="Ransomware",
        Threat="Ransomware",
        Sector="Technologies",
        Location="France",
        Title="Incident Example SA",
        URL="https://example.test/1",
        Collected_As_Of="2026-08-20T08:00:00+04:00",
    )
    values.update(changes)
    return Item(**values)


def _incident():
    return Incident(
        Incident_ID="INC-1",
        Date="2026-08-20",
        Date_Basis="Event_Date",
        Organisation="Example SA",
        Secteur="Technologies",
        Menace="Ransomware",
        Localisation="France",
        Sources="SRC",
        Source_URLs="https://example.test/1",
        Items_Count=1,
    )


def _report(item=None, incident=None, *, provenance=None, registry=None):
    from cyberwatch import identity

    items = [item or _item()]
    incidents = [incident or _incident()]
    return QualificationReport(
        items=items,
        incidents=incidents,
        changes={},
        provenance=list(provenance or []),
        decisions=[],
        decision_summary=[],
        incident_id_registry=list(registry or []),
        items_hash=identity.items_hash(items),
        incidents_hash=identity.incidents_hash(incidents),
    )


def test_exact_snapshot_without_work_is_reusable_despite_collection_timestamp():
    previous = [_item()]
    current = [_item(Collected_As_Of="2026-08-21T08:00:00+04:00")]
    assert can_reuse_snapshot(current, previous, work_item_ids=[])[0] is True


def test_work_item_forces_canonical_fallback_even_if_hash_is_same():
    reusable, reason = can_reuse_snapshot([_item()], [_item()], work_item_ids=["ITM-1"])
    assert reusable is False
    assert reason == "work_items_present"


def test_business_change_forces_canonical_fallback():
    reusable, reason = can_reuse_snapshot(
        [_item(Title="Titre modifié")], [_item()], work_item_ids=[]
    )
    assert reusable is False
    assert reason == "items_hash_changed"


def test_reuse_path_rebuilds_incidents_without_calling_qualify(monkeypatch):
    previous_items = [_item()]

    def forbidden(_items):
        raise AssertionError("qualify() ne doit pas être appelé sur le fast-path")

    monkeypatch.setattr("cyberwatch.incremental_qualification.qualify", forbidden)
    result = qualify_delta(
        copy.deepcopy(previous_items),
        previous_items=previous_items,
        previous_incidents=[_incident()],
        previous_provenance=[{"Item_ID": "ITM-1"}],
        previous_incident_id_registry=[],
        work_item_ids=[],
    )
    assert result.reused_snapshot is True
    assert result.fallback_reason == "exact_snapshot_match"
    assert result.report.items_hash == _report().items_hash
    assert result.report.changes["incremental_incidents_rebuilt"] == 1
    assert len(result.report.incidents) == 1
    assert result.report.incidents[0].Organisation == "Example SA"


def test_dirty_path_calls_canonical_qualify(monkeypatch):
    expected = _report()
    calls = []

    def canonical(items):
        calls.append(items)
        return expected

    monkeypatch.setattr("cyberwatch.incremental_qualification.qualify", canonical)
    result = qualify_delta(
        [_item(Title="modifié")],
        previous_items=[_item()],
        previous_incidents=[_incident()],
        previous_provenance=[],
        previous_incident_id_registry=[],
        work_item_ids=["ITM-1"],
    )
    assert calls
    assert result.reused_snapshot is False
    assert result.report is expected


def test_parity_failures_reports_hash_or_count_differences():
    canonical = _report()
    assert parity_failures(_report(), canonical) == []
    changed = _report(incident=Incident(Incident_ID="INC-2", Organisation="Other"))
    failures = parity_failures(changed, canonical)
    assert any("incidents_hash" in failure for failure in failures)


def test_parity_failures_reports_provenance_difference():
    canonical = _report(
        provenance=[{"Item_ID": "ITM-1", "Field": "Sector", "Decision": "APPLIED"}]
    )
    changed = _report(
        provenance=[{"Item_ID": "ITM-1", "Field": "Sector", "Decision": "REJECTED"}]
    )
    failures = parity_failures(changed, canonical)
    assert any("provenance_hash" in failure for failure in failures)


def test_parity_failures_reports_registry_difference():
    canonical = _report(registry=[{"Incident_ID": "INC-1", "Anchor_Item_ID": "ITM-1"}])
    changed = _report(registry=[{"Incident_ID": "INC-1", "Anchor_Item_ID": "ITM-2"}])
    failures = parity_failures(changed, canonical)
    assert any("incident_registry_hash" in failure for failure in failures)
