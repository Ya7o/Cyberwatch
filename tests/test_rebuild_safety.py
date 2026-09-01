from cyberwatch import identity
from cyberwatch.dedup import build_incidents_with_registry
from cyberwatch.incident_identity import validate_registry


def _registry_row(item, *, incident_id=None, redirect=""):
    return {
        "Incident_ID": incident_id or identity.incident_id(item.Organisation_Key, item.Item_ID),
        "Anchor_Item_ID": item.Item_ID,
        "Organisation_Key": item.Organisation_Key,
        "Redirect_To": redirect,
    }


def test_rebuild_prunes_registry_anchor_missing_from_current_items(make_item):
    removed = make_item(source="OLD_SOURCE", org="Removed Corp", published="2026-01-05", url="https://old")
    current = make_item(source="CURRENT_SOURCE", org="Current Corp", published="2026-08-01", url="https://current")
    stale_id = identity.incident_id(removed.Organisation_Key, removed.Item_ID)
    incidents, registry = build_incidents_with_registry([current], [_registry_row(removed, incident_id=stale_id)])
    assert stale_id not in {row["Incident_ID"] for row in registry}
    assert validate_registry(registry, [current], incidents) == []


def test_surviving_redirect_anchor_reactivates_when_target_anchor_disappears(make_item):
    survivor = make_item(source="A_SOURCE", org="Globex", published="2026-08-01", url="https://a")
    removed_target = make_item(source="B_SOURCE", org="Globex", published="2026-08-01", url="https://b")
    survivor_id = identity.incident_id(survivor.Organisation_Key, survivor.Item_ID)
    target_id = identity.incident_id(removed_target.Organisation_Key, removed_target.Item_ID)
    registry = [
        _registry_row(survivor, incident_id=survivor_id, redirect=target_id),
        _registry_row(removed_target, incident_id=target_id),
    ]
    incidents, updated = build_incidents_with_registry([survivor], registry)
    assert [incident.Incident_ID for incident in incidents] == [survivor_id]
    assert updated == [_registry_row(survivor, incident_id=survivor_id)]
    assert validate_registry(updated, [survivor], incidents) == []
