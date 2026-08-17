from cyberwatch import identity
from cyberwatch.dedup import build_incidents_with_registry
from cyberwatch.incident_identity import (
    assign_incident_ids,
    bootstrap_registry,
    validate_registry,
)


def test_bootstrap_recovers_published_anchor(make_item):
    item = make_item(source="CYBERATTAQUE_ORG", org="Globex", url="https://a")
    incident_id = identity.incident_id(item.Organisation_Key, item.Item_ID)
    from cyberwatch.model import Incident

    incident = Incident(
        Incident_ID=incident_id,
        Date=item.Published_Date,
        Date_Basis="Publication_Date",
        Organisation=item.Organisation_Raw,
        Secteur=item.Sector,
        Menace=item.Threat,
        Localisation=item.Location,
        Sources=item.Source_ID,
        Source_URLs=item.URL,
        Items_Count=1,
        First_seen=item.Collected_As_Of,
        Last_seen=item.Collected_As_Of,
    )

    rows = bootstrap_registry([item], [incident])

    assert rows == [{
        "Incident_ID": incident_id,
        "Anchor_Item_ID": item.Item_ID,
        "Organisation_Key": item.Organisation_Key,
        "Redirect_To": "",
    }]


def test_new_earlier_sorting_source_does_not_rename_incident(make_item):
    original = make_item(
        source="Z_SOURCE",
        org="Globex",
        published="2026-08-01",
        url="https://z",
        collected="2026-08-01T12:00:00+04:00",
    )
    first, registry = build_incidents_with_registry([original], [])
    stable_id = first[0].Incident_ID

    corroboration = make_item(
        source="A_SOURCE",
        org="Globex",
        published="2026-08-01",
        url="https://a",
        collected="2026-08-02T12:00:00+04:00",
    )
    second, updated = build_incidents_with_registry([original, corroboration], registry)

    assert len(second) == 1
    assert second[0].Incident_ID == stable_id
    active = [row for row in updated if not row["Redirect_To"]]
    assert len(active) == 1
    assert active[0]["Anchor_Item_ID"] == original.Item_ID


def test_merge_keeps_oldest_registered_anchor_and_redirects_other(make_item):
    older = make_item(
        source="A",
        org="Globex",
        published="2026-08-01",
        url="https://a",
        collected="2026-08-01T10:00:00+04:00",
    )
    newer = make_item(
        source="B",
        org="Globex",
        published="2026-08-01",
        url="https://b",
        collected="2026-08-02T10:00:00+04:00",
    )
    old_id = identity.incident_id(older.Organisation_Key, older.Item_ID)
    new_id = identity.incident_id(newer.Organisation_Key, newer.Item_ID)
    registry = [
        {"Incident_ID": old_id, "Anchor_Item_ID": older.Item_ID, "Organisation_Key": older.Organisation_Key, "Redirect_To": ""},
        {"Incident_ID": new_id, "Anchor_Item_ID": newer.Item_ID, "Organisation_Key": newer.Organisation_Key, "Redirect_To": ""},
    ]

    assigned, updated = assign_incident_ids([[newer, older]], registry)

    assert assigned == [old_id]
    rows = {row["Incident_ID"]: row for row in updated}
    assert rows[old_id]["Redirect_To"] == ""
    assert rows[new_id]["Redirect_To"] == old_id


def test_split_keeps_old_id_only_on_component_with_historical_anchor(make_item):
    bridge = make_item(
        source="CYBERATTAQUE_ORG",
        org="Inserm",
        published="2026-08-03",
        url="https://bridge",
    )
    first_native = make_item(
        source="FRENCHBREACHES",
        source_item_id="one",
        org="INSERM",
        published="2026-08-03",
        url="https://one",
    )
    second_native = make_item(
        source="FRENCHBREACHES",
        source_item_id="two",
        org="Institut national de la santé et de la recherche médicale",
        published="2026-08-06",
        url="https://two",
    )
    old_id = identity.incident_id(bridge.Organisation_Key, bridge.Item_ID)
    registry = [{
        "Incident_ID": old_id,
        "Anchor_Item_ID": bridge.Item_ID,
        "Organisation_Key": bridge.Organisation_Key,
        "Redirect_To": "",
    }]

    incidents, updated = build_incidents_with_registry(
        [bridge, first_native, second_native], registry
    )

    assert len(incidents) == 2
    assert old_id in {incident.Incident_ID for incident in incidents}
    active = [row for row in updated if not row["Redirect_To"]]
    assert len(active) == 2
    assert any(row["Incident_ID"] == old_id and row["Anchor_Item_ID"] == bridge.Item_ID for row in active)


def test_stale_registry_anchor_is_pruned_before_rebuild(make_item):
    stale = make_item(
        source="OLD_SOURCE",
        org="Legacy Corp",
        published="2026-07-01",
        url="https://old",
    )
    current = make_item(
        source="CYBERATTAQUE_ORG",
        org="Globex",
        published="2026-08-01",
        url="https://current",
    )
    stale_id = identity.incident_id(stale.Organisation_Key, stale.Item_ID)
    registry = [{
        "Incident_ID": stale_id,
        "Anchor_Item_ID": stale.Item_ID,
        "Organisation_Key": stale.Organisation_Key,
        "Redirect_To": "",
    }]

    incidents, updated = build_incidents_with_registry([current], registry)

    assert len(incidents) == 1
    assert all(row["Incident_ID"] != stale_id for row in updated)
    assert validate_registry(updated, [current], incidents) == []


def test_registry_validation_requires_one_active_anchor_per_incident(make_item):
    item = make_item(org="Globex", url="https://a")
    incident, registry = build_incidents_with_registry([item], [])
    assert validate_registry(registry, [item], incident) == []

    broken = [dict(registry[0], Redirect_To="INC-NOT-THERE")]
    problems = validate_registry(broken, [item], incident)
    assert any("cible de redirection absente" in problem for problem in problems)
