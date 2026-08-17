from cyberwatch.dedup import build_incidents, group_components


def test_component_veto_is_checked_against_all_members(make_item):
    """Un item tiers ne peut pas ponter deux IDs natifs incompatibles."""
    anchor = make_item(
        source="CYBERATTAQUE_ORG",
        source_item_id="",
        org="Inserm",
        published="2026-08-03",
        url="https://cyberattaque.example/inserm",
    )
    first_native = make_item(
        source="FRENCHBREACHES",
        source_item_id="fb-one",
        org="INSERM",
        published="2026-08-03",
        url="https://frenchbreaches.example/one",
    )
    second_native = make_item(
        source="FRENCHBREACHES",
        source_item_id="fb-two",
        org="Institut national de la santé et de la recherche médicale",
        published="2026-08-06",
        url="https://frenchbreaches.example/two",
    )

    components = group_components([anchor, first_native, second_native])

    assert len(components) == 2
    assert sorted(len(component) for component in components) == [1, 2]
    for component in components:
        french_ids = {
            item.Source_Item_ID
            for item in component
            if item.Source_ID == "FRENCHBREACHES" and item.Source_Item_ID
        }
        assert len(french_ids) <= 1


def test_component_veto_changes_incident_count_not_item_count(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", source_item_id="one", org="Globex", published="2026-08-01", url="https://b/1"),
        make_item(source="B", source_item_id="two", org="Globex", published="2026-08-02", url="https://b/2"),
    ]

    incidents = build_incidents(items)

    assert sum(incident.Items_Count for incident in incidents) == 3
    assert len(incidents) == 2
