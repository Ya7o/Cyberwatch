from cyberwatch.dedup import KEEP_SEPARATE, build_incidents, decide_merge, group_components


def _component_signature(items):
    return sorted(
        tuple(sorted(item.Item_ID for item in component))
        for component in group_components(items)
    )


def test_conflicting_event_dates_are_a_strong_veto(make_item):
    left = make_item(
        source="SOURCE_A",
        org="Example Org",
        event="2026-08-10",
        published="2026-08-11",
        url="https://a/1",
    )
    right = make_item(
        source="SOURCE_B",
        org="Example Org",
        event="2026-08-11",
        published="2026-08-12",
        url="https://b/1",
    )

    decision = decide_merge(left, right)

    assert decision.action == KEEP_SEPARATE
    assert decision.reason_code == "INCIDENT_KEEP_CONFLICTING_EVENT_DATE"
    assert len(build_incidents([left, right])) == 2


def test_conflicting_event_date_veto_cannot_be_bridged(make_item):
    first = make_item(
        source="SOURCE_A",
        org="Example Org",
        event="2026-08-10",
        published="2026-08-10",
        url="https://a/1",
    )
    bridge = make_item(
        source="SOURCE_B",
        org="Example Org",
        published="2026-08-10",
        url="https://b/1",
    )
    second = make_item(
        source="SOURCE_C",
        org="Example Org",
        event="2026-08-11",
        published="2026-08-10",
        url="https://c/1",
    )

    components = group_components([first, bridge, second])

    assert len(components) == 2
    assert sorted(len(component) for component in components) == [1, 2]
    assert not any(
        {item.Event_Date for item in component if item.Event_Date}
        == {"2026-08-10", "2026-08-11"}
        for component in components
    )


def test_grouping_is_invariant_to_input_order(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-02", url="https://b"),
        make_item(source="C", org="Globex", published="2026-08-10", url="https://c"),
    ]

    assert _component_signature(items) == _component_signature(list(reversed(items)))


def test_grouping_never_loses_or_duplicates_items(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(source="B", org="Globex", published="2026-08-02", url="https://b"),
        make_item(source="C", org="Initech", published="2026-08-03", url="https://c"),
    ]

    flattened = [item.Item_ID for component in group_components(items) for item in component]

    assert sorted(flattened) == sorted(item.Item_ID for item in items)
    assert len(flattened) == len(set(flattened))


def test_component_never_contains_conflicting_native_ids_for_same_source(make_item):
    items = [
        make_item(source="A", org="Globex", published="2026-08-01", url="https://a"),
        make_item(
            source="B",
            source_item_id="one",
            org="Globex",
            published="2026-08-01",
            url="https://b/1",
        ),
        make_item(
            source="B",
            source_item_id="two",
            org="Globex",
            published="2026-08-02",
            url="https://b/2",
        ),
    ]

    for component in group_components(items):
        ids_by_source = {}
        for item in component:
            if not item.Source_Item_ID:
                continue
            ids_by_source.setdefault(item.Source_ID, set()).add(item.Source_Item_ID)
        assert all(len(source_ids) <= 1 for source_ids in ids_by_source.values())
