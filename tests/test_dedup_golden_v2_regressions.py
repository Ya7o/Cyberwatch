from cyberwatch import store
from cyberwatch.dedup import MERGE, build_incidents, decide_merge, group_components
from cyberwatch.org_identity import effective_organisation_key

PAIRS = {
    "wizishop": ("ITM-5299e7c10746fa62", "ITM-c5d6e68764f9a13e"),
    "scalingo": ("ITM-ce51e4cd76737af7", "ITM-b8f59e73458e855a"),
}


def _items():
    return {item.Item_ID: item for item in store.load_items()}


def _component_map(items):
    return {
        item.Item_ID: index
        for index, component in enumerate(group_components(list(items.values())))
        for item in component
    }


def test_wizishop_identity_alias_is_explicit_and_canonical():
    items = _items()
    left, right = (items[item_id] for item_id in PAIRS["wizishop"])
    left_key = effective_organisation_key(left.Organisation_Raw, left.Organisation_Key)
    right_key = effective_organisation_key(right.Organisation_Raw, right.Organisation_Key)
    assert left_key == right_key == "wizishop"


def test_wizishop_pair_merges_directly_and_builds_one_incident():
    items = _items()
    left, right = (items[item_id] for item_id in PAIRS["wizishop"])

    decision = decide_merge(left, right)
    assert decision.action == MERGE
    assert decision.reason_code == "INCIDENT_MERGE_ALIAS"

    components = group_components([left, right])
    assert len(components) == 1
    assert {item.Item_ID for item in components[0]} == set(PAIRS["wizishop"])

    incidents = build_incidents([left, right])
    assert len(incidents) == 1
    assert incidents[0].Items_Count == 2
    assert incidents[0].Sources == "CYBERATTAQUE_ORG | FRENCHBREACHES"
    assert incidents[0].Menace == "Fuite de données"


def test_stored_alias_key_is_recanonicalized():
    assert effective_organisation_key("", "wizishop dropizi et evolup") == "wizishop"
    assert effective_organisation_key("", "wizishop dropizi et evolup pirates") == "wizishop"


def test_citypro_subentity_remains_distinct_without_explicit_legal_identity():
    items = _items()
    left = items["ITM-157ec8180d223fb4"]
    right = items["ITM-66285aa24e7daecb"]
    assert effective_organisation_key(left.Organisation_Raw, left.Organisation_Key) != effective_organisation_key(
        right.Organisation_Raw, right.Organisation_Key
    )


def test_golden_v2_recall_regressions_are_same_component():
    items = _items()
    components = _component_map(items)
    failures = {}
    for name, (left_id, right_id) in PAIRS.items():
        if components[left_id] != components[right_id]:
            left, right = items[left_id], items[right_id]
            same_key_items = [
                item for item in items.values()
                if effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
                == effective_organisation_key(left.Organisation_Raw, left.Organisation_Key)
            ]
            failures[name] = {
                "direct": decide_merge(left, right),
                "left_component": components[left_id],
                "right_component": components[right_id],
                "org_items": [
                    (item.Item_ID, item.Source_ID, item.Source_Item_ID, item.best_date, item.Title, components[item.Item_ID])
                    for item in sorted(same_key_items, key=lambda value: (value.best_date, value.Source_ID, value.Item_ID))
                ],
            }
    assert failures == {}
