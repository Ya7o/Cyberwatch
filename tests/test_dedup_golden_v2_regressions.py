from cyberwatch import store
from cyberwatch.dedup import decide_merge, group_components
from cyberwatch.org_identity import effective_organisation_key

PAIRS = {
    "citypro": ("ITM-157ec8180d223fb4", "ITM-66285aa24e7daecb"),
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


def test_citypro_and_wizishop_identity_aliases_are_explicit():
    items = _items()
    for name in ("citypro", "wizishop"):
        left, right = (items[item_id] for item_id in PAIRS[name])
        assert effective_organisation_key(left.Organisation_Raw, left.Organisation_Key) == effective_organisation_key(
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
                item
                for item in items.values()
                if effective_organisation_key(item.Organisation_Raw, item.Organisation_Key)
                == effective_organisation_key(left.Organisation_Raw, left.Organisation_Key)
            ]
            failures[name] = {
                "direct": decide_merge(left, right),
                "left_component": components[left_id],
                "right_component": components[right_id],
                "org_items": [
                    (
                        item.Item_ID,
                        item.Source_ID,
                        item.Source_Item_ID,
                        item.best_date,
                        item.Title,
                        components[item.Item_ID],
                    )
                    for item in sorted(same_key_items, key=lambda value: (value.best_date, value.Source_ID, value.Item_ID))
                ],
            }
    assert failures == {}
