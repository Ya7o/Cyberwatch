from cyberwatch import config
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


def test_ransomware_reunification_never_bridges_different_organisations(make_item):
    """Cas réel constaté (audit post-run 2026-08-25) : 11 organisations
    distinctes (ALIZE, Actini Group, Bouygues ES, Medicos...) publiées à
    quelques jours d'écart les unes des autres, toutes taguées Ransomware,
    se recollaient transitivement en un seul incident "ALIZE" — la passe de
    réunification de group_components() ne vérifiait que la fenêtre de
    corroboration (_ransomware_corroboration), jamais l'identité de
    l'organisation. Chaque maillon de la chaîne est à 1 jour du suivant
    (bien en-deçà des 14 jours de RANSOMWARE_CORROBORATION_DAYS)."""
    orgs = ["Alize", "Actini Group", "Bouygues ES", "Ernat Bureau Etudes", "Medicos"]
    items = [
        make_item(
            source="RANSOMWARE_LIVE",
            org=org,
            published=f"2026-08-{6 + index:02d}",
            threat=config.THREAT_RANSOMWARE,
            title=f"{org} revendiqué par un groupe",
            url=f"https://claim.example/{index}",
        )
        for index, org in enumerate(orgs)
    ]

    components = group_components(items)

    assert len(components) == len(orgs)
    assert sorted(len(component) for component in components) == [1] * len(orgs)
    assert len(build_incidents(items)) == len(orgs)


def test_ransomware_reunification_still_bridges_the_same_organisation(make_item):
    """Le cas visé par le commentaire du code reste couvert : un article
    éditorial et une revendication ransomware sur la MÊME victime, coupés en
    deux composantes par la construction ancrée (une troisième source crée
    une composante intermédiaire), doivent toujours se recoller."""
    claim = make_item(
        source="RANSOMWARE_LIVE",
        org="Filair",
        published="2026-08-01",
        threat=config.THREAT_RANSOMWARE,
        title="Filair revendiqué par un groupe",
        url="https://claim.example/filair",
    )
    other_org_bridge = make_item(
        source="FRENCHBREACHES",
        org="Autre Victime",
        published="2026-08-05",
        threat=config.THREAT_RANSOMWARE,
        title="Autre Victime",
        url="https://claim.example/autre-victime",
    )
    report = make_item(
        source="CYBERATTAQUE_ORG",
        org="Filair",
        published="2026-08-10",
        threat=config.THREAT_RANSOMWARE,
        title="Filair victime d'une cyberattaque",
        url="https://cyberattaque.example/filair",
    )

    components = group_components([claim, other_org_bridge, report])

    filair_component = next(c for c in components if any(i.Item_ID == claim.Item_ID for i in c))
    assert {i.Item_ID for i in filair_component} == {claim.Item_ID, report.Item_ID}


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
