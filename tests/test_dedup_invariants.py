from cyberwatch import config
from cyberwatch.dedup import KEEP_SEPARATE, MERGE, build_incidents, decide_merge, group_components
from cyberwatch.incident_dedup import DIFFERENT, SAME, pair_key


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


def test_event_date_et_publication_date_mixtes_comparent_les_publications(make_item):
    left = make_item(
        source="SOURCE_A", org="Example Org", event="2026-08-01",
        published="2026-08-10", url="https://a/1",
    )
    right = make_item(
        source="SOURCE_B", org="Example Org", event="",
        published="2026-08-10", url="https://b/1",
    )

    forward = decide_merge(left, right)
    reverse = decide_merge(right, left)

    assert forward.action == MERGE
    assert reverse.action == MERGE
    assert forward.reason_code == reverse.reason_code
    assert forward.reason_code != "INCIDENT_KEEP_TIME_GAP"


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


def test_ransomware_chain_never_exceeds_component_time_window(make_item):
    items = [
        make_item(source="CYBERATTAQUE_ORG", org="Globex", published="2026-08-01",
                  threat=config.THREAT_RANSOMWARE, url="https://a"),
        make_item(source="RANSOMWARE_LIVE", org="Globex", published="2026-08-14",
                  threat=config.THREAT_RANSOMWARE, url="https://b"),
        make_item(source="FRENCHBREACHES", org="Globex", published="2026-08-27",
                  threat=config.THREAT_RANSOMWARE, url="https://c"),
    ]

    components = group_components(items)

    assert sorted(len(component) for component in components) == [1, 2]
    assert not any(
        {item.Published_Date for item in component} == {
            "2026-08-01", "2026-08-14", "2026-08-27"
        }
        for component in components
    )


def test_llm_same_joins_a_closed_compatible_component(make_item):
    first = make_item(
        source="FRENCHBREACHES", source_item_id="post-a", org="Globex",
        published="2026-08-01", url="https://a",
    )
    veto = make_item(
        source="FRENCHBREACHES", source_item_id="post-b", org="Globex",
        published="2026-08-02", url="https://b",
    )
    confirmed = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="post-c", org="Globex",
        published="2026-08-08", url="https://c",
    )
    decisions = {pair_key(first.Item_ID, confirmed.Item_ID): SAME}

    components = group_components([first, veto, confirmed], decisions)

    assert sorted(
        sorted(item.Item_ID for item in component) for component in components
    ) == sorted([[first.Item_ID, confirmed.Item_ID], [veto.Item_ID]])


def test_component_grouping_is_invariant_across_permutations(make_item):
    from itertools import permutations

    items = [
        make_item(source="CYBERATTAQUE_ORG", org="Globex", published="2026-08-01",
                  threat=config.THREAT_RANSOMWARE, url="https://a"),
        make_item(source="RANSOMWARE_LIVE", org="Globex", published="2026-08-14",
                  threat=config.THREAT_RANSOMWARE, url="https://b"),
        make_item(source="FRENCHBREACHES", org="Globex", published="2026-08-27",
                  threat=config.THREAT_RANSOMWARE, url="https://c"),
    ]
    expected = _component_signature(items)

    assert all(_component_signature(list(order)) == expected for order in permutations(items))


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


def test_same_native_identity_survives_corrected_organisation_metadata(make_item):
    original = make_item(
        source="A", source_item_id="native-42", org="Ancien libellé",
        published="2026-08-01", url="https://old",
    )
    corrected = make_item(
        source="A", source_item_id="native-42", org="Nouveau libellé",
        published="2026-09-01", url="https://new",
    )
    # Le stockage normal remplace l'ancien item grâce à l'ID natif stable.
    # Des snapshots historiques réparés peuvent néanmoins contenir deux IDs.
    original.Item_ID = "LEGACY-A"
    corrected.Item_ID = "CURRENT-A"

    components = group_components([original, corrected])

    assert [[item.Item_ID for item in component] for component in components] == [
        ["LEGACY-A", "CURRENT-A"]
    ]


def test_llm_different_is_a_persistent_strong_veto(make_item):
    left = make_item(source="A", org="Globex", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Globex", published="2026-08-01", url="https://b")
    decisions = {pair_key(left.Item_ID, right.Item_ID): DIFFERENT}

    decision = decide_merge(left, right, decisions)

    assert decision.action == KEEP_SEPARATE
    assert decision.reason_code == "INCIDENT_KEEP_LLM_DIFFERENT"
    assert len(group_components([left, right], decisions)) == 2


def test_llm_same_can_confirm_a_cross_source_long_gap(make_item):
    left = make_item(source="A", org="Globex", published="2026-08-01", url="https://a")
    right = make_item(source="B", org="Globex", published="2026-08-10", url="https://b")
    decisions = {pair_key(left.Item_ID, right.Item_ID): SAME}

    decision = decide_merge(left, right, decisions)

    assert decision.action == "MERGE"
    assert decision.reason_code == "INCIDENT_MERGE_LLM_CONFIRMED"
    assert len(group_components([left, right], decisions)) == 1


def test_llm_same_j14_reste_accepte_et_j15_est_bloque(make_item):
    left = make_item(source="A", org="Globex", published="2026-08-01", url="https://a")
    j14 = make_item(source="B", org="Globex", published="2026-08-15", url="https://b14")
    j15 = make_item(source="B", org="Globex", published="2026-08-16", url="https://b15")

    assert decide_merge(left, j14, {pair_key(left.Item_ID, j14.Item_ID): SAME}).action == MERGE
    blocked = decide_merge(left, j15, {pair_key(left.Item_ID, j15.Item_ID): SAME})
    assert blocked.action == KEEP_SEPARATE
    assert blocked.reason_code == "INCIDENT_KEEP_LLM_TIME_GAP"


def test_llm_same_never_overrides_conflicting_native_ids(make_item):
    left = make_item(
        source="A", source_item_id="one", org="Globex",
        published="2026-08-01", url="https://a",
    )
    right = make_item(
        source="A", source_item_id="two", org="Globex",
        published="2026-08-01", url="https://b",
    )
    decisions = {pair_key(left.Item_ID, right.Item_ID): SAME}

    assert decide_merge(left, right, decisions).reason_code == "INCIDENT_KEEP_CONFLICTING_SOURCE_ITEM_ID"
    assert len(group_components([left, right], decisions)) == 2


def test_deterministic_edge_precedes_llm_edge_in_contaminated_component(
    make_item, monkeypatch,
):
    """Régression Printemps/SAD'S : la vraie paire homonyme est réunie avant
    qu'une arête LLM puisse créer une composante ensuite bloquée par un veto."""
    from cyberwatch import org_identity

    printemps_article = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="3054", org="Printemps",
        published="2026-09-09", url="https://example.test/printemps-article",
    )
    printemps_alert = make_item(
        source="FRENCHBREACHES", org="Printemps", published="2026-09-09",
        url="https://example.test/printemps-alert",
    )
    sads_article = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="3034", org="SAD’S Interim",
        published="2026-09-08", url="https://example.test/sads",
    )
    monkeypatch.setattr(
        org_identity,
        "ORGANISATION_IDENTITY_REGISTRY",
        {"printemps": "sad s interim"},
    )
    decisions = {
        pair_key(printemps_alert.Item_ID, sads_article.Item_ID): SAME,
    }

    components = group_components(
        [printemps_article, printemps_alert, sads_article], decisions
    )

    assert sorted(sorted(item.Item_ID for item in component) for component in components) == sorted([
        sorted([printemps_article.Item_ID, printemps_alert.Item_ID]),
        [sads_article.Item_ID],
    ])
