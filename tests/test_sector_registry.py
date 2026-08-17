from cyberwatch import config, enrichment, sector_registry


def _policy(**enabled):
    policy = sector_registry.load_policy()
    for channel, value in enabled.items():
        policy["channels"][channel]["enabled"] = value
    return policy


def test_structured_sector_propagates_to_same_exact_organisation(make_item):
    source = make_item(
        source="RANSOMWARE_LIVE", org="Acme", sector=config.SECTOR_TECH,
        url="https://ransomware.live/acme",
    )
    target = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="2", org="Acme",
        sector=config.SECTOR_UNKNOWN, url="https://cyberattaque.org/acme",
    )
    facts = [{
        "Item_ID": source.Item_ID,
        "Source_ID": "RANSOMWARE_LIVE",
        "Source_Sector_Raw": "Technology",
    }]

    registry = sector_registry.build_registry(
        [source, target], {}, source_fact_rows=facts, org_cache_rows=[],
        previous_provenance=[],
    )
    row = next(row for row in registry if row["Organisation_Key"] == source.Organisation_Key)
    assert row["Decision"] == sector_registry.DECISION_AUTO
    assert row["Sector"] == config.SECTOR_TECH

    changed, provenance, conflicts = sector_registry.apply_registry([source, target], registry)
    assert changed == 1
    assert conflicts == 0
    assert target.Sector == config.SECTOR_TECH
    assert provenance[0]["Origin"] == sector_registry.ORIGIN


def test_registry_application_is_reversible_and_not_self_proof(make_item):
    source = make_item(
        source="RANSOMWARE_LIVE", org="Acme", sector=config.SECTOR_TECH,
        url="https://ransomware.live/acme",
    )
    target = make_item(
        source="BONJOURLAFUITE", source_item_id="2", org="Acme",
        sector=config.SECTOR_UNKNOWN, url="https://bonjourlafuite/acme",
    )
    facts = [{
        "Item_ID": source.Item_ID, "Source_ID": "RANSOMWARE_LIVE",
        "Source_Sector_Raw": "Technology",
    }]
    registry = sector_registry.build_registry(
        [source, target], {}, source_fact_rows=facts, org_cache_rows=[],
        previous_provenance=[],
    )
    _changed, provenance, _conflicts = sector_registry.apply_registry([source, target], registry)
    assert target.Sector == config.SECTOR_TECH
    assert sector_registry.restore_registry_applications([source, target], provenance) == 1
    assert target.Sector == config.SECTOR_UNKNOWN

    rebuilt = sector_registry.build_registry(
        [source, target], {}, source_fact_rows=facts, org_cache_rows=[],
        previous_provenance=provenance,
    )
    row = next(row for row in rebuilt if row["Organisation_Key"] == source.Organisation_Key)
    assert row["Evidence_Count"] == "2"  # structured source + original known item only


def test_disabled_consensus_is_review_then_can_be_enabled(make_item):
    first = make_item(
        source="FRENCHBREACHES", org="Acme", sector=config.SECTOR_RETAIL,
        url="https://frenchbreaches/acme",
    )
    second = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="2", org="Acme",
        sector=config.SECTOR_RETAIL, url="https://cyberattaque/acme",
    )
    target = make_item(
        source="BONJOURLAFUITE", source_item_id="3", org="Acme",
        sector=config.SECTOR_UNKNOWN, url="https://bonjourlafuite/acme",
    )
    items = [first, second, target]

    registry = sector_registry.build_registry(
        items, {}, source_fact_rows=[], org_cache_rows=[], previous_provenance=[]
    )
    row = next(row for row in registry if row["Organisation_Key"] == first.Organisation_Key)
    assert row["Decision"] == sector_registry.DECISION_REVIEW
    assert row["Evidence_Type"] == "consensus_multi_source"

    registry = sector_registry.build_registry(
        items, {}, source_fact_rows=[], org_cache_rows=[], previous_provenance=[],
        policy=_policy(consensus_multi_source=True),
    )
    row = next(row for row in registry if row["Organisation_Key"] == first.Organisation_Key)
    assert row["Decision"] == sector_registry.DECISION_AUTO


def test_conflicting_known_sector_blocks_auto_structured_propagation(make_item):
    ransomware = make_item(
        source="RANSOMWARE_LIVE", org="Acme", sector=config.SECTOR_TECH,
        url="https://ransomware.live/acme",
    )
    conflicting = make_item(
        source="FRENCHBREACHES", source_item_id="2", org="Acme",
        sector=config.SECTOR_RETAIL, url="https://frenchbreaches/acme",
    )
    target = make_item(
        source="CYBERATTAQUE_ORG", source_item_id="3", org="Acme",
        sector=config.SECTOR_UNKNOWN, url="https://cyberattaque/acme",
    )
    facts = [{
        "Item_ID": ransomware.Item_ID, "Source_ID": "RANSOMWARE_LIVE",
        "Source_Sector_Raw": "Technology",
    }]
    registry = sector_registry.build_registry(
        [ransomware, conflicting, target], {}, source_fact_rows=facts,
        org_cache_rows=[], previous_provenance=[],
    )
    row = next(row for row in registry if row["Organisation_Key"] == ransomware.Organisation_Key)
    assert row["Decision"] == sector_registry.DECISION_CONFLICT
    changed, _provenance, _conflicts = sector_registry.apply_registry(
        [ransomware, conflicting, target], registry
    )
    assert changed == 0
    assert target.Sector == config.SECTOR_UNKNOWN


def test_manual_reference_remains_auto(make_item):
    target = make_item(org="Acme", sector=config.SECTOR_UNKNOWN)
    reference = {
        target.Organisation_Key: enrichment.Enrichment(
            organisation="Acme",
            sector=config.SECTOR_SERVICES,
            location="",
            scope="France",
            reason="validation humaine",
            validation_url="https://acme.example/about",
        )
    }
    registry = sector_registry.build_registry(
        [target], reference, source_fact_rows=[], org_cache_rows=[],
        previous_provenance=[],
    )
    row = next(row for row in registry if row["Organisation_Key"] == target.Organisation_Key)
    assert row["Decision"] == sector_registry.DECISION_AUTO
    assert row["Sector"] == config.SECTOR_SERVICES


def test_queue_prioritises_unmapped_raw_sector(make_item):
    target = make_item(
        source="RANSOMWARE_LIVE", org="Hotel Acme", sector=config.SECTOR_UNKNOWN,
    )
    facts = [{
        "Item_ID": target.Item_ID,
        "Source_ID": "RANSOMWARE_LIVE",
        "Source_Sector_Raw": "Hospitality",
    }]
    queue = sector_registry.build_enrichment_queue(
        [target], [], source_fact_rows=facts, challenger_provenance=[]
    )
    assert queue[0]["Category"] == "RAW_SECTOR_UNMAPPED"
    assert queue[0]["Raw_Sector_Values"] == "Hospitality"
