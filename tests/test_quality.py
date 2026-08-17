from cyberwatch import config, quality


def test_quality_detects_regression_and_accepts_improvement(make_item):
    baseline = quality.metrics([make_item(threat="Inconnu", sector="Inconnu", location="Inconnu")])
    assert quality.compare(
        quality.metrics([make_item(threat="Inconnu", sector="Inconnu", location="Inconnu")]),
        baseline,
    ) == []
    assert quality.compare(
        quality.metrics([make_item(threat="Ransomware", sector="Santé", location="France")]),
        baseline,
    ) == []

    current = quality.metrics([make_item(threat="Inconnu", sector="Santé", location="France")])
    baseline_clean = quality.metrics([make_item(threat="Ransomware", sector="Santé", location="France")])
    assert quality.compare(current, baseline_clean)


def test_population_change_is_not_a_quality_regression(make_item):
    baseline = quality.metrics([
        make_item(threat="Ransomware", sector="Santé", location="France"),
    ])
    current = quality.metrics([
        make_item(threat="Inconnu", sector="Inconnu", location="Inconnu"),
        make_item(threat="Inconnu", sector="Inconnu", location="Inconnu"),
    ])
    assert quality.compare(current, baseline) == []


def test_source_scope_is_compared_when_its_population_is_unchanged(make_item):
    baseline = quality.metrics([
        make_item(source="CYBERATTAQUE_ORG", threat="Ransomware", sector="Santé", location="France"),
        make_item(source="BONJOURLAFUITE", threat="Ransomware", sector="Santé", location="France"),
    ])
    current = quality.metrics([
        make_item(source="CYBERATTAQUE_ORG", threat="Ransomware", sector="Inconnu", location="France"),
        make_item(source="BONJOURLAFUITE", threat="Ransomware", sector="Santé", location="France"),
        make_item(source="BONJOURLAFUITE", threat="Ransomware", sector="Santé", location="France"),
    ])
    problems = quality.compare(current, baseline)
    assert any("CYBERATTAQUE_ORG" in problem and "sector_unknown" in problem for problem in problems)
    assert not any("BONJOURLAFUITE" in problem for problem in problems)


def test_sector_metrics_count_unique_and_repeated_unknown_organisations(make_item):
    items = [
        make_item(org="Alpha", url="https://example.org/a", sector="Inconnu"),
        make_item(org="Alpha", url="https://example.org/b", sector="Inconnu"),
        make_item(org="Beta", url="https://example.org/c", sector="Inconnu"),
        make_item(org="Gamma", url="https://example.org/d", sector="Santé"),
    ]

    metrics = quality.metrics(items)["global"]

    assert metrics["items"] == 4
    assert metrics["sector_unknown"] == 3
    assert metrics["sector_known"] == 1
    assert metrics["sector_coverage_ratio"] == 0.25
    assert metrics["organisations"] == 3
    assert metrics["sector_unknown_organisations"] == 2
    assert metrics["sector_unknown_repeated_organisations"] == 1
    assert metrics["sector_unknown_items_from_repeated_organisations"] == 2


def test_ransomware_source_sector_audit_separates_raw_mapping_states(make_item):
    mapped = make_item(
        source="RANSOMWARE_LIVE", org="Mapped", url="https://example.org/mapped", sector="Inconnu"
    )
    unmapped = make_item(
        source="RANSOMWARE_LIVE", org="Unmapped", url="https://example.org/unmapped", sector="Inconnu"
    )
    missing = make_item(
        source="RANSOMWARE_LIVE", org="Missing", url="https://example.org/missing", sector="Inconnu"
    )
    known = make_item(
        source="RANSOMWARE_LIVE", org="Known", url="https://example.org/known", sector=config.SECTOR_HEALTH
    )
    other = make_item(
        source="CYBERATTAQUE_ORG", org="Other", url="https://example.org/other", sector="Inconnu"
    )
    facts = [
        {"Item_ID": mapped.Item_ID, "Source_ID": "RANSOMWARE_LIVE", "Source_Sector_Raw": "Manufacturing"},
        {"Item_ID": unmapped.Item_ID, "Source_ID": "RANSOMWARE_LIVE", "Source_Sector_Raw": "Hospitality"},
        {"Item_ID": known.Item_ID, "Source_ID": "RANSOMWARE_LIVE", "Source_Sector_Raw": "Healthcare"},
        {"Item_ID": other.Item_ID, "Source_ID": "CYBERATTAQUE_ORG", "Source_Sector_Raw": "Manufacturing"},
    ]

    audit = quality.ransomware_source_sector_audit(
        [mapped, unmapped, missing, known, other], facts
    )

    assert audit["items"] == 4
    assert audit["current_unknown"] == 3
    assert audit["unknown_with_raw"] == 2
    assert audit["unknown_without_raw"] == 1
    assert audit["unknown_raw_mappable"] == 1
    assert audit["unknown_raw_unmapped"] == 1
    assert audit["raw_values"]["Manufacturing"]["mapped_sector"] == config.SECTOR_INDUSTRY
    assert audit["raw_values"]["Hospitality"]["mapped_sector"] == config.SECTOR_UNKNOWN


def test_measured_ransomware_aliases_are_mappable_but_broad_categories_stay_unknown(make_item):
    raws = [
        ("Professional Services", config.SECTOR_SERVICES),
        ("Technology", config.SECTOR_TECH),
        ("Retail & E-Commerce", config.SECTOR_RETAIL),
        ("Hospitality", config.SECTOR_UNKNOWN),
        ("Agriculture and Food Production", config.SECTOR_UNKNOWN),
        ("Government & Defense", config.SECTOR_UNKNOWN),
        ("Other", config.SECTOR_UNKNOWN),
        ("Not Found", config.SECTOR_UNKNOWN),
    ]
    items = []
    facts = []
    for index, (raw, _expected) in enumerate(raws):
        item = make_item(
            source="RANSOMWARE_LIVE",
            org=f"Org {index}",
            url=f"https://example.org/{index}",
            sector=config.SECTOR_UNKNOWN,
        )
        items.append(item)
        facts.append(
            {
                "Item_ID": item.Item_ID,
                "Source_ID": "RANSOMWARE_LIVE",
                "Source_Sector_Raw": raw,
            }
        )

    audit = quality.ransomware_source_sector_audit(items, facts)
    for raw, expected in raws:
        assert audit["raw_values"][raw]["mapped_sector"] == expected
