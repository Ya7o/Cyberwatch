from cyberwatch import quality


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
        make_item(source_id="CYBERATTAQUE_ORG", threat="Ransomware", sector="Santé", location="France"),
        make_item(source_id="BONJOURLAFUITE", threat="Ransomware", sector="Santé", location="France"),
    ])
    current = quality.metrics([
        make_item(source_id="CYBERATTAQUE_ORG", threat="Ransomware", sector="Inconnu", location="France"),
        make_item(source_id="BONJOURLAFUITE", threat="Ransomware", sector="Santé", location="France"),
        make_item(source_id="BONJOURLAFUITE", threat="Ransomware", sector="Santé", location="France"),
    ])
    problems = quality.compare(current, baseline)
    assert any("CYBERATTAQUE_ORG" in problem and "sector_unknown" in problem for problem in problems)
    assert not any("BONJOURLAFUITE" in problem for problem in problems)
