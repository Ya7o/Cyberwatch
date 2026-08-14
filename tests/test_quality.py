from cyberwatch import quality


def test_quality_detects_regression_and_accepts_improvement(make_item):
    baseline = quality.metrics([make_item(threat="Inconnu", sector="Inconnu", location="Inconnu")])
    assert quality.compare(quality.metrics([make_item(threat="Inconnu", sector="Inconnu", location="Inconnu")]), baseline) == []
    assert quality.compare(quality.metrics([make_item(threat="Ransomware", sector="Santé", location="France")]), baseline) == []
    assert quality.compare(quality.metrics([make_item(threat="Inconnu"), make_item(threat="Inconnu")]), baseline)


def test_ratio_is_diagnostic_only_when_population_changes(make_item):
    baseline = quality.metrics([make_item(threat="Inconnu"), make_item(threat="Ransomware")])
    current = quality.metrics([make_item(threat="Inconnu"), make_item(threat="Ransomware"), make_item(threat="Ransomware")])
    assert quality.compare(current, baseline) == []
