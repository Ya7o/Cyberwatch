def test_criticite_est_calculee_dans_le_runtime_unique_sans_observer_dom():
    app = open("assets/app.js", encoding="utf-8").read()

    assert "Données sensibles" in app
    assert "Données personnelles" in app
    assert "Données non qualifiées" in app
    assert "SENSITIVE" in app
    assert "PERSONAL" in app
    assert "function sensitivity(" in app
    assert "MutationObserver" not in app
    assert "assets/data-sensitivity.js" not in app
