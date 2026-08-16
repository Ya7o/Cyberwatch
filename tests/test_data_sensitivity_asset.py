def test_couche_criticite_est_chargee_et_conditionnelle():
    app = open("assets/app.js", encoding="utf-8").read()
    js = open("assets/data-sensitivity.js", encoding="utf-8").read()
    assert "assets/data-sensitivity.js" in app
    assert "Données sensibles" in js
    assert "Données personnelles" in js
    assert "Données non qualifiées" in js
    assert "incident-data-value" in js
    assert "SENSITIVE_MARKERS" in js
