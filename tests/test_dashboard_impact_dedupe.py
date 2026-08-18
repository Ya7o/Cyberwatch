"""Garde-fou UI : ne pas répéter un impact déjà couvert par une synthèse."""


def test_renderer_masque_un_impact_deja_present_dans_une_synthese():
    app = open("assets/app.js", encoding="utf-8").read()

    assert "function narrativeContains(container, detail)" in app
    assert "narrativeContains(fact.summary, fact.impact)" in app
    assert "narrativeContains(incidentSummary, fact.impact)" in app
    assert 'const sourceImpact = impactCovered ? "" : fact.impact;' in app
    assert 'factRow("Impact", sourceImpact)' in app


def test_renderer_conserve_un_impact_distinct():
    app = open("assets/app.js", encoding="utf-8").read()

    assert "haystack.includes(needle)" in app
    assert 'const sourceImpact = impactCovered ? "" : fact.impact;' in app
