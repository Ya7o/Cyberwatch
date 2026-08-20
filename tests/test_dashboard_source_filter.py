"""Contrat des filtres et garde-fous du dashboard unifié."""

import re


def test_filtre_source_et_recherche_organisation_sont_appliques_par_le_runtime_unique():
    html = open("index.html", encoding="utf-8").read()
    app = open("assets/app.js", encoding="utf-8").read()

    assert 'id="f-source"' in html
    assert 'id="f-org"' in html
    assert 'id="f-reset"' in html
    assert '<option value="">Toutes les sources</option>' in html
    for source_id in (
        "BONJOURLAFUITE", "FRENCHBREACHES", "CYBERATTAQUE_ORG",
        "RANSOMWARE_LIVE", "VEILLE_LLM",
    ):
        assert f'value="{source_id}"' in html

    assert "state.filters.source" in app
    assert "(incident.sources || []).includes(state.filters.source)" in app
    assert "normalize(incident.org).includes(query)" in app
    assert 'state.filters = { ocean: false, local: false, source: "", org: "" }' in app
    assert "assets/app-legacy.js" not in app
    assert "assets/dashboard-audit.js" not in app


def test_reset_annule_le_debounce_de_recherche_avant_de_vider_les_filtres():
    app = open("assets/app.js", encoding="utf-8").read()
    match = re.search(
        r'\$\("#f-reset"\)\.addEventListener\("click", \(\) => \{(.*?)\n    \}\);',
        app,
        re.DOTALL,
    )
    assert match, "handler #f-reset introuvable"
    body = match.group(1)
    assert "clearTimeout(searchTimer);" in body
    assert body.index("clearTimeout(searchTimer);") < body.index("state.filters =")


def test_historique_tronque_est_rendu_sans_degrader_le_statut_source():
    app = open("assets/app.js", encoding="utf-8").read()
    match = re.search(
        r"function renderSourceDetail\(rows\)\s*\{(.*?)\n  \}",
        app,
        re.DOTALL,
    )
    assert match, "renderSourceDetail() introuvable"
    body = match.group(1)
    assert "source.history_status" in body
    assert "source.oldest_available_date" in body
    assert 'historyStatus === "TRUNCATED"' in body
    assert "Historique borné" in body
    assert 'data-status="${esc(status)}"' in body


def test_synthese_incident_est_unique_et_les_blocs_sources_ne_la_repetent_pas():
    app = open("assets/app.js", encoding="utf-8").read()

    assert "function normalizeNarrative(value)" in app
    assert "function narrativeContains(container, detail)" in app
    assert 'if (incident.summary) parts.push(`<div class="incident-summary"><strong>Synthèse :</strong> ${esc(incident.summary)}</div>`)' in app
    assert 'factRow("Synthèse"' not in app
    assert "sourceSummary" not in app
    assert "factsInput.map((fact) => factHtml(fact, incident.summary))" in app


def test_impact_source_reste_deduplique_par_rapport_a_la_synthese():
    app = open("assets/app.js", encoding="utf-8").read()

    assert "narrativeContains(fact.summary, fact.impact)" in app
    assert "factHtml(fact, incident.summary)" in app
