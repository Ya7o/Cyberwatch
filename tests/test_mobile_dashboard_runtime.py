"""Garde-fous statiques pour la stabilité/performance du dashboard mobile."""

from __future__ import annotations

import re


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def test_index_charge_un_seul_runtime_dashboard():
    html = _read("index.html")
    scripts = re.findall(r'<script\s+src="([^"]+)"', html)
    # ``assets/app.js`` reste l'unique runtime applicatif. Les petits scripts
    # de correctifs de layout/détail sont des helpers statiques et ne doivent
    # pas être confondus avec les anciens runtimes parallèles retirés.
    assert scripts.count("assets/app.js") == 1
    assert scripts[0] == "assets/app.js"
    assert "dashboard-v2.js" not in html
    assert "activity-12m-trend.js" not in html
    assert "activity-two-columns.css" not in html


def test_styles_structurels_sont_charges_statiquement_avant_le_runtime():
    html = _read("index.html")
    js = _read("assets/app.js")
    runtime_css = _read("assets/dashboard-runtime.css")
    assert '<link rel="stylesheet" href="assets/dashboard-runtime.css">' in html
    assert html.index("assets/dashboard-runtime.css") < html.index("assets/app.js")
    assert "function installCss" not in js
    assert "dashboard-runtime-css" not in js
    assert "document.createElement(\"style\")" not in js
    assert ".activity-grid" in runtime_css
    assert ".filters-toolbar" in runtime_css


def test_incidents_json_n_est_charge_qu_une_fois():
    js = _read("assets/app.js")
    assert js.count('load("assets/data/incidents.json"') == 1
    assert js.count('assets/data/incidents.json') == 1


def test_aucun_mutation_observer_de_rendu_secondaire():
    js = _read("assets/app.js")
    assert "MutationObserver" not in js


def test_resize_ignore_les_micro_variations_du_viewport_mobile():
    js = _read("assets/app.js")
    assert "let lastWidth = document.documentElement.clientWidth" in js
    assert "Math.abs(width - lastWidth) <= 20" in js
    resize = re.search(r"function setupResize\(\)\s*\{(.*?)\n  \}", js, re.DOTALL)
    assert resize
    assert "renderCharts(filteredIncidents())" in resize.group(1)
    assert "renderDataView()" not in resize.group(1)


def test_pagination_et_tri_ne_reconstruisent_que_la_table():
    js = _read("assets/app.js")
    controls = re.search(r"function setupControls\(\)\s*\{(.*?)\n  \}\n\n  function setupTheme", js, re.DOTALL)
    assert controls
    body = controls.group(1)
    assert body.count("renderTable(filteredIncidents())") >= 3


def test_tableau_est_produit_directement_dans_l_ordre_des_entetes():
    js = _read("assets/app.js")
    table = re.search(r"function renderTable\(rows\)\s*\{(.*?)\n  \}\n\n  function incidentDate", js, re.DOTALL)
    assert table
    body = table.group(1)
    positions = [body.index(f'data-label="{label}"') for label in (
        "Date", "Organisation", "Secteur", "Menace", "Territoire", "Sources",
    )]
    assert positions == sorted(positions)


def test_graphiques_mobiles_wrap_et_scroll_local_uniquement():
    js = _read("assets/app.js")
    css = _read("assets/dashboard-mobile-fixes.css")
    assert "function wrapChartLabel" in js
    assert "isMobile ? 2 : 1" in js
    assert "overflow-x: hidden" in css
    assert "#chart-month" in css
    assert "overflow-x: auto" in css
    assert "overscroll-behavior-x: contain" in css


def test_kpi_activite_partagent_les_memes_regles_verticales():
    css = _read("assets/dashboard-runtime.css")
    assert "align-items: stretch" in css
    assert ".kpi-activity .activity-primary .kpi-value" in css
    assert ".activity-value" in css
    assert css.count("line-height: 1;") >= 2
    assert css.count("margin: 0 0 10px;") >= 2


def test_touch_targets_mobiles_ont_une_zone_de_44px_effective():
    runtime_css = _read("assets/dashboard-runtime.css")
    mobile_css = _read("assets/dashboard-mobile-fixes.css")
    html = _read("index.html")

    # La feuille mobile est chargée après le runtime : elle ne doit donc jamais
    # annuler les dimensions tactiles avec un reset global prioritaire.
    assert html.index("assets/dashboard-runtime.css") < html.index("assets/dashboard-mobile-fixes.css")
    assert "all: unset !important" not in mobile_css

    # Contrôles génériques garantis par le runtime.
    assert "min-height: 44px" in runtime_css
    for selector in (".btn-quick", ".btn-reset", ".audit-pager button", ".org-search"):
        assert selector in runtime_css

    # Contrôles qui avaient encore une faiblesse de cascade ou de largeur.
    theme_blocks = re.findall(r"\.theme-toggle\s*\{(.*?)\}", mobile_css, re.DOTALL)
    assert any("min-width: 44px" in body and "min-height: 44px" in body for body in theme_blocks)

    detail_blocks = re.findall(r"\.incidents-card \.incident-details-toggle\s*\{(.*?)\}", mobile_css, re.DOTALL)
    assert any("min-width: 44px" in body and "min-height: 44px" in body for body in detail_blocks)

    summary_blocks = re.findall(r"\.sources-detail > summary\s*\{(.*?)\}", mobile_css, re.DOTALL)
    assert any("min-height: 44px" in body for body in summary_blocks)


def test_detail_mobile_utilise_un_reset_cible_et_preserve_la_cascade():
    css = _read("assets/dashboard-mobile-fixes.css")
    blocks = re.findall(r"\.incidents-card \.incident-details-toggle\s*\{(.*?)\}", css, re.DOTALL)
    assert blocks
    reset = blocks[0]
    assert "appearance: none" in reset
    assert "background: transparent !important" in reset
    assert "border: 0 !important" in reset
    assert "all:" not in reset


def test_libelle_veille_llm_reste_stable():
    js = _read("assets/app.js")
    assert 'VEILLE_LLM: "veillellmReYt"' in js
    assert 'VEILLE_LLM: "Veille IA"' not in js
