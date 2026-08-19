"""Garde-fous statiques pour la stabilité/performance du dashboard mobile."""

from __future__ import annotations

import re


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def test_index_charge_un_seul_runtime_dashboard():
    html = _read("index.html")
    scripts = re.findall(r'<script\s+src="([^"]+)"', html)
    assert scripts == ["assets/app.js"]
    assert "dashboard-v2.js" not in html
    assert "activity-12m-trend.js" not in html
    assert "activity-two-columns.css" not in html


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
    js = _read("assets/app.js")
    assert ".activity-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:0;align-items:stretch}" in js
    assert ".kpi-activity .activity-primary .kpi-value{margin:0 0 10px;line-height:1" in js
    assert ".activity-value{font-size:clamp(2rem,5vw,3.2rem);font-weight:750;line-height:1;margin:0 0 10px" in js
