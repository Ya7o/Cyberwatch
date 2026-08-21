"""Contrats de non-régression pour le détail des incidents."""

from __future__ import annotations

import re


def _read(path: str) -> str:
    return open(path, encoding="utf-8").read()


def _function_body(js: str, name: str, next_name: str) -> str:
    match = re.search(
        rf"function {re.escape(name)}\([^)]*\)\s*\{{(.*?)\n  \}}\n\n  function {re.escape(next_name)}",
        js,
        re.DOTALL,
    )
    assert match, f"fonction {name} introuvable"
    return match.group(1)


def test_detail_incident_est_genere_directement_dans_sources():
    js = _read("assets/app.js")
    body = _function_body(js, "renderTable", "incidentDate")
    org_cell = re.search(r'<td data-label="Organisation"[^\n]*', body)
    source_cell = re.search(r'<td data-label="Sources"[^\n]*', body)
    assert org_cell and source_cell
    assert "incident-details-toggle" not in org_cell.group(0)
    assert "incident-details-toggle" in source_cell.group(0)
    assert "sourceLinks(incident)" in source_cell.group(0)


def test_synthese_incident_est_toujours_avant_les_blocs_sources():
    js = _read("assets/app.js")
    body = _function_body(js, "detailHtml", "sourceHomes")
    assert "const factsInput = Array.isArray(incident.facts) ? incident.facts : []" in body
    assert 'if (incident.summary) parts.push(`<div class="incident-summary"><strong>Synthèse :</strong> ${esc(incident.summary)}</div>`)' in body
    assert "factsInput.map((fact) => factHtml(fact, incident.summary))" in body


def test_les_blocs_sources_n_affichent_plus_de_synthese():
    js = _read("assets/app.js")
    body = _function_body(js, "factHtml", "detailHtml")
    assert 'factRow("Synthèse"' not in body
    assert "narrativeContains(fact.summary, fact.impact)" in body


def test_aucun_script_de_patch_detail_non_certifie_n_est_charge():
    html = _read("index.html")
    scripts = re.findall(r'<script\s+src="([^"]+)"', html)
    assert scripts == [
        "assets/app.js",
        "assets/p2.js?v=20260821-1",
        "assets/p3.js?v=20260821-1",
    ]
    assert "dashboard-layout-fixes.js" not in html
    assert "detail-summary-fix.js" not in html
    assert "patch" not in " ".join(scripts).lower()


def test_incident_et_sources_partagent_le_triangle_detail():
    css = _read("assets/dashboard-mobile-fixes.css")
    html = _read("index.html")
    assert '.incident-details-toggle::before' in css
    assert 'content: "▸"' in css
    assert '.incident-details-toggle[aria-expanded="true"]::before' in css
    assert '.sources-detail > summary::before' in css
    assert '.sources-detail[open] > summary::before' in css
    assert '<summary>Détail</summary>' in html
