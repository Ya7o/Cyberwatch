"""Contrat du résumé LLM affiché dans la fiche incident."""
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def render(incident, detail):
    script = r'''
const fs = require("fs");
const vm = require("vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const elements = {};
const context = {
  sessionStorage: {getItem: () => null},
  URL,
  document: {querySelector: (key) => elements[key] ||= {showModal() {}}},
};
const source = fs.readFileSync("assets/dashboard-v2.js", "utf8").replace(
  "  init();",
  "  globalThis.testApi = {state, incidentSummaryParagraphs, openIncident};"
);
vm.runInNewContext(source, context);
const api = context.testApi;
api.state.latest = [input.incident];
api.state.facts = {[input.incident.id]: input.detail};
api.openIncident(input.incident.id).then(() => console.log(JSON.stringify({
  paragraphs: api.incidentSummaryParagraphs(input.incident, input.detail),
  html: elements["#detail-dialog-content"].innerHTML,
})));
'''
    result = subprocess.run(
        ["node", "-e", script], cwd=ROOT, check=True, capture_output=True,
        input=json.dumps({"incident": incident, "detail": detail}), text=True,
    )
    return json.loads(result.stdout)


def test_two_generated_paragraphs_are_rendered_separately():
    first = "Exemple confirme une intrusion ayant exposé des données clients."
    second = "Les adresses e-mail ont été consultées et les accès compromis révoqués."
    result = render({"id": "example", "org": "Exemple"}, {
        "version": 3,
        "display_summary": "Ancienne phrase courte.",
        "summary_paragraphs": [first, second],
    })
    assert result["paragraphs"] == [first, second]
    assert result["html"].count("<p>") == 2
    assert first in result["html"] and second in result["html"]
    assert "Ancienne phrase courte" not in result["html"]
    assert "resolved-facts" not in result["html"]


def test_existing_incident_keeps_its_short_summary_as_fallback():
    headline = "Exemple signale une fuite de données clients."
    result = render({"id": "example", "org": "Exemple", "summary": headline}, {
        "version": 3, "display_summary": headline, "summary_paragraphs": [],
    })
    assert result["paragraphs"] == [headline]
    assert result["html"].count("<p>") == 1


def test_missing_or_oversized_fallback_uses_a_safe_message():
    unsafe = "<img src=x onerror=alert(1)>" + " x" * 100
    result = render({"id": "example", "org": "Exemple", "summary": unsafe}, None)
    assert result["paragraphs"] == [
        "Les informations disponibles ne permettent pas encore de résumer précisément cet incident."
    ]
    assert "<img" not in result["html"]


def test_generated_html_is_escaped():
    result = render({"id": "example", "org": "Exemple"}, {
        "version": 3, "summary_paragraphs": ["<script>alert(1)</script>"],
    })
    assert "<script>" not in result["html"]
    assert "&lt;script&gt;" in result["html"]
