"""Exécution du runtime réel pour les filtres, les routes et les cartes."""
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = r'''
const fs = require("fs"), vm = require("vm");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const elements = {};
function element(key) { return elements[key] ||= {
  dataset: {}, querySelector: () => ({}), querySelectorAll: () => [],
  setAttribute() {}, showModal() {this.open = true;},
}; }
const context = {
  URL, URLSearchParams, CustomEvent: class {},
  document: {querySelector: element, querySelectorAll: () => [], dispatchEvent() {}},
  window: {scrollTo() {}},
  location: {pathname: "/Cyberwatch/", search: input.query || ""},
  history: {pushState(a,b,url) {context.savedUrl=url;}, replaceState(a,b,url) {context.savedUrl=url;}},
};
const source = fs.readFileSync("assets/dashboard-v2.js", "utf8").replace(
  "  init();", "  globalThis.api = {state, readUrl, syncUrl, filteredSearch, applySearchPatch, incidentCardHtml, sectorLabel, simpleBars};"
);
vm.runInNewContext(source, context);
(async () => {
  const api = context.api;
  Object.assign(api.state, input.state || {});
  api.state.incidentsLoaded = true;
  if (input.action === "drilldown") await api.applySearchPatch(input.patch);
  if (input.action === "route") {api.readUrl(); api.syncUrl();}
  if (input.action === "bars") api.simpleBars(element("bars"), input.rows);
  console.log(JSON.stringify({
    filters: api.state.filters,
    matched: api.filteredSearch().map(row => row.id),
    url: context.savedUrl,
    card: input.incident ? api.incidentCardHtml(input.incident) : null,
    bars: elements.bars?.innerHTML,
    scope: api.state.analysisScope,
    period: api.state.analysisPeriod,
    incidentId: api.state.incidentId,
  }));
})();
'''


def runtime(**payload):
    result = subprocess.run(["node", "-e", SCRIPT], cwd=ROOT, check=True,
                            input=json.dumps(payload), text=True, capture_output=True)
    return json.loads(result.stdout)


def test_graph_drilldown_replaces_unrelated_query_and_source_filters():
    result = runtime(action="drilldown", patch={"threat": "Ransomware", "period": "90", "admission": "ACCEPTED"}, state={
        "status": {"run": {"as_of": "2026-09-30T17:00:00+04:00"}},
        "filters": {"q": "Tampon", "source": "VEILLE_LLM", "locations": ["La Réunion"], "period": "all"},
        "incidents": [{"id": "ransomware", "date": "2026-09-30", "org": "Autre", "threat": "Ransomware", "location": "France métropolitaine", "admission": "ACCEPTED"}],
    })
    assert result["matched"] == ["ransomware"]
    assert result["filters"]["q"] == result["filters"]["source"] == ""
    assert result["filters"]["locations"] == []
    assert "Tampon" not in result["url"]


def test_period_filter_matches_snapshot_inclusive_dates_not_wall_clock():
    result = runtime(state={
        "status": {"run": {"as_of": "2026-09-30T17:00:00+04:00"}},
        "filters": {"q": "", "threat": "", "sector": "", "locations": [], "source": "", "admission": "", "period": "30"},
        "incidents": [{"id": "edge", "date": "2026-09-01"}, {"id": "old", "date": "2026-08-31"}, {"id": "end", "date": "2026-09-30"}, {"id": "future", "date": "2026-10-01"}, {"id": "undated", "date": ""}],
    })
    assert result["matched"] == ["edge", "end"]


def test_incident_permalink_preserves_search_context_and_escapes_card():
    result = runtime(action="route", query="?vue=recherche&q=Tampon&incident=INC-A", incident={
        "id": "INC-A", "org": '<img src=x onerror="alert(1)">', "date": "2026-09-09", "sector": "Santé",
        "sector_status": {"status": "inferred", "confidence": .8}, "threat": "Inconnu", "summary": "",
    })
    assert result["url"] == "/Cyberwatch/?vue=recherche&q=Tampon&incident=INC-A"
    assert result["incidentId"] == "INC-A"
    assert "<img" not in result["card"]
    assert result["card"].count("data-open-id") == 1
    assert result["card"].count("Santé") == 1
    assert "80" not in result["card"]
    assert "Nature non déterminée" in result["card"]


def test_analysis_scope_and_period_survive_reload():
    result = runtime(action="route", query="?vue=analyse&scope=focus&period=30")
    assert result["scope"] == "focus" and result["period"] == "30"
    assert result["url"] == "/Cyberwatch/?vue=analyse&scope=focus&period=30"


def test_zero_bar_has_zero_width_and_descriptive_bars_are_not_fake_buttons():
    result = runtime(action="bars", rows=[{"label": "2026-09", "count": 0}, {"label": "2026-10", "count": 10}])
    assert 'width:0%' in result["bars"]
    assert "<button" not in result["bars"]
