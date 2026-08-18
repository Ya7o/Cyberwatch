import json

from cyberwatch import config, identity, site, sources, store
from cyberwatch.collectors import get_collector
from cyberwatch.collectors.base import Window
from cyberwatch.dedup import build_incidents
from cyberwatch.model import Item


def _item(source_id, org="STOR Solutions", date="2026-04-24", url="https://example.test/a"):
    key = "stor solutions"
    return Item(
        Item_ID=identity.item_id(source_id, date, key, url, ""),
        Source_ID=source_id,
        Published_Date=date,
        Event_Date=date,
        Organisation_Raw=org,
        Organisation_Key=key,
        Threat="Intrusion",
        Location=config.LOC_REUNION,
        URL=url,
    )


def test_veille_llm_source_is_active_local_snapshot():
    spec = sources.by_id("VEILLE_LLM")
    assert spec is not None and spec.active
    assert spec.collector == "veillellm"
    assert spec.layer == config.LAYER_REGIONAL_WATCH
    assert spec.params["replace_snapshot"] is True
    assert spec.params["non_evidence_source"] is True
    assert spec.zone == "La Réunion / Mayotte"


def test_veille_llm_imports_full_snapshot_regardless_of_score():
    """Le score cyberattaque est affichable, jamais un critère d'exclusion :
    tous les dossiers valides et non futurs sont importés, y compris les
    scores faibles (<50)."""
    spec = sources.by_id("VEILLE_LLM")
    assert "min_score" not in spec.params
    with open(spec.params["path"], encoding="utf-8") as handle:
        raw = json.load(handle)
    result = get_collector(spec.collector).collect(
        None, spec, Window("2026-01-01", "2026-08-15")
    )
    assert result.resolve() == ("OK", 100)
    assert result.items_seen == raw["metadata"]["record_count"] == len(raw["incidents"])
    expected = [row for row in raw["incidents"] if row["date"] <= "2026-08-15"]
    assert len(result.entries) == len(expected)
    assert any(int(row["score_cyberattaque"]) < 50 for row in expected)
    assert all(entry.location in {config.LOC_REUNION, config.LOC_MAYOTTE} for entry in result.entries)


def test_veille_llm_low_score_item_is_retained_and_visible():
    """Un item Veille LLM avec un score < 50 reste importé et visible dans
    ITEMS — le score n'est jamais un filtre d'exclusion."""
    spec = sources.by_id("VEILLE_LLM")
    with open(spec.params["path"], encoding="utf-8") as handle:
        raw = json.load(handle)
    low_score_records = [r for r in raw["incidents"] if int(r["score_cyberattaque"]) < 50]
    assert low_score_records, "fixture attendue avec au moins un score <50"

    result = get_collector(spec.collector).collect(
        None, spec, Window("2026-01-01", "2026-08-15")
    )
    low_score_orgs = {r["organisation"] for r in low_score_records}
    entry_orgs = {entry.organisation for entry in result.entries}
    assert low_score_orgs & entry_orgs == low_score_orgs


def test_veille_llm_does_not_inflate_direct_source_count():
    direct = _item("CYBERATTAQUE_ORG", url="https://www.cyberattaque.org/stor/")
    analytic = _item(
        "VEILLE_LLM",
        url="https://github.com/Ya7o/Cyberwatch/blob/main/sources/veillellm/cyberattaques_reunion_mayotte_2026.json",
    )
    incident = build_incidents([direct, analytic])[0]
    assert incident.Sources == "CYBERATTAQUE_ORG"
    assert incident.Items_Count == 2
    assert "veillellm" not in incident.Source_URLs.lower()


def test_veille_llm_remains_source_when_only_evidence():
    incident = build_incidents([_item("VEILLE_LLM")])[0]
    assert incident.Sources == "VEILLE_LLM"


def test_dashboard_payload_exposes_local_summary_score_and_references():
    items = store.load_items()
    incidents = store.load_incidents()
    analysis = site._local_analysis_by_incident(items)
    assert analysis
    payload = site.incidents_payload(incidents, analysis)
    local_rows = [row for row in payload if row.get("local")]
    assert local_rows
    assert all(0 <= row["local"]["score"] <= 100 for row in local_rows)
    assert all(row["local"]["summary"] for row in local_rows)
    assert all(row["local"]["references"] for row in local_rows)


def test_dashboard_has_single_reunion_mayotte_filter_for_local_watch():
    html = open("index.html", encoding="utf-8").read()
    app = open("assets/app.js", encoding="utf-8").read()

    assert 'id="f-local"' in html
    assert '>Réunion / Mayotte</button>' in html
    assert 'f-veille-llm' not in html + app
    assert 'f-presse-mahoraise' not in html + app
    assert "!i.local" in app
    assert "Score cyberattaque" in app
    assert "Analyse locale" in app
