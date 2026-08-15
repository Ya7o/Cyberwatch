from cyberwatch import config, identity, site, sources
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


def test_veille_llm_source_is_active_analytical_snapshot():
    spec = sources.by_id("VEILLE_LLM")
    assert spec is not None and spec.active
    assert spec.collector == "veillellm"
    assert spec.layer == config.LAYER_REGIONAL_WATCH
    assert spec.params["replace_snapshot"] is True
    assert spec.params["non_evidence_source"] is True
    assert spec.params["dashboard_filter"] == "veille_llm"


def test_veille_llm_imports_full_snapshot_and_rejects_weak_signals():
    spec = sources.by_id("VEILLE_LLM")
    result = get_collector(spec.collector).collect(
        None, spec, Window("2026-07-25", "2026-08-15")
    )
    assert result.resolve() == ("OK", 100)
    assert result.items_seen == 8
    assert len(result.entries) == 6
    organisations = {entry.organisation for entry in result.entries}
    assert "Commune de Ouangani" not in organisations
    assert "Le Quotidien de La Réunion" not in organisations
    assert "Ville de Mamoudzou" in organisations
    assert all(
        entry.location in {config.LOC_REUNION, config.LOC_MAYOTTE}
        for entry in result.entries
    )


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


def test_dashboard_payload_exposes_veille_llm_provenance_tag():
    item = _item("VEILLE_LLM")
    incident = build_incidents([item])[0]
    tags = site._provenance_tags_by_incident([item])
    payload = site.incidents_payload([incident], tags)[0]
    assert payload["provenance_tags"] == ["veille_llm"]


def test_dashboard_has_veille_llm_filter():
    html = open("index.html", encoding="utf-8").read()
    legacy = open("assets/app-legacy.js", encoding="utf-8").read()
    audit = open("assets/dashboard-audit.js", encoding="utf-8").read()
    assert 'id="f-veille-llm"' in html
    assert 'provenance_tags || []).includes("veille_llm")' in legacy
    assert 'provenance_tags || []).includes("veille_llm")' in audit
